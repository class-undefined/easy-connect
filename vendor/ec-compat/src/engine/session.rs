use crate::auth::{AuthState, auth_summary, rsa_encrypt_hex, safe_int};
use crate::config::{GatewayConfiguration, parse_gateway_configuration};
use crate::engine::data_plane::EasyConnectDataPlane;
use crate::modern::{ModernSessionId, parse_sha256_pin, request_modern_token_with_pin};
use crate::probe::{DEFAULT_TIMEOUT_SECONDS, GatewaySession};
use crate::session_renewal::{MaintenanceStatus, Termination};
use crate::session_status::SessionEndReason;
use crate::session_status::{SessionStatus, SessionStatusQuery};
use crate::xml::{first_descendant_text, parse_xml};
use crate::{Error, Result};
use reqwest::Method;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub struct AuthenticatedEngineSession {
    http: GatewaySession,
    password_policy: Option<crate::password::PasswordPolicy>,
    logout_path: String,
    gateway_host: String,
    timeout: Duration,
    modern_session: ModernSessionId,
    base_url: String,
    https_pin: Option<[u8; 32]>,
    resource_path: String,
    gateway_configuration: GatewayConfiguration,
    configured_certificate_pin: Option<[u8; 32]>,
    status_query: SessionStatusQuery,
    renewal: MaintenanceStatus,
}

impl AuthenticatedEngineSession {
    pub fn password_policy(&self) -> Option<&crate::password::PasswordPolicy> {
        self.password_policy.as_ref()
    }
    /// Number of positive TIMQ validity replies received by this login's worker.
    pub fn renewal_confirmations(&self) -> u64 {
        self.renewal.confirmations()
    }
    pub fn authenticate(config: &Value, username: &str, password: &str) -> Result<Self> {
        let base_url = required_text(config, "base_url")?;
        let parsed_url = Url::parse(base_url).map_err(|_| Error("invalid gateway URL".into()))?;
        let gateway_host = parsed_url
            .host_str()
            .ok_or_else(|| Error("gateway host missing".into()))?
            .to_owned();
        let timeout = Duration::from_secs(
            config["timeout_seconds"]
                .as_u64()
                .unwrap_or(DEFAULT_TIMEOUT_SECONDS),
        );
        let pin = config["tls"]["leaf_sha256"]
            .as_str()
            .map(parse_sha256_pin)
            .transpose()?;
        let (http, login, modulus, exponent) =
            authenticate_http_with_key(config, username, password)?;
        let login_summary = auth_summary(&login, "engine password login")?;
        if login_summary.state != AuthState::Authenticated {
            return Err(Error(format!(
                "gateway authentication failed (error_code={}, state={:?})",
                login_summary.error_code, login_summary.state
            )));
        }
        let mut pending = PendingSession {
            http: Some(http),
            logout_path: required_endpoint(config, "logout")?.to_owned(),
        };
        let password_policy = crate::password::PasswordPolicy::from_login(&login)?;
        if let Some(policy) = &password_policy {
            if policy.required() {
                return Err(Error(format!(
                    "{}；请运行 easy-connect change-password。{}",
                    policy.message(),
                    policy.marker()
                )));
            }
        }
        let modern_session = ModernSessionId::from_login_xml(&login)?;
        let login_document = parse_xml(&login, "session monitor login")?;
        let session_id = Zeroizing::new(first_descendant_text(
            login_document.root_element(),
            "TwfID",
        ));
        let status_query = SessionStatusQuery::new(session_id, modulus, exponent);
        let resource_path = required_endpoint(config, "resource_list")?.to_owned();
        let http = pending
            .http
            .as_ref()
            .ok_or_else(|| Error("missing HTTP session".into()))?;

        let configuration_path = required_endpoint(config, "session_config")?;
        let (configuration, _, _) =
            http.request("session_config", configuration_path, Method::GET, None)?;
        let configuration = Zeroizing::new(configuration);
        let gateway_configuration = parse_gateway_configuration(&configuration)?;
        if !gateway_configuration.has_l3_configuration {
            return Err(Error("gateway supplied no L3 configuration".into()));
        }

        let configured_certificate_pin = config["modern_tunnel"]["special_tls_leaf_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(parse_sha256_pin)
            .transpose()?;
        Ok(Self {
            password_policy,
            http: pending
                .http
                .take()
                .ok_or_else(|| Error("missing HTTP session".into()))?,
            logout_path: required_endpoint(config, "logout")?.to_owned(),
            gateway_host,
            timeout,
            modern_session,
            base_url: base_url.to_owned(),
            https_pin: pin,
            resource_path,
            gateway_configuration,
            configured_certificate_pin,
            status_query,
            renewal: MaintenanceStatus::default(),
        })
    }

    /// Starts the TLS data channels and legacy TIMQ renewal for this login.
    /// TIMQ uses an independent unencrypted, unauthenticated TCP connection
    /// carrying the session ID, as required by the macOS 7.6.7 protocol.
    pub fn establish_data_plane(&self) -> Result<EasyConnectDataPlane> {
        let acquisition = request_modern_token_with_pin(
            &self.base_url,
            &self.modern_session,
            self.timeout,
            self.https_pin,
        )?;
        let mut plane = EasyConnectDataPlane::connect(
            &self.gateway_host,
            &acquisition,
            self.timeout,
            self.configured_certificate_pin.as_ref(),
        )?;
        plane.start_session_renewal(&self.modern_session, self.renewal.clone())?;
        Ok(plane)
    }

    /// P0 diagnostic only. Unlike the data plane, this sends the session ID
    /// in plaintext and cannot authenticate the peer. The HTTPS verification
    /// below does NOT secure the subsequent independent TCP connection.
    /// Call only after explicit consent to the legacy protocol's exposure.
    pub fn probe_legacy_renewal_without_server_authentication(
        &self,
        uptime_seconds: u32,
    ) -> Result<(
        crate::session_renewal::LegacyProbe,
        crate::session_renewal::Observation,
    )> {
        let acquisition = request_modern_token_with_pin(
            &self.base_url,
            &self.modern_session,
            self.timeout,
            self.https_pin,
        )?;
        crate::session_renewal::LegacyProbe::connect_without_server_authentication(
            acquisition.peer_address(),
            &self.modern_session,
            uptime_seconds,
        )
    }

    pub fn resource_xml(&self) -> Result<Zeroizing<Vec<u8>>> {
        let (xml, _, _) =
            self.http
                .request("resource_list", &self.resource_path, Method::GET, None)?;
        Ok(Zeroizing::new(xml))
    }

    pub fn dns_servers(&self) -> Vec<Ipv4Addr> {
        self.gateway_configuration
            .l3_dns
            .iter()
            .filter_map(|value| value.parse().ok())
            .collect()
    }

    /// Reuse the authenticated cookie jar and RSA context; never logs in again.
    pub fn session_status(&self) -> Result<SessionStatus> {
        if self.renewal.termination() == Some(Termination::SessionChanged) {
            return Ok(SessionStatus::Ended(SessionEndReason::SessionChanged));
        }
        let status = self.status_query.query(|stage, path| {
            self.http
                .get_once_with_timeout(stage, path, self.timeout.min(Duration::from_secs(3)))
        });
        // Read AFTER HTTP too: renewal may have ended while the portal request
        // was in flight. A positive or failed portal query cannot resurrect it.
        resolve_renewal_status(status, self.renewal.termination())
    }

    pub fn logout(self) -> Result<()> {
        self.renewal.stop();
        if self.renewal.termination() == Some(Termination::SessionChanged) {
            // Never send the old cookie to a logout endpoint after replacement.
            return Ok(());
        }
        self.http
            .get_once_with_timeout(
                "logout",
                &self.logout_path,
                self.timeout.min(Duration::from_secs(3)),
            )
            .map(|_| ())
    }
}

fn resolve_renewal_status(
    status: Result<SessionStatus>,
    termination: Option<Termination>,
) -> Result<SessionStatus> {
    match termination {
        Some(Termination::SessionChanged) => {
            Ok(SessionStatus::Ended(SessionEndReason::SessionChanged))
        }
        Some(reason) => {
            if let Ok(SessionStatus::Ended(reason)) = status {
                return Ok(SessionStatus::Ended(reason));
            }
            Ok(SessionStatus::Ended(match reason {
                Termination::ServerTimeout => SessionEndReason::Timeout,
                Termination::ValidityExpired
                | Termination::Unresponsive
                | Termination::ProtocolError => SessionEndReason::ConnectionLost,
                Termination::SessionChanged => SessionEndReason::SessionChanged,
            }))
        }
        None => status,
    }
}

#[cfg(test)]
mod renewal_tests {
    use super::*;

    #[test]
    fn portal_online_or_failure_cannot_overwrite_terminal_renewal() {
        for (termination, reason) in [
            (Termination::ServerTimeout, SessionEndReason::Timeout),
            (
                Termination::SessionChanged,
                SessionEndReason::SessionChanged,
            ),
            (
                Termination::ValidityExpired,
                SessionEndReason::ConnectionLost,
            ),
            (Termination::Unresponsive, SessionEndReason::ConnectionLost),
            (Termination::ProtocolError, SessionEndReason::ConnectionLost),
        ] {
            for status in [
                Ok(SessionStatus::Online),
                Err(Error("portal unavailable".into())),
            ] {
                assert_eq!(
                    resolve_renewal_status(status, Some(termination)).unwrap(),
                    SessionStatus::Ended(reason)
                );
            }
        }
    }

    #[test]
    fn preserve_explicit_remote_logout_and_never_guess_a_private_kick() {
        assert_eq!(
            resolve_renewal_status(
                Ok(SessionStatus::Ended(SessionEndReason::AdminKick)),
                Some(Termination::ServerTimeout)
            )
            .unwrap(),
            SessionStatus::Ended(SessionEndReason::AdminKick)
        );
        assert_eq!(
            resolve_renewal_status(Ok(SessionStatus::Online), None).unwrap(),
            SessionStatus::Online
        );
        assert!(resolve_renewal_status(Err(Error("portal unavailable".into())), None).is_err());
        let marker = SessionEndReason::SessionChanged.marker();
        assert_eq!(
            SessionEndReason::from_log(&marker),
            Some(SessionEndReason::SessionChanged)
        );
    }
}

/// Release authenticated cookies if post-login configuration parsing fails.
struct PendingSession {
    http: Option<GatewaySession>,
    logout_path: String,
}

impl Drop for PendingSession {
    fn drop(&mut self) {
        if let Some(http) = &self.http {
            let _ = http.request("logout", &self.logout_path, Method::GET, None);
        }
    }
}

fn required_text<'a>(config: &'a Value, name: &str) -> Result<&'a str> {
    config[name]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error(format!("engine configuration is missing {name}")))
}

fn required_endpoint<'a>(config: &'a Value, name: &str) -> Result<&'a str> {
    config["endpoints"][name]
        .as_str()
        .map(str::trim)
        .filter(|value| value.starts_with('/'))
        .ok_or_else(|| Error(format!("engine endpoint is missing {name}")))
}

pub(crate) fn authenticate_http(
    config: &Value,
    username: &str,
    password: &str,
) -> Result<(GatewaySession, Zeroizing<Vec<u8>>)> {
    authenticate_http_with_key(config, username, password).map(|(http, login, _, _)| (http, login))
}

fn authenticate_http_with_key(
    config: &Value,
    username: &str,
    password: &str,
) -> Result<(GatewaySession, Zeroizing<Vec<u8>>, Zeroizing<String>, u64)> {
    let base_url = required_text(config, "base_url")?;
    let parsed_url =
        Url::parse(base_url).map_err(|_| Error("engine base URL is invalid".into()))?;
    if parsed_url.scheme() != "https" {
        return Err(Error("engine base URL must use HTTPS".into()));
    }

    let timeout_seconds = config["timeout_seconds"]
        .as_u64()
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS);

    let user_agent = config["user_agent"]
        .as_str()
        .unwrap_or("EasyConnect_windows");
    let pin = config["tls"]["leaf_sha256"]
        .as_str()
        .map(parse_sha256_pin)
        .transpose()?;
    let http = GatewaySession::new_with_pin(
        base_url.to_owned(),
        user_agent.to_owned(),
        timeout_seconds,
        pin,
    )?;

    let discovery_path = required_endpoint(config, "discovery")?;
    let _ = http.request("discovery", discovery_path, Method::GET, None)?;
    let password_config_path = required_endpoint(config, "password_config")?;
    let (password_config, _, _) =
        http.request("password_config", password_config_path, Method::GET, None)?;
    let password_config = Zeroizing::new(password_config);
    let document = parse_xml(&password_config, "engine password configuration")?;
    let root = document.root_element();
    let modulus = Zeroizing::new(first_descendant_text(root, "RSA_ENCRYPT_KEY"));
    let csrf = Zeroizing::new(first_descendant_text(root, "CSRF_RAND_CODE"));
    let exponent = safe_int(&first_descendant_text(root, "RSA_ENCRYPT_EXP"), 65_537);
    let mid_attack = safe_int(&first_descendant_text(root, "MID_ATK_CHECK"), 0);
    if modulus.is_empty() || csrf.is_empty() || mid_attack != 0 {
        return Err(Error(
            "gateway password configuration is unsupported".into(),
        ));
    }
    let password_material = Zeroizing::new(format!("{password}_{}", csrf.as_str()));
    let encrypted_password = Zeroizing::new(rsa_encrypt_hex(
        password_material.as_bytes(),
        &modulus,
        exponent as u64,
    )?);
    let mut form = [
        ("mitm_result".into(), String::new()),
        ("svpn_req_randcode".into(), csrf.as_str().to_owned()),
        ("svpn_name".into(), username.to_owned()),
        (
            "svpn_password".into(),
            encrypted_password.as_str().to_owned(),
        ),
        ("svpn_rand_code".into(), String::new()),
    ]
    .into_iter()
    .collect::<BTreeMap<String, String>>();
    let login_result = http.request(
        "password_login",
        required_endpoint(config, "password_login")?,
        Method::POST,
        Some(&form),
    );
    form.values_mut().for_each(Zeroize::zeroize);
    let (login, _, _) = login_result?;
    let login = Zeroizing::new(login);
    Ok((http, login, modulus, exponent as u64))
}
