//! Session status/logout reasons from the official 7.6.7 portal protocol.
//!
//! `res.js` queries timequery, then randtick and getlogoutinfo after logout.
//! `common.js::encryptID` encrypts TWFID + "_" + RandTick with the password
//! RSA key, using the same PKCS#1 v1.5/hex encoding as password authentication.
use crate::{
    Error, Result,
    auth::rsa_encrypt_hex,
    xml::{child_text, parse_xml},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub const SESSION_END_MARKER: &str = "EC_SESSION_END ";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    PrivateKick,
    AdminKick,
    Timeout,
    OutsideTimePlan,
    LoggedOut,
    LocalException,
    Unknown,
    ConnectionLost,
    SessionChanged,
}

impl SessionEndReason {
    pub fn message(self) -> &'static str {
        match self {
            Self::PrivateKick => "账号已在其他设备登录，本次连接已断开。",
            Self::AdminKick => "连接已被管理员断开。",
            Self::Timeout => "登录会话已超时，请重新连接。",
            Self::OutsideTimePlan => "当前不在允许的访问时段，连接已断开。",
            Self::LoggedOut => "登录会话已结束，请重新连接。",
            Self::LocalException => "客户端会话异常，连接已断开，请重新连接。",
            Self::Unknown => "登录会话已结束，请重新连接。",
            Self::ConnectionLost => "与 VPN 服务器的连接已中断，请检查网络后重新连接。",
            Self::SessionChanged => "服务器已更换登录会话，本次连接已停止，请重新连接。",
        }
    }

    pub fn marker(self) -> String {
        format!(
            "{SESSION_END_MARKER}{}",
            json!({"reason": self, "message": self.message()})
        )
    }

    pub fn from_log(line: &str) -> Option<Self> {
        #[derive(Deserialize)]
        struct Event {
            reason: SessionEndReason,
        }
        serde_json::from_str::<Event>(line.strip_prefix(SESSION_END_MARKER)?)
            .ok()
            .map(|event| event.reason)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Online,
    Ended(SessionEndReason),
}

/// Sensitive fields deliberately have no Debug/Serialize implementation.
pub(crate) struct SessionStatusQuery {
    session_id: Zeroizing<String>,
    modulus: Zeroizing<String>,
    exponent: u64,
}

impl SessionStatusQuery {
    pub(crate) fn new(
        session_id: Zeroizing<String>,
        modulus: Zeroizing<String>,
        exponent: u64,
    ) -> Self {
        Self {
            session_id,
            modulus,
            exponent,
        }
    }

    pub(crate) fn query(
        &self,
        mut request: impl FnMut(&'static str, &str) -> Result<Vec<u8>>,
    ) -> Result<SessionStatus> {
        let response = Zeroizing::new(request("session status", "/por/timequery.csp")?);
        if parse_online(&response)? {
            return Ok(SessionStatus::Online);
        }
        // Once offline is established, failure to fetch a reason must not keep
        // the dead tunnel alive, nor infer that another login caused the loss.
        let reason = self
            .logout_reason(&mut request)
            .unwrap_or(SessionEndReason::Unknown);
        Ok(SessionStatus::Ended(reason))
    }

    fn logout_reason(
        &self,
        request: &mut impl FnMut(&'static str, &str) -> Result<Vec<u8>>,
    ) -> Result<SessionEndReason> {
        let tick = request("logout nonce", "/por/randtick.csp")
            .ok()
            .and_then(|xml| parse_tick(&Zeroizing::new(xml)).ok())
            .unwrap_or_else(|| {
                // The official client also falls back to the local Unix time.
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .to_string()
            });
        let material = Zeroizing::new(format!("{}_{}", self.session_id.as_str(), tick));
        let encrypted = Zeroizing::new(rsa_encrypt_hex(
            material.as_bytes(),
            &self.modulus,
            self.exponent,
        )?);
        // Hex is URL safe; plaintext session identifiers never enter URLs/logs.
        let path = Zeroizing::new(format!(
            "/por/getlogoutinfo.csp?exdata={}",
            encrypted.as_str()
        ));
        let response = Zeroizing::new(request("logout reason", &path)?);
        Ok(parse_logout_reason(&response))
    }
}

fn auth_fields(data: &[u8]) -> Result<(String, String)> {
    let document = parse_xml(data, "session status")?;
    let root = document.root_element();
    if root.tag_name().name() != "Auth" {
        return Err(Error(
            "gateway session status has an unexpected root".into(),
        ));
    }
    Ok((child_text(root, "ErrorCode"), child_text(root, "data")))
}

fn parse_online(data: &[u8]) -> Result<bool> {
    let (code, value) = auth_fields(data)?;
    // res.js uses the numeric data field to classify status, even when the
    // ErrorCode is not success. Do not classify malformed/session-switch data.
    code.parse::<i64>()
        .map_err(|_| Error("gateway session status has no error code".into()))?;
    if value.starts_with("externsession#oldsessid=") {
        return Err(Error(
            "gateway requested an unsupported session switch".into(),
        ));
    }
    value
        .parse::<i64>()
        .map(|remaining| remaining > 0)
        .map_err(|_| Error("gateway returned an unsupported session status".into()))
}

fn parse_tick(data: &[u8]) -> Result<String> {
    let document = parse_xml(data, "logout nonce")?;
    let root = document.root_element();
    let tick = child_text(root, "RandTick");
    if root.tag_name().name() != "Auth"
        || child_text(root, "ErrorCode") != "1"
        || tick.is_empty()
        || tick.len() > 20
        || !tick.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error("gateway returned an invalid logout nonce".into()));
    }
    Ok(tick)
}

fn parse_logout_reason(data: &[u8]) -> SessionEndReason {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return SessionEndReason::Unknown;
    };
    if value["ErrorCode"].as_i64() != Some(1) {
        return SessionEndReason::Unknown;
    }
    // The message/data may contain identity or peer addresses. Expose only
    // a recognized reason and our own fixed, non-sensitive user-facing text.
    match value["data"]["reason"].as_str() {
        Some("LOGOUT_PRIVATEKICK") => SessionEndReason::PrivateKick,
        Some("LOGOUT_ADMINKICK") => SessionEndReason::AdminKick,
        Some("LOGOUT_TIMEOUT") => SessionEndReason::Timeout,
        Some("LOGOUT_NOTIN_TIMEPLAN") => SessionEndReason::OutsideTimePlan,
        Some("LOGOUT_COMMON") => SessionEndReason::LoggedOut,
        Some("LOGOUT_LOCAL_EXCEPTION") => SessionEndReason::LocalException,
        _ => SessionEndReason::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, traits::PublicKeyParts};

    fn query_fixture() -> (SessionStatusQuery, RsaPrivateKey) {
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 512).unwrap();
        (
            SessionStatusQuery::new(
                Zeroizing::new("test-session-id!".into()),
                Zeroizing::new(hex::encode(key.n().to_bytes_be())),
                65_537,
            ),
            key,
        )
    }

    #[test]
    fn positive_status_never_requests_logout_or_credentials() {
        let (query, _) = query_fixture();
        let mut requests = 0;
        assert_eq!(
            query
                .query(|_, path| {
                    requests += 1;
                    assert_eq!(path, "/por/timequery.csp");
                    Ok(b"<Auth><ErrorCode>1</ErrorCode><data>29</data></Auth>".to_vec())
                })
                .unwrap(),
            SessionStatus::Online
        );
        assert_eq!(requests, 1);
    }

    #[test]
    fn offline_query_uses_current_session_and_official_rsa_payload() {
        let (query, key) = query_fixture();
        let mut requests = 0;
        let status = query.query(|_, path| {
            requests += 1;
            Ok(match requests {
                1 => {
                    assert_eq!(path, "/por/timequery.csp");
                    b"<Auth><ErrorCode>0</ErrorCode><data>-1</data></Auth>".to_vec()
                },
                2 => {
                    assert_eq!(path, "/por/randtick.csp");
                    b"<Auth><ErrorCode>1</ErrorCode><RandTick>1700000000</RandTick></Auth>".to_vec()
                },
                3 => {
                    let cipher = hex::decode(path.strip_prefix("/por/getlogoutinfo.csp?exdata=").unwrap()).unwrap();
                    assert_eq!(key.decrypt(Pkcs1v15Encrypt, &cipher).unwrap(), b"test-session-id!_1700000000");
                    br#"{"ErrorCode":1,"data":{"reason":"LOGOUT_PRIVATEKICK","msg":"secret user 10.0.0.1","data":"private"}}"#.to_vec()
                },
                _ => panic!("unexpected request"),
            })
        }).unwrap();
        assert_eq!(status, SessionStatus::Ended(SessionEndReason::PrivateKick));
        assert_eq!(requests, 3);
        let marker = SessionEndReason::PrivateKick.marker();
        assert!(!marker.contains("secret"));
        assert!(!marker.contains("10.0.0.1"));
        assert_eq!(
            SessionEndReason::from_log(&marker),
            Some(SessionEndReason::PrivateKick)
        );
        assert_eq!(
            SessionEndReason::from_log(&format!("ordinary log: {marker}")),
            None
        );
    }

    #[test]
    fn unknown_or_unsuccessful_logout_reason_never_means_kicked() {
        for data in [
            br#"{"ErrorCode":0,"data":{"reason":"LOGOUT_PRIVATEKICK"}}"#.as_slice(),
            br#"{"ErrorCode":1,"data":{"reason":"NEW_REASON"}}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            assert_eq!(parse_logout_reason(data), SessionEndReason::Unknown);
        }
        for (wire, expected) in [
            ("LOGOUT_ADMINKICK", SessionEndReason::AdminKick),
            ("LOGOUT_TIMEOUT", SessionEndReason::Timeout),
            ("LOGOUT_NOTIN_TIMEPLAN", SessionEndReason::OutsideTimePlan),
            ("LOGOUT_COMMON", SessionEndReason::LoggedOut),
            ("LOGOUT_LOCAL_EXCEPTION", SessionEndReason::LocalException),
            ("LOGOUT_DEFAULT", SessionEndReason::Unknown),
        ] {
            let data = json!({"ErrorCode":1,"data":{"reason":wire}}).to_string();
            assert_eq!(parse_logout_reason(data.as_bytes()), expected);
        }
    }

    #[test]
    fn malformed_or_switching_status_is_not_a_kick() {
        for value in ["", "invalid", "externsession#oldsessid=private", "29oops"] {
            let xml = format!("<Auth><ErrorCode>1</ErrorCode><data>{value}</data></Auth>");
            assert!(parse_online(xml.as_bytes()).is_err());
        }
        assert!(parse_online(b"<Auth><data>29</data></Auth>").is_err());
    }

    #[test]
    fn session_switch_error_does_not_expose_the_session_identifier() {
        let xml = b"<Auth><ErrorCode>1</ErrorCode><data>externsession#oldsessid=private-session-token</data></Auth>";
        assert_eq!(
            parse_online(xml).unwrap_err().to_string(),
            "gateway requested an unsupported session switch"
        );
        assert_eq!(
            parse_online(b"<Auth><ErrorCode>1</ErrorCode><data>invalid</data></Auth>")
                .unwrap_err()
                .to_string(),
            "gateway returned an unsupported session status"
        );
    }

    #[test]
    fn failed_logout_reason_still_ends_the_dead_session() {
        let (query, _) = query_fixture();
        assert_eq!(
            query
                .query(|_, path| {
                    if path == "/por/timequery.csp" {
                        Ok(b"<Auth><ErrorCode>1</ErrorCode><data>0</data></Auth>".to_vec())
                    } else {
                        Err(Error("network unavailable".into()))
                    }
                })
                .unwrap(),
            SessionStatus::Ended(SessionEndReason::Unknown)
        );
        assert!(
            query
                .query(|_, _| Err(Error("network unavailable".into())))
                .is_err()
        );
    }
}
