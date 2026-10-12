//! Password policy compatibility derived from the official 7.6.7 portal flow.
use crate::{
    Error, Result,
    auth::{AuthState, auth_summary},
    engine::session::authenticate_http,
    xml::{first_descendant_text, parse_xml},
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

pub const POLICY_MARKER: &str = "PASSWORD_POLICY:";
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub mask: u32,
    pub min_length: usize,
    pub remaining_days: Option<u32>,
}
impl PasswordPolicy {
    pub fn from_login(data: &[u8]) -> Result<Option<Self>> {
        let doc = parse_xml(data, "password policy")?;
        let root = doc.root_element();
        let mask = first_descendant_text(root, "pwpErrorCode")
            .parse()
            .unwrap_or(0);
        Ok((mask != 0).then(|| Self {
            mask,
            min_length: first_descendant_text(root, "pwdMinLen")
                .parse()
                .unwrap_or(0),
            remaining_days: first_descendant_text(root, "pwdRemaintm").parse().ok(),
        }))
    }
    pub fn required(&self) -> bool {
        self.mask != 0 && self.mask != 4
    }
    pub fn message(&self) -> String {
        if self.mask & 16 != 0 {
            "首次登录需要修改初始密码".into()
        } else if self.mask & 2 != 0 {
            "VPN 密码已过期，请修改密码".into()
        } else if self.mask == 4 {
            self.remaining_days
                .map(|n| format!("VPN 密码将在 {n} 天后过期"))
                .unwrap_or_else(|| "VPN 密码即将过期".into())
        } else {
            "VPN 密码不满足网关策略，请修改密码".into()
        }
    }
    pub fn from_log(line: &str) -> Option<Self> {
        serde_json::from_str(line.split_once(POLICY_MARKER)?.1).ok()
    }
    pub fn marker(&self) -> String {
        format!(
            "{POLICY_MARKER}{}",
            serde_json::to_string(self).expect("numeric policy fields serialize")
        )
    }
    pub fn validate(&self, username: &str, old: &str, new: &str) -> Result<()> {
        let mut errors = Vec::new();
        if new.is_empty() {
            errors.push("新密码不能为空".to_owned());
        }
        if self.mask & 1 != 0 && new.encode_utf16().count() < self.min_length {
            errors.push(format!("密码至少 {} 位", self.min_length));
        }
        if self.mask & 8 != 0 && !username.is_empty() && new.contains(username) {
            errors.push("密码不能包含用户名".into());
        }
        if self.mask & 32 != 0 {
            if self.mask & 64 != 0 && !new.chars().any(|c| c.is_ascii_digit()) {
                errors.push("密码必须包含数字".into());
            }
            if self.mask & 128 != 0 && !new.chars().any(|c| c.is_ascii_alphabetic()) {
                errors.push("密码必须包含字母".into());
            }
            if self.mask & 256 != 0 && !new.chars().any(|c| "!@#$%^&*()".contains(c)) {
                errors.push("密码必须包含 !@#$%^&*() 中的特殊字符".into());
            }
        }
        if self.mask & 512 != 0 && new == old {
            errors.push("新密码不能与旧密码相同".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error(errors.join("；")))
        }
    }
}

/// Uses a short-lived authenticated HTTPS session, never a tunnel or a password in a URL.
pub fn change_password(config: &Value, username: &str, old: &str, new: &str) -> Result<()> {
    if username.is_empty() || old.is_empty() || new.is_empty() {
        return Err(Error("账号、当前密码和新密码不能为空".into()));
    }
    let (http, login) = authenticate_http(config, username, old)?;
    let result = submit_change(&login, username, old, new, |stage, path, method, form| {
        http.request(stage, path, method, form)
            .map(|(data, _, _)| data)
    });
    // A successful password change must not be reported as a failure if logout fails.
    if let Some(path) = config["endpoints"]["logout"].as_str() {
        let _ = http.request("password change logout", path, Method::GET, None);
    }
    result
}
fn submit_change(
    login: &[u8],
    username: &str,
    old: &str,
    new: &str,
    mut request: impl FnMut(
        &'static str,
        &str,
        Method,
        Option<&BTreeMap<String, String>>,
    ) -> Result<Vec<u8>>,
) -> Result<()> {
    let summary = auth_summary(login, "password change login")?;
    if summary.state != AuthState::Authenticated {
        return Err(Error(format!("密码认证失败（{}）", summary.error_code)));
    }
    let info = request(
        "password account policy",
        "/por/perinfo.csp",
        Method::GET,
        None,
    )?;
    let info = Zeroizing::new(info);
    if auth_summary(&info, "password account policy")?.error_code != 1 {
        return Err(Error("网关未允许读取改密信息".into()));
    }
    let doc = parse_xml(&info, "password account policy")?;
    let root = doc.root_element();
    let policy = PasswordPolicy {
        mask: first_descendant_text(root, "ALL_ENABLE_PWP")
            .parse()
            .unwrap_or(0),
        min_length: first_descendant_text(root, "MINLEN").parse().unwrap_or(0),
        remaining_days: None,
    };
    policy.validate(username, old, new)?;
    let forced = PasswordPolicy::from_login(login)?.is_some_and(|p| p.required());
    let mut form = BTreeMap::from([
        (
            "pripsw".into(),
            if forced {
                String::new()
            } else {
                old.to_owned()
            },
        ),
        ("newpsw".into(), new.to_owned()),
        (
            "svpn_req_randcode".into(),
            first_descendant_text(root, "CSRF_RAND_CODE"),
        ),
    ]);
    let result = request(
        "change password",
        "/por/changepwd.csp?cknote=0",
        Method::POST,
        Some(&form),
    );
    form.values_mut().for_each(Zeroize::zeroize);
    let response = result?;
    change_result(&response, &policy, username, old, new)
}
fn change_result(
    data: &[u8],
    policy: &PasswordPolicy,
    username: &str,
    old: &str,
    new: &str,
) -> Result<()> {
    let summary = auth_summary(data, "change password")?;
    let doc = parse_xml(data, "change password")?;
    let mask = first_descendant_text(doc.root_element(), "PswMask")
        .parse()
        .unwrap_or(0);
    if mask != 0 {
        PasswordPolicy {
            mask,
            ..policy.clone()
        }
        .validate(username, old, new)?;
        return Err(Error("新密码未通过网关密码策略".into()));
    }
    if summary.error_code != 1 {
        let message = match summary.error_code {
            20237 | 20241 | 20248 => "该账号不允许在 VPN 修改密码，请联系管理员",
            20239 => "当前密码不正确",
            20242 => "新密码长度不符合要求",
            20243 => "新密码不能包含用户名",
            20244 => "新密码必须包含数字",
            20245 => "新密码必须包含字母",
            20246 => "新密码必须包含特殊字符",
            20247 => "新密码不能与旧密码相同",
            _ => "网关拒绝了密码修改",
        };
        return Err(Error(format!("{message}（{}）", summary.error_code)));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn successful_login_can_still_require_password_change() {
        let data=b"<Auth><ErrorCode>1</ErrorCode><pwpErrorCode>2</pwpErrorCode><pwdRemaintm>0</pwdRemaintm></Auth>";
        let policy = PasswordPolicy::from_login(data).unwrap().unwrap();
        assert!(policy.required());
        assert!(policy.message().contains("过期"));
        assert_eq!(
            PasswordPolicy::from_log(&format!("Error: {}", policy.marker())),
            Some(policy)
        );
        assert!(
            !PasswordPolicy {
                mask: 4,
                ..Default::default()
            }
            .required()
        );
        assert!(
            PasswordPolicy::from_login(b"<Auth><ErrorCode>1</ErrorCode></Auth>")
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn policy_validates_server_mask_and_rejects_soft_success() {
        let policy = PasswordPolicy {
            mask: 1 | 8 | 32 | 64 | 128 | 256 | 512,
            min_length: 8,
            remaining_days: None,
        };
        assert!(policy.validate("alice", "Oldpass1!", "Strong2!").is_ok());
        assert!(policy.validate("alice", "Oldpass1!", "alice123!").is_err());
        assert!(policy.validate("alice", "Oldpass1!", "Oldpass1!").is_err());
        assert!(
            change_result(
                b"<Auth><ErrorCode>1</ErrorCode><PswMask>512</PswMask></Auth>",
                &policy,
                "alice",
                "Oldpass1!",
                "Strong2!"
            )
            .is_err()
        );
        assert!(
            change_result(
                b"<Auth><ErrorCode>20239</ErrorCode></Auth>",
                &policy,
                "alice",
                "old",
                "new"
            )
            .is_err()
        );
    }
    #[test]
    fn forced_change_posts_only_after_authenticated_account_policy() {
        let login = b"<Auth><ErrorCode>1</ErrorCode><pwpErrorCode>2</pwpErrorCode></Auth>";
        let mut calls = 0;
        submit_change(login,"alice","Oldpass1!","Strong2!", |_,path,method,form| {
            calls+=1;
            if calls==1 {
                assert_eq!(path,"/por/perinfo.csp"); assert_eq!(method,Method::GET); assert!(form.is_none());
                Ok(b"<Auth><ErrorCode>1</ErrorCode><ALL_ENABLE_PWP>737</ALL_ENABLE_PWP><MINLEN>8</MINLEN><CSRF_RAND_CODE>synthetic-csrf</CSRF_RAND_CODE></Auth>".to_vec())
            } else {
                assert_eq!(path,"/por/changepwd.csp?cknote=0"); assert_eq!(method,Method::POST);
                let form=form.unwrap(); assert_eq!(form["newpsw"],"Strong2!"); assert_eq!(form["pripsw"],""); assert_eq!(form["svpn_req_randcode"],"synthetic-csrf");
                Ok(b"<Auth><ErrorCode>1</ErrorCode></Auth>".to_vec())
            }
        }).unwrap();
        assert_eq!(calls, 2);
        assert!(
            submit_change(
                b"<Auth><ErrorCode>20004</ErrorCode></Auth>",
                "alice",
                "old",
                "new",
                |_, _, _, _| panic!("must not submit for failed authentication")
            )
            .is_err()
        );
    }
}
