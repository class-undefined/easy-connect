use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const RELEASES: &str = "https://github.com/class-undefined/easy-connect/releases";
#[derive(Clone, Default)]
pub(super) enum UpdateState {
    #[default]
    Idle,
    Checking,
    Current,
    Available {
        version: String,
        url: String,
    },
    Failed(String),
}
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}
fn newer(release: Release, current: &str) -> Result<UpdateState> {
    let tag = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);
    let version = semver::Version::parse(tag).context("Release 版本号无效")?;
    if release.draft || release.prerelease || !version.pre.is_empty() {
        bail!("未找到正式版本");
    }
    if version > semver::Version::parse(current)? {
        Ok(UpdateState::Available {
            url: format!("{RELEASES}/tag/v{version}"),
            version: version.to_string(),
        })
    } else {
        Ok(UpdateState::Current)
    }
}
pub(super) fn check(state: Arc<Mutex<UpdateState>>) {
    if let Ok(mut s) = state.lock() {
        if matches!(*s, UpdateState::Checking) {
            return;
        }
        *s = UpdateState::Checking;
    }
    std::thread::spawn(move || {
        let result = (|| -> Result<UpdateState> {
            tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
                let client = reqwest::Client::builder().timeout(Duration::from_secs(15))
                    .user_agent(concat!("easy-connect/", env!("CARGO_PKG_VERSION")))
                    .build()?;
                let response = client.get("https://api.github.com/repos/class-undefined/easy-connect/releases/latest")
                    .header("Accept", "application/vnd.github+json").send().await?.error_for_status()?;
                let release = serde_json::from_slice(&response.bytes().await?)?;
                newer(release, env!("CARGO_PKG_VERSION"))
            })
        })();
        if let Ok(mut s) = state.lock() {
            *s = result.unwrap_or_else(|e| UpdateState::Failed(format!("检查更新失败：{e}")));
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    fn release(tag: &str) -> Release {
        Release {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
        }
    }
    #[test]
    fn compares_versions_numerically_and_never_downgrades() {
        assert!(matches!(
            newer(release("v0.10.0"), "0.9.0").unwrap(),
            UpdateState::Available { .. }
        ));
        assert!(matches!(
            newer(release("v0.9.0"), "0.10.0").unwrap(),
            UpdateState::Current
        ));
        assert!(matches!(
            newer(release("v0.10.0"), "0.10.0").unwrap(),
            UpdateState::Current
        ));
        assert!(newer(release("v1.0.0-rc.1"), "0.10.0").is_err());
        assert!(newer(release("../../other"), "0.10.0").is_err());
    }
}
