use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};

mod installer;

const RELEASES: &str = "https://github.com/class-undefined/easy-connect/releases";
const MAX_DOWNLOAD: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(super) struct Offer {
    version: String,
    name: String,
    size: u64,
    url: String,
    checksums_url: String,
    digest: Option<String>,
}

#[derive(Clone, Default)]
pub(super) enum UpdateState {
    #[default]
    Idle,
    Checking,
    Current,
    Available(Offer),
    Downloading {
        offer: Offer,
        received: u64,
    },
    Preparing(Offer),
    Ready {
        offer: Offer,
        prepared: Arc<installer::PreparedUpdate>,
    },
    Installing(Offer),
    Failed {
        message: String,
        offer: Option<Offer>,
    },
}

impl UpdateState {
    pub(super) fn manual_url(&self) -> Option<String> {
        match self {
            Self::Failed {
                offer: Some(offer), ..
            } => offer
                .url
                .rsplit_once('/')
                .map(|(base, _)| base.replacen("/download/", "/tag/", 1)),
            Self::Failed { .. } => Some(RELEASES.into()),
            _ => None,
        }
    }
    pub(super) fn busy(&self) -> bool {
        matches!(
            self,
            Self::Checking
                | Self::Downloading { .. }
                | Self::Preparing(_)
                | Self::Ready { .. }
                | Self::Installing(_)
        )
    }
    pub(super) fn can_install(&self) -> bool {
        matches!(
            self,
            Self::Available(_) | Self::Failed { offer: Some(_), .. }
        )
    }
    pub(super) fn label(&self) -> String {
        match self {
            Self::Available(offer) => format!("一键更新 v{}", offer.version),
            Self::Downloading { offer, received } => format!(
                "下载更新 {}%",
                received.saturating_mul(100) / offer.size.max(1)
            ),
            Self::Preparing(offer) => format!("校验 v{}…", offer.version),
            Self::Ready { .. } | Self::Installing(_) => "正在安装并重启…".into(),
            Self::Checking => "检查中…".into(),
            Self::Current => "已是最新版".into(),
            Self::Failed { offer: Some(_), .. } => "重试更新".into(),
            Self::Failed { .. } => "更新失败 · 重试".into(),
            _ => format!("v{} · 检查更新", env!("CARGO_PKG_VERSION")),
        }
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
    #[serde(default)]
    digest: Option<String>,
}

fn asset_name(version: &str, os: &str, arch: &str) -> Result<String> {
    let suffix = match (os, arch) {
        ("macos", "aarch64" | "x86_64") => "dmg",
        ("windows", "aarch64" | "x86_64") => "zip",
        _ => bail!("当前系统或架构不支持一键更新"),
    };
    Ok(format!("easy-connect-{version}-{os}-{arch}.{suffix}"))
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
    if version <= semver::Version::parse(current)? {
        return Ok(UpdateState::Current);
    }
    let name = asset_name(
        &version.to_string(),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )?;
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .context("新版尚未提供当前系统的安装包")?;
    if asset.size == 0 || asset.size > MAX_DOWNLOAD {
        bail!("更新包大小无效");
    }
    if !release
        .assets
        .iter()
        .any(|asset| asset.name == "SHA256SUMS.txt")
    {
        bail!("新版缺少 SHA-256 校验文件");
    }
    // Construct repository-owned URLs instead of following URLs from metadata.
    let mut base = url::Url::parse(RELEASES)?;
    base.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("更新地址无效"))?
        .push("download")
        .push(&release.tag_name);
    let download_url = |name: &str| -> Result<String> {
        let mut url = base.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("更新地址无效"))?
            .push(name);
        Ok(url.to_string())
    };
    Ok(UpdateState::Available(Offer {
        version: version.to_string(),
        url: download_url(&name)?,
        checksums_url: download_url("SHA256SUMS.txt")?,
        name,
        size: asset.size,
        digest: asset.digest.clone(),
    }))
}

fn client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(15))
        .user_agent(concat!("easy-connect/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

async fn bounded_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    response = response.error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            bail!("更新服务器响应过大");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(super) fn initial_state() -> UpdateState {
    installer::previous_failure().map_or(UpdateState::Idle, |message| UpdateState::Failed {
        message,
        offer: None,
    })
}

pub(super) fn check(state: Arc<Mutex<UpdateState>>) {
    if let Ok(mut s) = state.lock() {
        if s.busy() {
            return;
        }
        *s = UpdateState::Checking;
    } else {
        return;
    }
    std::thread::spawn(move || {
        let result = (|| -> Result<UpdateState> {
            tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
                let response = client(Duration::from_secs(20))?
                    .get("https://api.github.com/repos/class-undefined/easy-connect/releases/latest")
                    .header("Accept", "application/vnd.github+json").send().await?;
                newer(serde_json::from_slice(&bounded_body(response, 1024 * 1024).await?)?, env!("CARGO_PKG_VERSION"))
            })
        })();
        if let Ok(mut s) = state.lock() {
            *s = result.unwrap_or_else(|e| UpdateState::Failed {
                message: format!("检查更新失败：{e:#}"),
                offer: None,
            });
        }
    });
}

fn checksum(manifest: &[u8], name: &str) -> Result<String> {
    let text = std::str::from_utf8(manifest).context("校验文件编码无效")?;
    let mut matches = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(hash), Some(path)) = (fields.next(), fields.next()) else {
            continue;
        };
        let path = path
            .trim_start_matches('*')
            .strip_prefix("dist/")
            .unwrap_or(path.trim_start_matches('*'));
        if path == name {
            if fields.next().is_some()
                || hash.len() != 64
                || !hash.bytes().all(|b| b.is_ascii_hexdigit())
            {
                bail!("更新包校验记录无效");
            }
            matches.push(hash.to_ascii_lowercase());
        }
    }
    if matches.len() != 1 {
        bail!("更新包缺少唯一的 SHA-256 校验记录");
    }
    Ok(matches.remove(0))
}

async fn download(
    offer: &Offer,
    job: &std::path::Path,
    state: &Arc<Mutex<UpdateState>>,
) -> Result<std::path::PathBuf> {
    let client = client(Duration::from_secs(15 * 60))?;
    let manifest = bounded_body(
        client
            .get(&offer.checksums_url)
            .timeout(Duration::from_secs(20))
            .send()
            .await?,
        64 * 1024,
    )
    .await?;
    let expected = checksum(&manifest, &offer.name)?;
    if let Some(digest) = &offer.digest
        && digest != &format!("sha256:{expected}")
    {
        bail!("Release 与校验文件的摘要不一致");
    }
    let part = job.join("download.part");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&part)?;
    let mut response = client.get(&offer.url).send().await?.error_for_status()?;
    let mut received = 0_u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response.chunk().await? {
        received += chunk.len() as u64;
        if received > offer.size || received > MAX_DOWNLOAD {
            bail!("下载文件大小与 Release 不符");
        }
        file.write_all(&chunk)?;
        hash.update(&chunk);
        if let Ok(mut s) = state.lock() {
            *s = UpdateState::Downloading {
                offer: offer.clone(),
                received,
            };
        }
    }
    file.sync_all()?;
    drop(file);
    if received != offer.size || hex::encode(hash.finalize()) != expected {
        bail!("更新包校验失败，请重新下载");
    }
    let archive = job.join(&offer.name);
    std::fs::rename(part, &archive)?;
    Ok(archive)
}

pub(super) fn activate(state: Arc<Mutex<UpdateState>>) {
    let offer = if let Ok(mut s) = state.lock() {
        if s.busy() {
            return;
        }
        let offer = match &*s {
            UpdateState::Available(offer)
            | UpdateState::Failed {
                offer: Some(offer), ..
            } => Some(offer.clone()),
            _ => None,
        };
        if let Some(offer) = &offer {
            *s = UpdateState::Downloading {
                offer: offer.clone(),
                received: 0,
            };
        }
        offer
    } else {
        return;
    };
    let Some(offer) = offer else {
        check(state);
        return;
    };
    std::thread::spawn(move || {
        let mut job = None;
        let result = (|| -> Result<installer::PreparedUpdate> {
            let directory = installer::new_job()?;
            job = Some(directory.clone());
            let archive = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(download(&offer, &directory, &state))?;
            if let Ok(mut s) = state.lock() {
                *s = UpdateState::Preparing(offer.clone());
            }
            installer::prepare(&archive, directory, &offer.version)
        })();
        if result.is_err()
            && let Some(job) = job
        {
            let _ = std::fs::remove_dir_all(job);
        }
        if let Ok(mut s) = state.lock() {
            *s = match result {
                Ok(prepared) => UpdateState::Ready {
                    offer,
                    prepared: Arc::new(prepared),
                },
                Err(error) => UpdateState::Failed {
                    message: format!("更新失败：{error:#}"),
                    offer: Some(offer),
                },
            };
        }
    });
}

pub(super) fn install_if_ready(
    state: &Arc<Mutex<UpdateState>>,
    controller: &super::Controller,
) -> bool {
    let Ok(mut s) = state.lock() else {
        return false;
    };
    if let UpdateState::Installing(offer) = &*s
        && let Ok(live) = controller.live.lock()
        && !live.quitting
    {
        *s = UpdateState::Failed {
            message: live
                .notice
                .clone()
                .unwrap_or_else(|| "更新安装未能启动，请重试".into()),
            offer: Some(offer.clone()),
        };
    }
    let UpdateState::Ready { offer, prepared } = &*s else {
        return false;
    };
    let (offer, prepared) = (offer.clone(), prepared.clone());
    if controller.quit_with_install(move || installer::launch(&prepared)) {
        *s = UpdateState::Installing(offer);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release(tag: &str) -> Release {
        let version = tag.trim_start_matches('v');
        Release {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
            assets: vec![
                Asset {
                    name: asset_name(version, std::env::consts::OS, std::env::consts::ARCH)
                        .unwrap(),
                    size: 123,
                    digest: None,
                },
                Asset {
                    name: "SHA256SUMS.txt".into(),
                    size: 100,
                    digest: None,
                },
            ],
        }
    }
    #[test]
    fn compares_versions_numerically_and_never_downgrades() {
        assert!(matches!(
            newer(release("v0.10.0"), "0.9.0").unwrap(),
            UpdateState::Available(_)
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
    #[test]
    fn selects_only_the_matching_platform_package_and_requires_checksums() {
        for os in ["macos", "windows"] {
            for arch in ["aarch64", "x86_64"] {
                let name = asset_name("1.2.3", os, arch).unwrap();
                assert!(name.contains(&format!("{os}-{arch}")));
            }
        }
        assert!(asset_name("1.2.3", "windows", "x86").is_err());
        let mut r = release("v1.2.3");
        r.assets.pop();
        assert!(newer(r, "1.0.0").is_err());
        let mut r = release("v1.2.3");
        r.assets[0].name = "other-platform.zip".into();
        assert!(newer(r, "1.0.0").is_err());
    }
    #[test]
    fn checksum_is_bound_to_one_exact_release_asset() {
        let hash = "a".repeat(64);
        let manifest = format!("{hash}  dist/package.dmg\n{}  other.dmg\n", "b".repeat(64));
        assert_eq!(checksum(manifest.as_bytes(), "package.dmg").unwrap(), hash);
        assert!(checksum(manifest.as_bytes(), "missing.dmg").is_err());
        assert!(
            checksum(
                format!("{manifest}{hash}  package.dmg\n").as_bytes(),
                "package.dmg"
            )
            .is_err()
        );
        assert!(checksum(b"bad  package.dmg", "package.dmg").is_err());
    }
    #[test]
    fn checking_cannot_replace_an_update_in_progress() {
        let UpdateState::Available(offer) = newer(release("v1.2.3"), "1.0.0").unwrap() else {
            panic!()
        };
        let state = Arc::new(Mutex::new(UpdateState::Downloading {
            offer,
            received: 12,
        }));
        check(state.clone());
        activate(state.clone());
        assert!(matches!(
            *state.lock().unwrap(),
            UpdateState::Downloading { received: 12, .. }
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "downloads a published DMG; only swaps temporary fixture directories"]
    fn published_package_download_staging_and_rollback() -> Result<()> {
        let job = installer::new_job()?;
        let result = (|| -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let (offer, archive) = runtime.block_on(async {
                let response = client(Duration::from_secs(30))?.get("https://api.github.com/repos/class-undefined/easy-connect/releases/tags/v0.4.6").send().await?;
                let UpdateState::Available(offer) = newer(serde_json::from_slice(&bounded_body(response, 1024 * 1024).await?)?, "0.0.0")? else { bail!("fixture release unavailable") };
                let state = Arc::new(Mutex::new(UpdateState::Idle));
                let archive = download(&offer, &job, &state).await?;
                Ok::<_, anyhow::Error>((offer, archive))
            })?;
            let destination = job.join("Installed 测试 'app'.app");
            std::fs::create_dir(&destination)?;
            std::fs::write(destination.join("old-version"), b"unchanged")?;
            let prepared = installer::prepare_macos(
                &archive,
                job.clone(),
                &offer.version,
                destination.clone(),
            )?;
            let incoming = job.join("incoming.app");
            let backup = job.join("backup.app");
            let apply = |mode: &str| -> Result<()> {
                let output = std::process::Command::new("/bin/sh")
                    .arg(prepared.job.join("apply.sh"))
                    .arg(job.join("EasyConnect Rust.app"))
                    .arg(&destination)
                    .arg(&incoming)
                    .arg(&backup)
                    .arg(mode)
                    .output()?;
                if !output.status.success() {
                    bail!(
                        "fixture installer failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Ok(())
            };
            apply("install")?;
            assert!(
                destination
                    .join("Contents/MacOS/easy-connect-gui")
                    .is_file()
            );
            assert_eq!(std::fs::read(backup.join("old-version"))?, b"unchanged");
            apply("rollback")?;
            assert_eq!(
                std::fs::read(destination.join("old-version"))?,
                b"unchanged"
            );
            assert!(!incoming.exists());
            println!(
                "Verified published v{} download, checksum, signature, staging, temporary install and rollback",
                offer.version
            );
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&job);
        result
    }
}
