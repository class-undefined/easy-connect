//! First-use certificate trust, stored separately for each HTTPS origin.
use super::*;
use std::io::Write;
use std::path::Path;

pub(super) fn resolve(gateway: &str) -> Result<String> {
    crate::cli::validate_gateway(gateway)?;
    let origin = url::Url::parse(gateway)?.origin().ascii_serialization();
    let directory = preferences_path()?
        .parent()
        .context("missing configuration directory")?
        .join("gateway-certificates");
    // Migrate a manually configured pin only for its original gateway.
    let legacy_pin = std::fs::read(preferences_path()?)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Preferences>(&bytes).ok())
        .filter(|preferences| {
            url::Url::parse(&preferences.gateway)
                .ok()
                .is_some_and(|url| url.origin().ascii_serialization() == origin)
        })
        .map(|preferences| preferences.cert_sha256)
        .unwrap_or_default();
    resolve_in(&directory, &origin, || {
        if !legacy_pin.is_empty() {
            ec_compat::modern::parse_sha256_pin(&legacy_pin)?;
            Ok(legacy_pin.to_owned())
        } else {
            Ok(ec_compat::trust::fetch_certificate_sha256(gateway)?)
        }
    })
}

fn resolve_in(
    directory: &Path,
    origin: &str,
    fetch: impl FnOnce() -> Result<String>,
) -> Result<String> {
    let path = directory.join(format!("{}.sha256", hex::encode(Sha256::digest(origin))));
    match std::fs::read_to_string(&path) {
        Ok(pin) => {
            ec_compat::modern::parse_sha256_pin(pin.trim())?;
            return Ok(pin.trim().to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("无法读取已保存的网关证书"),
    }
    let pin = fetch()?;
    ec_compat::modern::parse_sha256_pin(&pin)?;
    std::fs::create_dir_all(directory)?;
    let temporary = directory.join(format!(
        ".{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> Result<String> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(pin.as_bytes())?;
        file.sync_all()?;
        drop(file);
        // Atomically publish without replacing a pin saved by another process.
        match std::fs::hard_link(&temporary, &path) {
            Ok(()) => Ok(pin),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let saved = std::fs::read_to_string(path)?;
                ec_compat::modern::parse_sha256_pin(saved.trim())?;
                Ok(saved.trim().to_owned())
            }
            Err(error) => Err(error).context("无法保存网关证书"),
        }
    })();
    let _ = std::fs::remove_file(temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_are_persistent_and_scoped_to_origin() {
        let directory = std::env::temp_dir().join(format!("ec-pins-{}", rand::random::<u64>()));
        let first = "01".repeat(32);
        let second = "02".repeat(32);
        assert_eq!(
            resolve_in(&directory, "https://example.com:4430", || Ok(first.clone())).unwrap(),
            first
        );
        assert_eq!(
            resolve_in(&directory, "https://example.com:4430", || panic!(
                "must not fetch again"
            ))
            .unwrap(),
            first
        );
        assert_eq!(
            resolve_in(
                &directory,
                "https://example.com:4431",
                || Ok(second.clone())
            )
            .unwrap(),
            second
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn corrupt_saved_pin_is_not_replaced() {
        let directory = std::env::temp_dir().join(format!("ec-pins-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&directory).unwrap();
        let origin = "https://example.com";
        let path = directory.join(format!("{}.sha256", hex::encode(Sha256::digest(origin))));
        std::fs::write(path, "invalid").unwrap();
        assert!(resolve_in(&directory, origin, || panic!("must not replace trust")).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
