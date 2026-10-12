#!/bin/bash
set -euo pipefail
: "${MACOS_CERTIFICATE_P12:?Signing certificate secret is required}"
: "${MACOS_CERTIFICATE_PASSWORD:?Signing password secret is required}"
: "${RUNNER_TEMP:?This script is intended for GitHub Actions}"
keychain="$RUNNER_TEMP/easy-connect-signing.keychain-db"
archive="$RUNNER_TEMP/easy-connect-signing.p12"
certificate="$RUNNER_TEMP/easy-connect-signing.pem"
keychain_password="$(openssl rand -hex 32)"
echo "::add-mask::$keychain_password"
umask 077
printf '%s' "$MACOS_CERTIFICATE_P12" | base64 --decode > "$archive"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$archive" -k "$keychain" -P "$MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign > /dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain" > /dev/null
security find-certificate -c class-undefined -p "$keychain" > "$certificate"
fingerprint="$(openssl x509 -in "$certificate" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
if [ "$fingerprint" != '16CA7F918F2452512BEC526ECFF8561349493198' ]; then
  echo 'Unexpected macOS signing identity' >&2
  exit 1
fi
security add-trusted-cert -r trustRoot -p codeSign -k "$keychain" "$certificate"
rm -f "$archive"
printf 'MACOS_SIGNING_KEYCHAIN=%s\n' "$keychain" >> "$GITHUB_ENV"
printf 'MACOS_SIGNING_IDENTITY=%s\n' "$fingerprint" >> "$GITHUB_ENV"
