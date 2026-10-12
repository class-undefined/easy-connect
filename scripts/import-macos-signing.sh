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
# The user trust domain prompts through SecurityAgent even in CI. The ephemeral
# runner permits noninteractive admin trust; constrain it to code signing.
sudo -n security add-trusted-cert -d -r trustRoot -p codeSign -k /Library/Keychains/System.keychain "$certificate"
# Key lookup and certificate-chain lookup use the user search list as well as
# codesign's explicit --keychain. Preserve the runner's existing keychains.
existing_keychains=()
while IFS= read -r entry; do
  existing_keychains+=("$entry")
done < <(security list-keychains -d user | sed -E 's/^[[:space:]]*"(.*)"$/\1/')
security list-keychains -d user -s "$keychain" "${existing_keychains[@]}"
security find-identity -v -p codesigning "$keychain"
rm -f "$archive"
printf 'MACOS_SIGNING_KEYCHAIN=%s\n' "$keychain" >> "$GITHUB_ENV"
printf 'MACOS_SIGNING_IDENTITY=%s\n' "$fingerprint" >> "$GITHUB_ENV"
