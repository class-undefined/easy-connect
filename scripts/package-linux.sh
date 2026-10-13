#!/bin/bash
set -euo pipefail
arch="${1:-x86_64}"
version="${2:?Supply package version}"
target="$arch-unknown-linux-gnu"
stage=".release-stage/linux-$arch"
mkdir -p "$stage/deploy/linux" "$stage/scripts" "$stage/docs" dist
cp "target/$target/release/easy-connect" "$stage/"
cp LICENSE THIRD_PARTY_NOTICES.md .release-stage/DEPENDENCY-LICENSES.txt "$stage/"
cp -R vendor/ec-compat/LICENSES "$stage/"
cp vendor/ec-compat/NOTICE.md "$stage/UPSTREAM-NOTICE.md"
cp vendor/ec-compat/PROVENANCE.md "$stage/UPSTREAM-PROVENANCE.md"
cp deploy/linux/easy-connect.service "$stage/deploy/linux/"
cp scripts/install-linux.sh "$stage/scripts/"
cp docs/linux-tailscale.md "$stage/docs/"
printf '%s\n' 'Source: https://github.com/class-undefined/easy-connect' > "$stage/SOURCE.txt"
tar -czf "dist/easy-connect-$version-linux-$arch.tar.gz" -C "$stage" .
