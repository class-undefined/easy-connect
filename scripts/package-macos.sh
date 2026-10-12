#!/bin/bash
set -euo pipefail
arch="${1:-aarch64}"
version="${2:-0.2.0}"
target="$arch-apple-darwin"
stage=".release-stage/macos-$arch"
app="$stage/EasyConnect Rust.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" dist
cp "target/$target/release/easy-connect" "$app/Contents/MacOS/easy-connect"
cp "target/$target/release/easy-connect-gui" "$app/Contents/MacOS/easy-connect-gui"
cp -R LICENSE THIRD_PARTY_NOTICES.md vendor/ec-compat/LICENSES "$app/Contents/Resources/"
cp vendor/ec-compat/NOTICE.md "$app/Contents/Resources/UPSTREAM-NOTICE.md"
cp vendor/ec-compat/PROVENANCE.md "$app/Contents/Resources/UPSTREAM-PROVENANCE.md"
cp .release-stage/DEPENDENCY-LICENSES.txt "$app/Contents/Resources/"
printf '%s\n' 'Source: https://github.com/class-undefined/easy-connect' > "$app/Contents/Resources/SOURCE.txt"
cp assets/EasyConnect.icns "$app/Contents/Resources/EasyConnect.icns"
cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>EasyConnect Rust</string>
<key>CFBundleDisplayName</key><string>EasyConnect Rust</string>
<key>CFBundleIdentifier</key><string>com.easy-connect.desktop</string>
<key>CFBundleExecutable</key><string>easy-connect-gui</string>
<key>CFBundleIconFile</key><string>EasyConnect.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
codesign --force --sign - "$app/Contents/MacOS/easy-connect"
codesign --force --deep --sign - "$app"
codesign --verify --deep --strict "$app"
ln -s /Applications "$stage/Applications"
hdiutil create -volname "EasyConnect Rust $version" -srcfolder "$stage" -ov -format UDZO "dist/easy-connect-$version-macos-$arch.dmg"
