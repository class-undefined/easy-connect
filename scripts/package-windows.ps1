param([Parameter(Mandatory=$true)][string]$Arch,[string]$Version="0.2.0")
$ErrorActionPreference = "Stop"
$target = "$Arch-pc-windows-msvc"
$stage = ".release-stage/windows-$Arch"
New-Item -ItemType Directory -Force $stage,dist | Out-Null
Copy-Item "target/$target/release/easy-connect.exe","target/$target/release/easy-connect-gui.exe" $stage
$temporaryRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$archive = Join-Path $temporaryRoot "wintun-0.14.1.zip"
Invoke-WebRequest "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $archive
$expected = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLower() -ne $expected) { throw "Wintun checksum mismatch" }
$unpacked = "$archive.contents"
Expand-Archive $archive $unpacked -Force
$driverArch = if ($Arch -eq "aarch64") { "arm64" } else { "amd64" }
Copy-Item "$unpacked/wintun/bin/$driverArch/wintun.dll" $stage
Copy-Item "$unpacked/wintun/LICENSE.txt" "$stage/WINTUN-LICENSE.txt"
Copy-Item LICENSE,THIRD_PARTY_NOTICES.md,README.md $stage
Copy-Item .release-stage/DEPENDENCY-LICENSES.txt $stage
Copy-Item vendor/ec-compat/NOTICE.md "$stage/UPSTREAM-NOTICE.md"
Copy-Item vendor/ec-compat/PROVENANCE.md "$stage/UPSTREAM-PROVENANCE.md"
"Source: https://github.com/class-undefined/easy-connect" | Set-Content "$stage/SOURCE.txt"
Copy-Item -Recurse vendor/ec-compat/LICENSES "$stage/LICENSES"
Compress-Archive "$stage/*" "dist/easy-connect-$Version-windows-$Arch.zip" -Force
