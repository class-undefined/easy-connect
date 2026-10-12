# Third-party notices

This distribution contains third-party components. Their licenses apply to
those components independently of the GPL/AGPL terms governing this project.
Pinned dependency versions are recorded in `engine/Cargo.lock` and
`desktop/package-lock.json`.

## GeiserX/Tailscale userspace netstack

The release engine statically links these crates at version `0.43.0`:

- `geiserx_ts_netstack_smoltcp`
- `geiserx_ts_netstack_smoltcp_core`
- `geiserx_ts_netstack_smoltcp_socket`

Source: <https://github.com/GeiserX/tailscale-rs>  
Reviewed repository commit: `43dac4616ae17f997af184114cd8cf0473af375b`  
License: BSD-3-Clause

The required copyright notice, conditions, and disclaimer are reproduced
verbatim in `LICENSES/BSD-3-Clause-GeiserX-tailscale-rs.txt` and must remain
with source and binary distributions.

## Electron and Chromium

The desktop application bundles Electron and Chromium. Their license and
third-party Chromium notices are copied from the exact installed Electron
distribution into `Contents/Resources/legal/electron/` in packaged macOS apps.
Those generated release files must not be removed.

## Other locked dependencies

Other Rust and Node packages retain the license identifiers and source
integrity metadata recorded by their locked manifests. Build-only Node
packages are not represented as runtime code merely because they appear in
`desktop/package-lock.json`. Release maintainers must review the resolved
runtime artifact whenever the dependency graph changes and preserve any
package-specific attribution or license text required by that artifact.

This file is an attribution index, not a replacement for the full license
texts shipped in `LICENSES/` or with Electron.
