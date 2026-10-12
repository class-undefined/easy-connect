# Source provenance

This document records the upstream source relationships relevant to licensing
and reproducibility. It distinguishes code ancestry from build and runtime
dependencies.

## Provenance summary

| Source | Version or commit | Current relationship | License effect |
| --- | --- | --- | --- |
| [`heeh02/HKUST-GZ-Connect`](https://github.com/heeh02/HKUST-GZ-Connect) | `321cecdc860b96f25c36d99447b5f151bc18c7a2` | Source basis for the desktop UI, CLI, release tooling, and substantial Rust engine code | Inherited material remains GPL-3.0-only |
| [`Mythologyli/zju-connect`](https://github.com/Mythologyli/zju-connect) | `v1.1.1` | Source reference used during development of the active EasyConnect-compatible protocol implementation; not a build or runtime dependency | The engine is treated conservatively as carrying AGPL-3.0-only obligations in addition to its GPL obligations |
| [`lyc8503/NJUConnect`](https://github.com/lyc8503/NJUConnect), formerly EasierConnect | Indirect upstream named by `zju-connect` | No source was directly imported by this repository; listed to preserve the documented upstream lineage | No separate direct dependency classification is asserted here |
| [`GeiserX/tailscale-rs`](https://github.com/GeiserX/tailscale-rs) | crates `geiserx_ts_netstack_smoltcp`, `_core`, and `_socket` `0.43.0`; repository commit `43dac4616ae17f997af184114cd8cf0473af375b` | Compiled dependency providing the userspace TCP/IP stack | BSD-3-Clause notice must accompany source and binary distributions |
| Sangfor EasyConnect-compatible campus gateway and official client | Behavior observed with authorization | Protocol behavior and compatibility reference only; no official client binary is shipped | Proprietary names and binaries are not licensed by this project |

## `heeh02/HKUST-GZ-Connect`

The current repository was assembled from and modified after the GPL-3.0-only
source at the commit listed above. This relationship is substantive, not merely
conceptual: current desktop, CLI, and engine files retain code from that source.
The upstream author has not granted this project a separate relicensing
permission. Those files therefore remain covered by GPL-3.0-only.

## `zju-connect`

`zju-connect` source is not downloaded, linked, embedded, or invoked during the
current build or at runtime. A local source review nevertheless informed the
active protocol implementation. The project has no agreement with its authors
and does not claim that reading AGPL source created a clean-room boundary.

Because a reliable file- or expression-level separation cannot now be proven,
the entire `engine/` component is distributed under the combined expression
`GPL-3.0-only AND AGPL-3.0-only`. This is a conservative compliance decision;
it is not a claim of authorship over, or relicensing of, upstream code.

`zju-connect` documents EasierConnect, now `lyc8503/NJUConnect`, as its own
upstream. This repository records that lineage without claiming a direct
source import from EasierConnect/NJUConnect.

## Userspace netstack

The Rust engine imports `geiserx_ts_netstack_smoltcp` directly. Its three
published crates are pinned to `0.43.0` in `engine/Cargo.lock` and statically
linked into release engine binaries. The fork's BSD-3-Clause notice preserves
the original Tailscale copyright and the GeiserX fork-modification copyright.
The exact notice shipped with the reviewed repository commit is reproduced in
`LICENSES/BSD-3-Clause-GeiserX-tailscale-rs.txt`.

## Desktop runtime and packaging

Version 1.4.1 updates the existing Electron runtime to `43.7.9` and resolves
the existing electron-builder dependency to `26.17.0`. Compatible transitive
security patches and the existing build overrides are recorded with their
integrity hashes in `desktop/package-lock.json`; no additional upstream source
was imported for the app lifecycle changes. Electron's MIT license and its
Chromium third-party notices are copied from the exact runtime into the
packaged application's `legal/electron/` directory as described in
`THIRD_PARTY_NOTICES.md`.

## Evidence and future changes

- Preserve the upstream identifiers and license files in every release.
- Do not describe the implementation as clean-room or independently authored
  unless a documented audit establishes that conclusion.
- Do not change the GPL/AGPL classification without permission from all
  relevant copyright holders or qualified legal review of a documented
  provenance audit.
- Record new copied, translated, vendored, linked, or source-reviewed projects
  here before merging the affected code.
