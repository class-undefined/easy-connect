# Notices and attribution

HKUST and HKUST(GZ) names and marks belong to the university. This repository
uses the name only to identify network compatibility. It contains no official
university logo, seal, client binary, private key, credential, session token,
or raw packet capture, and it does not imply university endorsement.

This repository incorporates and modifies GPL-3.0-only source from
`heeh02/HKUST-GZ-Connect` at commit
`321cecdc860b96f25c36d99447b5f151bc18c7a2`. The current maintainers are not
affiliated with that project and have no separate relicensing agreement with
its authors. The inherited material remains under GPL-3.0-only.

Development of the Rust engine also included review of the AGPL-3.0-only
`Mythologyli/zju-connect` v1.1.1 source. `zju-connect` is not downloaded,
linked, embedded, or invoked by the current build or runtime, but that fact
does not remove source-provenance obligations. Because a reliable boundary
cannot now be established, `engine/` is treated as a GPLv3/AGPLv3 combined
work. `zju-connect` in turn acknowledges EasierConnect, now
`lyc8503/NJUConnect`, as its upstream; that indirect lineage is preserved in
`PROVENANCE.md`.

The engine statically links the BSD-3-Clause
`geiserx_ts_netstack_smoltcp` 0.43.0 crate family from
`GeiserX/tailscale-rs`. The required Tailscale and GeiserX copyright notice,
conditions, and disclaimer are shipped in
`LICENSES/BSD-3-Clause-GeiserX-tailscale-rs.txt`.

Other third-party Rust, Node, Electron, and Chromium components retain their
own licenses. Locked dependency manifests are committed for review and
reproducible resolution. See `LICENSE`, `PROVENANCE.md`, and
`THIRD_PARTY_NOTICES.md`.
