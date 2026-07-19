# Changelog

Notable changes, generated from [conventional commits](https://www.conventionalcommits.org) by
git-cliff. Do not edit by hand.
## Unreleased

### Bug Fixes
- block SSRF to internal/metadata targets by resolved IP (ADV18-10) (95d51a7)
- close F-18d, HpsRekey fails safe under a mid-arm panic (#104) (879019b)
- cover Destination::Vaccine in every workspace crate (relay/relayd/hop-sim) + workspace fmt/clippy (e611c4d)

### CI
- bump create-github-app-token to v3.2.0 across all mirrored components (efc9f6c)

### Chore
- gate ssrf ip filter behind reqwest feature; fmt (a6f4665)
- drop the root license, license per-component (FSL-1.1-ALv2) (#146) (be2a5a7)

### Dependencies
- land the grouped rust-dependencies bump (sha2, ed25519/x25519-dalek, chacha20poly1305, snow, rusqlite, p256, uniffi, tungstenite) (#89) (2038ce9)

### Documentation
- branded, marketable READMEs for every sub-repo (9c2a477)

### Other
- CLA gate on contributions (preserve commercial relicensing of core) (5a9aa7d)
- SECURITY.md per component + enable-security in the bootstrap script (a1492e9)
- copyright holder is Hop Mesh, LLC (7d8c514)
- fill the Apache-2.0 copyright placeholder (2026 Jason Waldrip) (2fb7d1c)
- Apache-2.0 for everything except core/ (only the protocol stays FSL) (0fe9439)
- CHANGE_REQUEST sync-back + document merge/conversation + confidentiality (9e1dec2)
- remove Destination::InternetEgress (mesh-visible internet-bound leak) (5dd64d3)

