# mullvad-masque-proxy (vendored)

The MASQUE CONNECT-UDP client that carries WireGuard datagrams inside QUIC for the
`quic` transport (`crates/core/src/transports/quic.rs`).

Source: <https://github.com/mullvad/mullvadvpn-app>, path `mullvad-masque-proxy/`, commit
`e522e99b8c2057e0168e7b9d966ca66ae2103bf5`. The crate is a workspace member upstream and is
not published on crates.io, so it is vendored rather than pulled from the registry.

License: GPL-3.0-or-later, the same licence as this application. See the repository's
[`LICENSE`](../../../../LICENSE).

## What changed

- `Cargo.toml` only. Upstream inherits `edition`, `rust-version`, `license` and all
  dependency versions from its workspace; they are written out here, pinned to the versions
  upstream uses. The dev-dependencies (`talpid-tunnel`, `clap`, `criterion`, `rand`) are
  removed because the benches, examples and integration tests are not vendored, and the
  Windows GSO dependencies (`socket2`, `windows-sys`) are dropped because this copy is only
  built for OpenHarmony. `src/client/mod.rs` keeps its Windows GSO path, which is inert on
  this target.
- Everything under `src/` is byte-for-byte upstream, including the unused `server` module
  (kept so `src/lib.rs` needs no edit and the diff stays reviewable).

To update: re-copy `src/` from a newer upstream checkout and re-apply the manifest changes
above.
