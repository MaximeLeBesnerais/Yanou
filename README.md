# MuHarmony

An unofficial Mullvad VPN client for **HarmonyOS NEXT**, written in ArkTS with the
WireGuard engine in Rust.

> **Not affiliated with Mullvad VPN AB.** "Mullvad" is their trademark and is used here
> only to describe what this client connects to. There is no endorsement, no support and
> no warranty. Use it with your own account, at your own risk, and respect the laws of
> the country you are in.

## What works

- Account sign-in with a rotated device key per login, devices managed from the app.
- WireGuard tunnels over IPv4 and IPv6, plus Shadowsocks obfuscation through a relay's
  dedicated `shadowsocks_extra_addr_in` addresses when the relay's own address is
  filtered.
- Transport ladder `direct-v6 → shadowsocks-v4 → direct-v4 → shadowsocks-v6`, relay-major,
  with a fixed reconnect ladder on a dropped tunnel (same relay twice, then a different
  one, then a notification).
- Server browser: country → city → relay, filter chips, favourites, recents, usage.
- Continuous background task, status notification with Disconnect/Reconnect actions, and a
  watchdog that reports a silently dropped VPN instead of lying about it.
- Diagnostics: one entry per connection attempt, with a live tail and export.

## What does not work (yet)

- DAITA, multihop, LWO, QUIC/MASQUE, udp2tcp.
- Per-application tunnelling, DNS content blocking, custom DNS.
- Android-in-a-box containers (EasyAbroad, DroidTong) bypass any host-level VPN; that is a
  platform boundary, not something this client can fix. See `PORT-PLAN.md` §3.3.

## Building

Requirements: DevEco Studio 6.x with the HarmonyOS SDK (API 26), Rust with the
`aarch64-unknown-linux-ohos` target, the HarmonyOS NDK, and a device or emulator.

```sh
# 1. signing: let DevEco generate a debug profile for *your* device, then
#    copy the generated material into app/build-profile.json5 (see the example)
cp app/build-profile.example.json5 app/build-profile.json5

# 2. native core (tun + gotatun + API client) for OHOS
cd app && CARGO_HOME="$HOME/.cargo" ./scripts/build-native.sh

# 3. HAP
hvigorw assembleHap --mode module -p product=default -p module=entry@default --no-daemon

# 4. install
hdc install -r entry/build/default/outputs/default/entry-default-signed.hap
```

`app/scripts/shot.sh` pulls a screenshot, `app/scripts/push-hap.sh` copies the signed HAP
into the device's Downloads folder.

## Layout

| Path | What |
|---|---|
| `app/` | DevEco project: ArkTS UI, the VPN extension, the C NAPI shim |
| `app/rust/crates/core` | WireGuard engine, transport/obfuscation, Mullvad API client |
| `PORT-PLAN.md` | feasibility study, milestones, roadmap, UI backlog |
| `ANDROID-PATH-REPORT.md` | line-by-line trace of the official Android client's connect path |
| `docs/` | sample diagnostics log |

`source/` is **not** part of this repository: it is a sparse checkout of
[mullvad/mullvadvpn-app](https://github.com/mullvad/mullvadvpn-app) used while writing the
port, not to build it.

## Licence

GPL-3.0-or-later, the same licence as the client this is derived from. See `LICENSE`.
The Rust side follows upstream's structure closely (`talpid-wireguard`, `tunnel-obfuscation`,
`mullvad-api`), and the domain-fronting strategy is copied from `mullvad-api`.
