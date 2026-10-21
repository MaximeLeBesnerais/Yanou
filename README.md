# Yanshu

**Yanshu is an unofficial HarmonyOS NEXT client for Mullvad VPN.** You sign in with your
own Mullvad account number; the app registers a WireGuard device with `api.mullvad.net`,
downloads Mullvad's signed relay list, and sends the tablet's traffic through a Mullvad
relay inside the system VPN extension. The relays are Mullvad's, the account and its
five-device limit are Mullvad's, and the tunnel is real WireGuard — nothing here is a
proxy, a reseller or a separate network.

> **Not affiliated with Mullvad VPN AB.** "Mullvad" is their trademark, used here only to
> describe what this client connects to. No endorsement, no support, no warranty. Use it
> with your own account, at your own risk, and obey the law where you are.

Getting to Mullvad from a filtered network is most of the engineering. `api.mullvad.net`
is DNS-poisoned on the networks this was built on, so the client speaks Mullvad's own
**domain-fronting** protocol (TLS to a CDN with a harmless SNI, the API multiplexed
inside); and when a network blackholes plain WireGuard, it can wrap the tunnel in
Mullvad's **Shadowsocks** transport instead. Both paths are described in
[Part 2](#part-2--how-the-app-works).

The repository is two things at once: a working client, and a record of what it takes to
port a VPN from Android to HarmonyOS — including the parts the documentation does not tell
you. This README starts with how to get a development setup working, because that is the
first wall anyone hits. The port notes follow in
[Part 3](#part-3--porting-a-vpn-client-to-harmonyos), with the long-form background in
[`PORT-PLAN.md`](PORT-PLAN.md) and [`ANDROID-PATH-REPORT.md`](ANDROID-PATH-REPORT.md).

**Tested on** a Huawei MatePad (TGR-W00), HarmonyOS 6.1, SDK API 26, `compatibleSdkVersion
6.1.1(24)`. Only the `arm64-v8a` ABI is wired up.

---

## Part 1 — Setting up HarmonyOS development

Everything below was done on macOS with a HarmonyOS 6.1 tablet (API 24 compatible, API 26
SDK). Windows and Linux differ only in install paths.

### 1.1 A Huawei developer account

You need a Huawei ID, and it needs to be a *developer* account — the signing service refuses
to issue a profile otherwise.

1. Register or sign in at <https://developer.huawei.com>.
2. Complete **identity verification**. For an individual this is usually a phone number
   plus, in mainland China, real-name verification with an ID card; overseas accounts
   typically need contact details and sometimes payment/tax information.
3. Accept the HarmonyOS developer agreement. This is what actually unlocks app signing in
   DevEco Studio — without it, the "Automatically generate signature" step in 1.4 fails
   with a permission error that does not say so.
4. Optional: create an app record in **AppGallery Connect** ("My projects → Add project")
   with the bundle name you intend to use. Not needed for debug builds; required for
   release signing, internal testing, or a store listing.

Free. No paid tier is required for personal debugging.

### 1.2 Install DevEco Studio and the SDK

1. Download DevEco Studio 6.x from <https://developer.huawei.com/consumer/en/deveco-studio/>
   (the Chinese site has the same IDE behind a locale switch).
2. Install it. Default paths:
   - macOS: `/Applications/DevEco-Studio.app/Contents`
   - Windows: `C:\Program Files\Huawei\DevEco Studio`
3. On first launch, let the **SDK Manager** download a HarmonyOS SDK. This project targets
   API 26 (`compileSdkVersion: 26.0.0`) and is compatible with `6.1.1(24)`. Older SDKs do
   not have `vpnExtension` in the form used here.
4. Two bundled tools are used constantly:

   ```sh
   HDC=/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc
   NK=/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/native   # NDK
   ```

   Put `hdc` on your `PATH`; the NDK is only needed to build the Rust core.

5. For the native half you also need Rust and the OHOS target:

   ```sh
   rustup target add aarch64-unknown-linux-ohos
   ```

### 1.3 Prepare the device

1. **Enable developer mode.** Settings → About device → tap *Software version* / *Build
   number* seven times. On some builds the entry is under *About phone → Version info*.
2. Settings → System & updates → **Developer options** → enable **USB debugging** (and
   switch the USB mode to file transfer if prompted).
3. Plug the tablet in and accept the debugging prompt on the device:

   ```sh
   hdc list targets          # must print your device serial
   hdc shell bm get --udid   # the UDID your signing profile will be bound to
   ```

If `hdc list targets` stays empty: try another cable (data, not charge-only), revoke and
re-authorise USB debugging, and restart the host side with `hdc kill && hdc start`.

### 1.4 Auto-signing with your device (the step that bites)

A debug signing profile is **bound to specific device UDIDs**. A HAP signed for your tablet
will not install on someone else's, and the installer only reports "signature verification
failed".

1. Open the project in DevEco Studio (`File → Open…`, pick the `app/` directory).
2. Sign in to DevEco with the Huawei ID from 1.1 (`File → Settings → Huawei Account`).
3. `File → Project Structure… → Project → Signing Configs`.
4. Tick **Automatically generate signature**, with the device connected. DevEco reads the
   UDID over `hdc`, requests a debug certificate and profile from the signing service, and
   writes them to `~/.ohos/config/`:
   - `*.p12` — the key store (contains the private key)
   - `*.cer` — the certificate
   - `*.p7b` — the provisioning profile, with your UDID inside
5. `build-profile.json5` then references those files. **That file is git-ignored here**,
   because it holds the store path and the encrypted passwords. The repository ships
   `app/build-profile.example.json5`; copy it and let DevEco fill in the real material:

   ```sh
   cp app/build-profile.example.json5 app/build-profile.json5
   ```

6. To add a second device (a friend's tablet): the profile must list its UDID too. Either
   re-generate the signature with that device connected, or edit the profile in AppGallery
   Connect and add the UDID there.

The bundle identifier is deliberately left at `com.maxime.muharmony`. It is what the
installed debug profile is bound to: changing it would mean a new profile, a new signature
and a second install alongside the old app, while the user-visible name is the label
(`$string:app_name`, `Yanshu`). Treat the bundle id as frozen.

### 1.5 Build, install, run

```sh
# native core: Rust cdylib + the C NAPI shim, for aarch64 OHOS
cd app
CARGO_HOME="$HOME/.cargo" ./scripts/build-native.sh

# the HAP
NODE_HOME=/Applications/DevEco-Studio.app/Contents/tools/node
export PATH="$NODE_HOME/bin:/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin:$PATH"
export DEVECO_SDK_HOME=/Applications/DevEco-Studio.app/Contents/sdk
export TMPDIR="$PWD/../tmp"
hvigorw assembleHap --mode module -p product=default -p module=entry@default --no-daemon

# install and launch
hdc install -r entry/build/default/outputs/default/entry-default-signed.hap
hdc shell aa start -b com.maxime.muharmony -a EntryAbility
```

`scripts/build-native.sh` derives `OHOS_NDK_HOME` from the NDK path and needs a `cmake` on
`PATH` — DevEco bundles one and the script prepends it. The first native build compiles
`aws-lc-sys` and takes several minutes; later builds are seconds.

Convenience scripts:

| Script | Purpose |
|---|---|
| `app/scripts/build-native.sh` | cross-compile the Rust core and link the NAPI shim into `entry/libs/arm64-v8a/` |
| `app/scripts/shot.sh [name]` | screenshot the device into `tmp/` |
| `app/scripts/push-hap.sh` | copy the signed HAP into the device's `Download`, `Documents` and storage root |

### 1.6 Sharing the app

- **Debug HAP:** installs only on devices whose UDID is in the profile. To hand it to a
  friend, either have them build it with their own DevEco auto-signing (easiest), or add
  their UDID to your profile.
- **Release / internal testing:** requires an AppGallery Connect app record, a release
  certificate and profile, and review. A VPN client needs a licensed VPN service to be
  listed in mainland China, so a personal client should be distributed overseas only, if at
  all.
- On-device sideloading exists (open a `.hap` from Files), but it still checks the profile,
  so it does not bypass the UDID restriction.

---

## Part 2 — How the app works

### 2.1 Process model

HarmonyOS does not let a normal app open a tunnel socket. A VPN is an **extension ability**
in its own process, and the UI only talks to it through the system VPN service:

```
EntryAbility (UI process, ArkTS)
   │  startVpnExtensionAbility(Want{ ipv6, ipVersion, killSwitch, target, relayCandidates, … })
   ▼
YanshuVpnAbility (separate process, ArkTS + Rust)
   │  vpnExtension.createVpnConnection(context).create(VpnConfig)
   │     → tun fd, routes, DNS, MTU
   │  connection.protect(udpFd)            ← the engine's socket must bypass its own tunnel
   │  native.tunnelStart(fd, …, endpoint, ssEndpoint)
   ▼
libyanshu_core.so (Rust: tun + gotatun + transports + API client)
   │  UDP datagrams ⇄ relay
   ▼
relay (WireGuard server)
```

Two consequences shape everything:

- **The UI cannot see the tun fd.** State travels back as a common event
  (`VPN_STATE_EVENT`, one JSON payload per second).
- **The two processes do not share memory.** Both read preferences and files from the app
  sandbox; anything the extension needs is passed in the `Want` or read from disk.

### 2.2 The connection lifecycle

1. The UI calls `startVpnExtensionAbility` with a `Want` carrying the tunnel IPv4 address,
   the account's IPv6 address, the **device IP version** (`ipv4` / `ipv6` / `auto`), the
   kill-switch flag, the selected target, the candidate relays (hostname, IPv4, IPv6,
   public key, Shadowsocks extra addresses), the expected device key and the diagnostics
   flag.
2. The extension reads the device key **without creating one**, compares it with the key the
   account registered (`expectKey`), and refuses to proceed on a mismatch.
3. It builds a `VpnConfig`: tunnel address `/32`, default routes `0.0.0.0/0` and — always —
   `::/0` (the IPv6 address is claimed even in IPv4 mode, so the excluded family is routed
   *into* the tunnel and can be dropped there), DNS `10.64.0.1`, MTU 1420,
   `isIPv6Accepted`, and `isBlocking` whenever a family is excluded or the kill switch is
   on.
4. The native core is told which families to forward (`setIpVersion`, bit 1 IPv4, bit 2
   IPv6). The peer's allowed IPs only include those families, so the other one dies inside
   the tunnel instead of leaking onto the carrier.
5. `create()` returns the tun fd. The engine's UDP socket is created, its fd is passed to
   `protect()`, and both are handed to Rust.
6. Rust builds a `gotatun` device on that fd with a transport factory (plain UDP or
   Shadowsocks) and calls `force_handshake`: 5 s per attempt, a 3 minute budget, and the
   ladder in 2.4 deciding what to try next.
7. A completed handshake flips the phase to `connected`; the UI starts the continuous
   background task and publishes the status notification.
8. On disconnect, failure or a watchdog timeout, the extension destroys the connection —
   releasing the system VPN slot and its notification — and the UI clears its state.

### 2.3 The native core

`app/rust/crates/core` is a `cdylib` with a small C ABI, wrapped by a C NAPI shim
(`app/entry/src/main/cpp/yanshu_napi.c`) so the module needs no `libc++_shared.so`.

| Function | Purpose |
|---|---|
| `mh_init(dir)` | where the key and relay cache live |
| `mh_rotate_key()` / `mh_clear_key()` / `mh_device_key()` | key lifecycle (create, delete, read-only) |
| `mh_open_relay_socket(family)` | the UDP socket the engine will use, IPv4 or IPv6 |
| `mh_set_ip_version(families)` | which families the peer forwards |
| `mh_tunnel_start(fd, mtu, peer, endpoint, port, ss)` | build the WireGuard device and handshake |
| `mh_tunnel_status()` | running / handshake / rx / tx / handshake age / last error |
| `mh_api_*` | login, devices, account, relay list — through the fronted API client |

`tunnel.rs` owns the gotatun device, `obfs.rs` the transports, `api.rs` the Mullvad HTTP
client.

### 2.4 Transports, families and the ladder

Mullvad relays are reachable over plain WireGuard — unless the network blackholes the
relay's address, which is common on filtered networks. The client therefore walks a ladder:

```
direct-v6  →  shadowsocks-v4  →  direct-v4  →  shadowsocks-v6
```

- **direct** dials the relay's `ipv6_addr_in` or `ipv4_addr_in` on a port from the published
  ranges. The order is 51820 first (fail fast if it is blocked), then 53, then 123, then a
  random port from 4000–33433, 33565–51819 or 52001–60000.
- **shadowsocks** dials the relay's dedicated `shadowsocks_extra_addr_in` address (ports
  51900–51949, `aes-256-gcm`, password `mullvad`) and wraps each WireGuard datagram, with the
  inner destination `127.0.0.1:51820`.
- The ladder is *relay-major*: every candidate relay is tried on one transport before moving
  to the next.

Two different "families" are in play, and conflating them is a bug:

- the **outer family** is how the client reaches the relay (the ladder's `-v4` / `-v6`
  suffix), and
- the **inner family** is what the tunnel forwards — the *Device IP version* setting.

IPv6 transports go first because they are the path most likely to survive a filtered
network, but that says nothing about what the tunnel carries: the default is **IPv4-only
device traffic**. The same ladder restricted to one protocol is what the *Protocol
preference* setting selects (`WireGuard only`, `Obfuscated only`, or `Automatic`).

A dropped tunnel retries the *same* relay twice, then a different one, then gives up with a
notification.

### 2.5 The API client

`api.mullvad.net` is DNS-poisoned on the networks this was developed on, so `api.rs` speaks
**domain fronting**: TLS to CDN77 with `SNI=www.phpmyadmin.net`, Mullvad's
`domain-fronting` multiplexing protocol, then a second TLS connection to the API inside it.

The direct (unfronted) path is **off by default**, because it is the leaky one: it resolves
`api.mullvad.net` and sends that name as TLS SNI, which is exactly what a filtering network
watches for. The **Direct connection** setting turns it on for networks that do not poison
the name; when it is on, a 4 s timeout guards it and one failure skips it for ten minutes,
so a black-holed address does not cost every call.

The relay list is fetched signed (`/trl/v1/…`) and flattened into `relays.json`: hostname,
IPv4, IPv6, public key, country, city, DAITA flag, and the Shadowsocks extra addresses. The
cache is good for 24 h; a missing field forces a refresh.

### 2.6 Secrets

- The WireGuard private key is a `0600` file in the app sandbox, never in preferences.
- **Every sign-in rotates it.** Mullvad does not accept a reused device key: sign-in deletes
  the old key, generates a new one and registers it; sign-out deletes both the device and
  the key.
- The extension **can only read** the key. If it is missing, the connection fails with a
  message rather than minting an unregistered key the relay would silently drop.
- The account token lives in the HUKS-backed Asset Store, not in a plain file.

### 2.7 Surviving the background

HarmonyOS freezes or kills background apps, which kills the VPN with them. Four pieces fix
that:

- **Continuous task** (`backgroundTaskManager.startBackgroundRunning`, `dataTransfer`
  mode). The mode must be declared in `module.json5` under `abilities[].backgroundModes`, or
  the call fails with `9800005`.
- **Status notification** with Disconnect / Reconnect actions. The buttons start
  `EntryAbility` with a `notificationAction` parameter, which the page picks up from
  `AppStorage` — so they work even when the UI was frozen.
- **Rekey before the session expires.** WireGuard drops a session that has not rekeyed for
  about three minutes, which an idle tunnel never does on its own. The stats loop calls
  `force_handshake` once the last handshake passes 100 s, so a tunnel left alone overnight
  is still there in the morning.
- **Two watchdogs, different jobs.** The extension declares the tunnel dead after 90 s with
  no traffic at all or 240 s without a key exchange, then rebuilds it on the next relay.
  The UI declares "Connection lost" after five seconds without a broadcast — but only while
  the page is in the foreground: HarmonyOS suspends broadcasts for a backgrounded page, and
  reading that silence as a dead tunnel is exactly the bug that made a healthy VPN look
  broken.

---

## Part 3 — Porting a VPN client to HarmonyOS

### 3.1 Where the port followed upstream

The structure deliberately mirrors `mullvad/mullvadvpn-app`:

| Upstream | Here |
|---|---|
| `talpid-wireguard` (gotatun device, MTU, peer config) | `crates/core/src/tunnel.rs` |
| `tunnel-obfuscation::shadowsocks` (AEAD transport) | `crates/core/src/obfs.rs` |
| `mullvad-api` (domain fronting, token, devices, relay list) | `crates/core/src/api.rs` |
| `SocketBypass` → `VpnService.protect` | `vpnExtension.VpnConnection.protect` |
| `connectivity::Check` (`rx_bytes > 0` = up) | `device.peers()` handshake poll |
| `RETRY_ORDER` transport ladder | `LADDER` in the extension |
| "Connected to <relay>" UI state | `VpnStatePayload.target` |

`ANDROID-PATH-REPORT.md` traces the official Android path line by line — Connect button →
gRPC → daemon → tunnel state machine → VpnService → gotatun — and compares each step with
this client.

### 3.2 What had to be invented

- **The extension bridge**: no daemon, no JNI. A `Want` in, an event stream out.
- **The NAPI shim in C** so the Rust core needs no C++ runtime.
- **Transport selection inside the extension**, because there is no relay-selector crate to
  call.
- **Family sealing**: the inner family is a setting, and the family that is not forwarded is
  routed into the tun (`::/0` is claimed unconditionally) so gotatun drops it instead of the
  carrier seeing it. That is what makes "IPv4 only" a promise rather than a preference.
- **Diagnostics**: one log section per connection attempt, parsed into entries by the UI.

### 3.3 Platform traps that cost real time

| Symptom | Cause | Fix |
|---|---|---|
| `401 Parameter error` from `create()` | the session stores `ipv4` as a CIDR (`10.170.64.72/32`); `LinkAddress` wants address and prefix separately | split on `/` |
| `9800005` from `startBackgroundRunning` | background mode not declared | `backgroundModes: ["dataTransfer"]` in `module.json5` |
| VPN dies silently in the background | no continuous task | continuous task + notification + watchdog |
| "No device key on this tablet" after re-login | an in-flight login completed *after* sign-out and registered a key whose file was already deleted | auth generation counter; read-only key in the extension |
| Handshake packets leave, relay never answers | relay key not registered (row above), or the network blackholes the relay address | key check, then the IPv6 / obfuscation ladder |
| `ifconfig` shows no IPv6 | HarmonyOS's `ifconfig` does not print `inet6` at all — not even for `lo` | test with `ping6`, and dial `ipv6_addr_in` |
| List content vertically centred in `Scroll` | `Scroll` defaults to `Alignment.Center` for a child smaller than the viewport | `.align(Alignment.TopStart)` |
| `sys.symbol.square_on_square` not found | symbol names differ from the Android/iOS sets | enumerate the SDK's symbol table, use e.g. `doc_text_on_doc_text` |
| A healthy tunnel reported as "Connection lost" after backgrounding | the UI watchdog read suspended broadcasts as silence | track `onPageShow` / `onPageHide`, and give the next publish five seconds after resume |

### 3.4 Networking findings worth knowing

- **The outer path and the inner family are separate decisions.** A network can blackhole
  Mullvad's IPv4 addresses while its IPv6 prefixes stay reachable — which is why the dial
  ladder starts with IPv6 — while the tablet's own traffic still defaults to IPv4-only,
  because that is what most networks and most users need. The *Device IP version* setting
  changes what the tunnel carries; it does not change how the client reaches the relay.
- **Obfuscation is not optional everywhere.** On the same network, Shadowsocks to a relay's
  dedicated address worked while every plain WireGuard port failed.
- **Android-in-a-box containers bypass host VPNs.** EasyAbroad / DroidTong run their own
  network stack (`ancowlan0`, `192.168.124.0/24`) and re-originate sockets with marks that
  opt out of VPN routing; verified with `ifconfig.me` returning the host's own address while
  the tunnel was up and moving traffic. A VPN inside the Android environment (the Mullvad
  APK in DroidTong) covers it; a host-level VPN cannot.
- **Relay lists change.** Addresses and prefixes move; the client refetches on a 24 h cache
  and refreshes when a new field is missing.

---

## Part 4 — Repository

```
app/                         DevEco project
  entry/src/main/ets/        ArkTS: UI, VPN extension, settings, diagnostics
  entry/src/main/cpp/        C NAPI shim (yanshu_napi.c) + typings
  entry/libs/arm64-v8a/      built native libraries (git-ignored)
  rust/crates/core/          Rust: tunnel, transports, API client (crate yanshu-core)
  scripts/                   build-native, screenshot, push-HAP
PORT-PLAN.md                 feasibility study, milestones, roadmap, UI backlog
ANDROID-PATH-REPORT.md       the official client's connect path, line by line
```

**Not implemented, deliberately:** DAITA, multihop, LWO, QUIC/MASQUE, udp2tcp,
per-application tunnelling, DNS content blocking, custom DNS. Each is described in
`PORT-PLAN.md` §7 with what it would take.

**Building** is in [1.5](#15-build-install-run).

**Contributing:** the code follows upstream's shape where it can, so a change that exists in
`talpid-*` should look like that change here. Nothing is merged without running on a device
— an ArkTS compile says very little about whether a VPN works.

## Licence

GPL-3.0-or-later, as is the client this is derived from. See [`LICENSE`](LICENSE). The
domain-fronting strategy, the transport design and much of the WireGuard configuration come
from `mullvad/mullvadvpn-app` and remain under their authors' copyright.
