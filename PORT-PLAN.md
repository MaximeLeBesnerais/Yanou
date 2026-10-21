# Mullvad on HarmonyOS: feasibility and port plan

Checked against the actual sources: `mullvadvpn-app@main` (sparse clone in `source/`) and the
HarmonyOS SDK installed here (`DevEco-Studio.app/Contents/sdk/default`, API 26 / HarmonyOS 26.0.0).

> **Planning rule for this file: no durations, no dates.** Milestones are ordered by dependency and
> closed by an exit criterion that can be observed on the device or in the build.

## Verdict

The port is feasible, and the protocol layer is smaller than it appears because the ecosystem
already moved: the `tun` crate has an OpenHarmony backend that takes a raw fd, `libc`/`nix` know
about `target_env = "ohos"`, and `aws-lc-sys` ships an explicit OpenHarmony build path
(`OHOS_NDK_HOME` → NDK's `ohos.toolchain.cmake`). Mullvad's WireGuard is `gotatun`, which is
pure Rust apart from the AEAD provider, so it cross-compiles once cmake is on PATH.

What is not small is everything around it: 89k lines of Kotlin/Compose that cannot exist on
HarmonyOS, a Rust core whose Android branches are the ones that matter and whose Linux branches
are the ones that compile, and a platform model that tears the VPN down when the UI process dies.

The VPN layer is the well-supported part. The work is in the platform lifecycle, and in writing a
new client rather than porting one.

## 1. The partial clone

The clone is small. Measured on this machine:

```
git clone --depth 1 --filter=blob:none --sparse https://github.com/mullvad/mullvadvpn-app.git
cd mullvadvpn-app && git sparse-checkout set android
# .git 23M, android/ 33M
```

Add the crates needed for the analysis:

```
git sparse-checkout add talpid-core talpid-tunnel talpid-wireguard talpid-routing \
                        talpid-types mullvad-daemon mullvad-api mullvad-jni dist-assets
# whole thing: 26M .git, 67M working tree
```

`android/` alone is not a buildable unit, and it is not the part being ported:

- `android/settings.gradle.kts` pulls in 91 Gradle modules, most of them under `android/lib/*`.
- `android/app/build.gradle.kts:346` sets `module = repoRootPath`, `libname = "mullvad-jni"`;
  the tunnel comes from the Rust workspace at the repo root, not from `android/`.
- `:165` and `:222` pull `dist-assets/relays/` in as app assets.

Building the Android app requires the whole repository, the Android SDK/NDK, JDK 17 and the
Rust Android targets, about 10 GB, none of which helps with HarmonyOS. A read-only clone is enough
for the analysis.

## 2. What HarmonyOS provides

`@ohos.net.vpnExtension` (API 11+, present in this SDK at
`openharmony/ets/api/@ohos.net.vpnExtension.d.ts`) is the `VpnService` equivalent, and the
mapping is almost one-to-one:

| Android (`TalpidVpnService`)            | HarmonyOS (`vpnExtension`)                     |
| --------------------------------------- | ---------------------------------------------- |
| `VpnService.Builder.setMtu`             | `VpnConfig.mtu`                                 |
| `addAddress`                            | `VpnConfig.addresses` (`LinkAddress[]`)         |
| `addRoute`                              | `VpnConfig.routes` (`RouteInfo[]`, iface `vpn-tun`) |
| `addDnsServer`                          | `VpnConfig.dnsAddresses`                        |
| `addDisallowedApplication`              | `VpnConfig.blockedApplications`                 |
| `addAllowedApplication`                 | `VpnConfig.trustedApplications`                 |
| `setBlocking` (kill switch)             | `VpnConfig.isBlocking`                          |
| `protect(socket)`                       | `VpnConnection.protect(socketFd)`               |
| `Builder.establish()` → tun fd          | `VpnConnection.create(config)` → tun fd         |
| `VpnService` lifecycle                  | `VpnExtensionAbility` (`"type": "vpn"`)         |

What this buys: `protect()` is the one thing that cannot be emulated, and it exists. The tun fd is
a real fd that can be handed to Rust. Routes, DNS, MTU and per-app split tunnelling are all
system-side, so `talpid-routing`, `talpid-dns` and `talpid-core::firewall` do not need real
implementations; same situation as Android, where they are stubs.

Constraints, from the OpenHarmony guide (`en/application-dev/network/net-vpnExtension.md`):

- Only `ohos.permission.INTERNET` must be declared. There is **no** special VPN permission and no
  Huawei approval to call the API; the first `startVpnExtensionAbility` shows a system consent
  dialog.
- One active VPN system-wide. Starting a second one is rejected by the system.
- The VPN service runs in **its own process** ("the VPN service process is destroyed").
- The system tears the VPN down when the process that called `startVpnExtensionAbility` exits.

That last pair dictates the architecture (below) and is the item most often designed around
instead of for.

## 3. What has to be written

### 3.1 Rust core

The trap: for `aarch64-unknown-linux-ohos`, rustc reports

```
target_os   = "linux"      <- not "ohos"
target_env  = "ohos"
target_family = "unix"
```

Mullvad branches on `target_os = "android"` in **350 places** across `talpid-core`,
`talpid-routing`, `talpid-types`, `talpid-tunnel` and `mullvad-daemon` (Android: no netlink, no
firewall, routes from the OS). On `ohos` those branches are all false, so the Linux code compiles:
`rtnetlink`, D-Bus/NetworkManager, `/etc/resolv.conf`, `ip route`. It will build and then do the
wrong thing at runtime, or fail on a device that has no NetworkManager.

So the port's first real decision is a cfg policy. The workable one:

- `#[cfg(any(target_os = "android", target_env = "ohos"))]` for "the OS owns routes/DNS/firewall"
  (`talpid-routing/src/unix/android.rs` is already that stub; reuse it).
- Keep `#[cfg(target_os = "android")]` for the genuinely JNI-shaped parts that get replaced anyway.

Do not blind-sed all 350 sites; some are JNI/Java-class specific and need an ohos sibling, not a
reuse.

Already solved upstream, use as-is:

- `tun` 0.8.14 has `src/platform/ohos/` and builds the device from `Configuration.raw_fd`
  (`platform/mod.rs` gates the Linux impl out with `not(target_env = "ohos")`). This is exactly
  the Android shape: fd comes from outside.
- `libc` treats `target_env = "ohos"` as musl-like; `nix` guards musl/ohos together.
- `aws-lc-sys` has `configure_open_harmony()`, reads `OHOS_NDK_HOME` or `OHOS_SDK_NATIVE`, maps
  `aarch64-unknown-linux-ohos` → `OHOS_ARCH=arm64-v8a`. So `rustls`, `tokio-rustls` and
  `mullvad-api` can build. **`ring` has no ohos path**, so build `gotatun` with `aws-lc-rs`
  (its default), never the `ring` feature. Needs `cmake` installed; the NDK is already here.

Then:

- `talpid-tunnel/src/tun_provider/android/` (JNI `TalpidVpnService.prepareTun`/`bypass`) needs an
  `ohos/` sibling: a `ThreadsafeFunction` into ArkTS to call `vpnExtension.create()`, plus the
  `protect` callback for the WireGuard UDP socket, which the daemon gets from the same shim.
  `mullvad-jni` is only 510 lines; a `mullvad-napi` of similar size is the whole native boundary.
- Skip gRPC. On Android the Kotlin UI talks to the in-process daemon over gRPC-on-UDS; on
  HarmonyOS the UI and the VPN are different processes, so some IPC is required, but it does not
  have to be gRPC. Either keep `mullvad-management-interface` over a unix socket and write a small
  NAPI client (no ArkTS protobuf work), or expose the `DaemonCommandChannel` directly as NAPI and
  let the UI-process shim forward over a local socket.
- `mullvad-paths` needs the app's `filesDir` injected at init (Android does the same through
  `AndroidContext`); the rest of the daemon config is portable.

### 3.2 ArkTS shell: a rewrite

`android/` is 1187 Kotlin files / ~89k lines, Compose UI, Hilt, Play billing, Android Keystore,
`ConnectivityManager`. None of it exists on HarmonyOS. The client has to speak the same daemon
API: account login (account number → device + WireGuard key), relay list, location
picker, connect/disconnect, settings (DNS, kill switch, split tunnel, obfuscation, multihop),
status. That is where most of the code lives, and it is ordinary app work.

Equivalent platform pieces:

| Android                            | HarmonyOS                                              |
| ---------------------------------- | ------------------------------------------------------ |
| Android Keystore                   | HUKS (`@ohos.security.huks`)                            |
| `ConnectivityManager` callbacks     | `@ohos.net.connection`                                  |
| DataStore / Room                   | `@ohos.data.preferences` / relational store             |
| Foreground service + notification   | continuous task (`backgroundTaskManager`) + `statusBarManager` |
| `PackageManager` (app list)         | **not available**, see gaps                             |

### 3.3 Gaps no amount of code fixes

- **Always-on / start at boot.** No public API for a third-party VPN. The extension is started by
  the app; if the app process dies, the system drops the VPN. It is held with a continuous
  background task, which is why the one existing HarmonyOS VPN demo
  ([etohos](https://github.com/collaborative-creation/etohos), EasyTier) holds a *location*
  subscription to keep the process alive. That is a review-liability hack, not a design.
- **Split tunnelling app picker.** `VpnConfig.blockedApplications` takes bundle names, but
  enumerating installed apps needs `ohos.permission.GET_BUNDLE_INFO_PRIVILEGED` (system_basic) or
  `ENTERPRISE_GET_INSTALLED_BUNDLE_LIST` (enterprise). A normal app can resolve a bundle name it
  already knows, not list them. Android's picker cannot be reproduced as-is.
- **Distribution.** A general-purpose VPN client is a licensing problem in mainland China, not an
  engineering one; assume sideload with a developer certificate. Shipping on AppGallery
  (overseas) means a VPN qualification review. Also: the app is GPL-3.0-or-later, so a distributed
  port must publish its source.
- **No control-center tile, no unremovable custom notification.** See 3.4; both are platform
  limitations, not omissions in the plan.
- DAITA, obfuscation (shadowsocks/udp-over-tcp), multihop and custom DNS live in Rust and come for
  free once the core builds; they are not gaps, only untested.
- **Android-in-a-box containers (EasyAbroad, DroidTong) bypass the host VPN.** Verified on device:
  with the tunnel up and moving traffic, Brave inside EasyAbroad reports the tablet's own Chinese
  IPv6 (`2403:ac00:b201:…`) on `ifconfig.me`, not a Mullvad exit. The container runs its own
  network stack (`ancowlan0`, 192.168.124.0/24) and re-originates sockets with marks that opt out
  of VPN routing, so nothing a host-level VPN does can capture it. YouTube inside those containers
  therefore needs a VPN *inside* the Android environment (the Mullvad APK in DroidTong does work
  there). Out of scope for this client; recorded so it is not re-investigated.

### 3.4 Notification and "tile"

Both asked-for surfaces exist, but neither maps to the Android component.

| Want                                   | HarmonyOS                                                        | Verdict |
| -------------------------------------- | ---------------------------------------------------------------- | ------- |
| Notification with Connect / Disconnect | `NotificationRequest.actionButtons` + `WantAgent`                  | yes, but dismissable |
| Non-dismissable notification           | `isOngoing` / `isUnremovable` are `Not supported currently`        | no |
| Unremovable while the VPN runs         | continuous-task notification (system template)                     | yes, no custom buttons |
| Control-center tile                    | no API in the API 26 SDK                                           | no |
| Home-screen toggle                     | `form` extension ability (service widget), 1x1 / 2x1               | yes |
| Long-press icon action                 | `shortcuts` + `@ohos.bundle.shortcutManager` (API 20+)             | yes |

**The permanent notification.** `isOngoing` and `isUnremovable` carry "Not supported currently" in
`notification/notificationRequest.d.ts:130-145`, so a normal app cannot publish a notification the
user is unable to swipe away. The only unremovable notification is the continuous task's, and
`ContinuousTaskRequest` (`@ohos.resourceschedule.backgroundTaskManager.d.ts:70`) exposes only
`backgroundTaskModes`, `backgroundTaskSubmodes`, `wantAgent`, `combinedTaskNotification`,
`continuousTaskId`, and no title, text or buttons. The system draws it; `wantAgent` decides where
a tap lands. It also must be requested **from a UIAbility** ("Continuous tasks can be requested
only by the UIAbility in the stage model"), which fits the rule that the VPN dies when the process
that called `startVpnExtensionAbility` exits: the UI process holds the task.

So "permanent notification" is really two: the system's continuous-task card (unremovable, no
controls, tap → app) and a normal notification published and re-published on every state change,
carrying the buttons. The continuous task itself needs a `backgroundModes` claim in
`module.json5`, and the enum has no `vpn`; `taskKeeping` and `dataTransfer` are the plausible
ones, both reviewed by Huawei, and a rejected mode surfaces as
`9800005 - Continuous task verification failed` rather than as a compile error. Note that
`requestAuthFromUser` / `specialScenarioProcessing` exists but puts a consent dialog in front of
the user, which is the wrong trade for a VPN toggle.

```ts
const request: notificationManager.NotificationRequest = {
  id: VPN_NOTIFICATION_ID,
  notificationSlotType: notificationManager.SlotType.SERVICE_INFORMATION,
  content: { /* normal content with title/text */ },
  actionButtons: [
    { title: 'Connect',    wantAgent: toggleAgent },
    { title: 'Disconnect', wantAgent: toggleAgent },
  ],
  tapDismissed: false, // keep it after a button tap; the button's effect re-publishes it
};
```

`NotificationActionButton.wantAgent` (`notification/notificationActionButton.d.ts`) is executed by
the system, and `WantAgent` supports `OperationType.SEND_COMMON_EVENT`, so a button does not have
to raise the UI; it publishes an in-app common event that the VPN process subscribes to. That is
the cheapest control path, and it is exactly what the widget needs too.

**The tile.** There is no `TileService` equivalent: the API 26 SDK contains no control-center or
quick-setting API at all (`ets/api` has no `controlCenter` / `quickSetting` / tile symbol). The
same question keeps coming up on Huawei's developer forum
([example](https://developer.huawei.com/consumer/cn/forum/topic/0201202923434091911)) with no API
to point at, so treat the control center as closed to third-party apps. The two things that do
exist:

- **Service widget**: a `form` extension ability (`FormExtensionAbility` plus a form config
  profile referenced from `module.json5`), 1x1 or 2x1, with buttons that call
  `postCardAction({ action: 'message', params })`; the payload arrives in the widget's
  `onFormEvent`, which then publishes the same common event. This is the closest thing to a tile
  and it is the practical choice.
- **Icon shortcut**: `shortcuts` in `module.json5` plus `shortcutManager` (API 20+): long-press
  the app icon → "Connect" / "Disconnect". Entries are `want`s, so they open an ability; keep the
  trampoline page that reads the parameter thin and finish it immediately.

Both are separate processes from the VPN service, so all three surfaces converge on one in-app
event bus rather than on direct calls:

```
notification button ─┐
                     ├─ common event "mullvad.toggle" ─→ VpnExtAbility process (Rust daemon)
home-screen widget ──┘                                        │
                                                              └─ state change → republish notification

widget state ← formProvider.updateForm(formId, …) ← formId registered at onAddForm
```

Two things this forces into M1 rather than later: the daemon must expose state changes as events
(not just request/response), and the app needs a stable formId registry, because
`formProvider.updateForm` is the only way to keep the tile showing the real state.

## 4. Order of work

There are no durations: the order is by dependency, and each milestone closes when a condition
holds, not when a date arrives.

**M0: the pipe exists on the device.**
`VpnExtensionAbility` + `vpnExtension.create` → fd → `tun` crate → `gotatun` → one ping through a
real relay.
*Closes when:* a handshake completes, traffic leaves through the relay while the UI process is
alive, and the tunnel tears down cleanly.

**Half of M0 is verified on the tablet (2026-10-18, MatePad TGR-W00, API 24).** With the scaffold
in `app/`: the consent dialog appears, `VpnConnection.create` returns an fd, the Rust `tun` crate's
`ohos` backend reads it, the 0.0.0.0/0 route captures packets, and `VpnConnection.protect(26)`
succeeds on the relay socket. Still open: the actual WireGuard handshake. This build counts and
drops what it captures, so nothing leaves the device yet.

This is the milestone that decides whether the rest is viable: if `aws-lc` and the fd handoff
work, everything after it is ordinary work; if not, the design changes before any UI exists.

**M1: the Rust core builds and runs headless for `aarch64-unknown-linux-ohos`.**
cfg policy for `target_env = "ohos"`, a tun provider replacing the JNI one, `mullvad-paths`
injected from the app sandbox, NAPI boundary, daemon in-process.
*Closes when:* connect / disconnect / status work from a test harness with no ArkTS UI.

**M2: account and relay list.**
`mullvad-api` as-is if aws-lc cooperates; otherwise device creation and relay fetch move to the
ArkTS HTTP stack and only the tunnel stays in Rust. Plus the minimal UI: login, location, connect.
*Closes when:* a fresh account number logs in, a relay is selected from the live list, and the
connection is made with nothing hardcoded.

**M3: lifecycle and surfaces.**
Continuous task from the UIAbility, the state-carrying notification with Connect/Disconnect
buttons, the home-screen widget, icon shortcuts, reconnect on network change, kill switch, split
tunnel, IPv6, MTU edge cases.
*Closes when:* the tunnel survives a Wi-Fi ↔ cellular switch, the UI process being backgrounded,
and a reconnection attempt after the system drops the extension; the notification reflects the
daemon's real state within one state change; a button and the widget both toggle the tunnel
without raising the UI; and the kill switch actually blocks when it should.

**M4: parity.**
DNS blocking, multihop, obfuscation, DAITA, problem reports, translations.
*Closes when:* each feature is either verified on device or explicitly descoped in this file.

M0–M3 is the "usable client" line. M4 is open-ended by nature and gates nothing.

## 5. Alternative: a per-device WireGuard config

Mullvad's account page generates per-device WireGuard configs. If a WireGuard client is available
for HarmonyOS, importing one replaces the whole port with a config file. Check that before
starting M1.

## 6. Open questions before M1

1. Does the VPN extension process survive a long-lived UI process with a continuous task on the
   MatePad (TGR-W00, HarmonyOS 6.1 / API 24)? That is an on-device experiment, not a doc.
2. Are unix domain sockets usable between the UI process and the VPN extension process in the app
   sandbox? If not, the IPC design changes (shared data group, or a socketpair handed over at
   start).
3. Does `VpnConnection.create` accept `10.64.0.1` as DNS plus `0.0.0.0/0` routed into the tunnel on
   this device build (Mullvad's DNS blocking depends on it)?
4. Do same-app common events published by a notification button's `WantAgent` reach a dynamic
   subscriber in the VPN extension process while the app is backgrounded? If they do not, the
   buttons have to target an ability instead, and the "no UI flash" requirement fails for M3.
5. Is the `form` extension sandboxed away from the app's data dir the way `inputMethod` is? If it
   is, the formId registry cannot be a file shared with the VPN process, and `updateForm` needs the
   formId delivered another way.
6. Does `combinedTaskNotification: true` merge the continuous-task card and the custom
   Connect/Disconnect notification into one card, or only group them? Two VPN notifications is a
   product decision that depends on this answer.

## 7. Work units

The features are grouped into **work units** rather than listed one per feature. A unit is a
set of changes one person can carry without editing files another unit is editing, so two
units can run at the same time. Each unit has an exit criterion that can be checked on the
device.

Sizes are relative (S, M, L, XL), not durations, per the rule at the top of this file.

**Status:** U0–U6 are implemented and merged into `main`; the units were built in parallel
worktrees and integrated one at a time. Device verification is still open — the exit criteria
below marked "on device" have not all been run on the tablet yet. `main` builds, and the Rust
core carries 41 unit tests covering LWO and udp2tcp framing, multihop MTU and settings, and
the DAITA protobuf/gRPC exchange.

| Unit | Contains | Depends on | Parallel with | Size |
|---|---|---|---|---|
| **U0 Contract** | relay fields, transport trait, data-driven ladder | none | U1, U4 | S |
| **U1 DNS** | custom DNS, content blocking | none | U0, U4 | S |
| **U2 LWO** | LWO v1/v2 transport | U0 | U3, U4, U5 | M |
| **U3 udp2tcp** | TCP-framed transport | U0 | U2, U4, U5 | M |
| **U4 Multihop** | two-device chain, exit selection | none | U0, U1, U2, U3, U5 | L |
| **U5 QUIC** | MASQUE transport | U0 | U2, U3, U4 | L |
| **U6 DAITA** | config service, maybenot, netstack | U4 | none | XL |

```
U0 contract ──┬──> U2 LWO ──────┐
              ├──> U3 udp2tcp ──┤   all three in separate files
              └──> U5 QUIC ─────┘

U1 DNS ─────── independent, any time
U4 Multihop ── independent, owns tunnel.rs and the UI
U6 DAITA ───── after U4, shares the peer and ingress model
```

**File ownership**, so parallel units do not collide:

| File | Owner |
|---|---|
| `api.rs`, `MullvadApi.ets` (relay model) | U0, then read-only |
| `obfs.rs` → `transports/` | U0 splits it; U2, U3, U5 own one file each afterwards |
| `VpnExtensionAbility.ets` | U0 (ladder), U1 (DNS), U4 (`Want`) — separate functions, merge last |
| `tunnel.rs` | U4, then U6 |
| `Index.ets` (settings page) | U1 |
| `Index.ets` (main page, server selection) | U4 |
| `VpnSettings.ets` | U1 |

### U0 — Transport contract  (S)

Nothing in it is a feature; it is what lets U2, U3 and U5 be written at the same time.

- **Relay model.** The four fields we keep today (hostname, IPv4, IPv6, public key) grow to
  carry `features.quic` (`addr_in`, `token`, `domain`), `features.lwo`/`lwo_v2` and
  `wireguard.udp2tcp_ports`. Read in `api.rs`, added to `RelayCandidate`, passed to the
  extension in the `Want`.
- **Transport trait.** `obfs.rs` becomes `transports/mod.rs` plus one file per transport, with
  a small trait: create from (relay, socket, settings), report MTU overhead, send, recv.
  Shadowsocks is the worked example.
- **Ladder.** Data-driven: each transport reports whether it applies to this relay and what
  its overhead is, instead of the string array and the branch in `startCandidate()`.

Exit criterion: a stub transport can be added by creating one file and one relay field,
without editing the ladder logic in `VpnExtensionAbility.ets`.

Risk: low. It is a refactor of working code, and the transport trait is already implicit in
what Shadowsocks does.

### U1 — DNS  (S)

Two settings, one unit, no Rust work.

**Custom DNS.** The user supplies resolvers instead of `10.64.0.1`
(`mullvad-daemon/src/dns.rs`, `DnsState::Custom`). They go into
`VpnConfig.dnsAddresses`; public ones are reached through the tunnel by the default route,
private ones should not be, which is the split upstream makes with `is_local_address` and
means adding RFC1918 route exclusions in `setup()`.

**Content blocking.** The resolver *is* the configuration: `100.64.0.0` with a bitmask in the
last octet, ads 1, trackers 2, malware 4, adult 8, gambling 16, social 32. Ads alone gives
`100.64.0.1`; ads and trackers gives `100.64.0.3`.

Exit criterion: `dig` through the tunnel returns the blocked answer for a known ad domain,
and a custom resolver answers when configured.

Risk: none. Verify the resolver answers inside the tunnel before building the UI around it.

### U2 — LWO  (M)

WireGuard packets padded and obfuscated so they do not look like WireGuard, without a TCP
tunnel. Two versions; v2 adds timer parameters on the gotatun peer.

Upstream: `tunnel-obfuscation/src/lwo/mod.rs`, `v2.rs`, and `lwo_version`/`lwo_timer_params` in
`talpid-wireguard/src/gotatun/mod.rs`.

Work: keys derived from both public keys, per-version framing and padding, and
`Peer::dangerously_with_timer_params` for v2. No new dependency.

Exit criterion: a handshake completes through LWO against a relay that advertises `lwo_v2`.

Risk: the framing must match the relay exactly; one device session proves it either way.

### U3 — udp2tcp  (M)

Datagrams length-prefixed into a TCP stream to a port on the relay, for networks that pass TCP
and drop UDP.

Upstream: `tunnel-obfuscation/src/udp2tcp.rs`, the `udp-over-tcp` fork pinned by git revision,
relay field `wireguard.udp2tcp_ports`.

Work: a TCP socket, `protect()` on its descriptor (the call is descriptor-based, so it works
for TCP), the framing from the crate.

Exit criterion: a handshake completes over TCP to a relay that publishes udp2tcp ports.

Risk: the dependency is a git fork; pin and vendor it or the build stops being reproducible.

### U4 — Multihop  (L)

Traffic goes entry relay then exit relay, so no single relay sees both the client and the
destination.

Upstream: `Multihop`, `EntryDevice`, `ExitDevice`, `TunChannelTx`/`TunChannelRx` in
`talpid-wireguard/src/gotatun/mod.rs`; entry and exit selection in `mullvad-relay-selector`.

Work: two gotatun devices. The entry device has the tun on one side and a packet channel on the
other; the exit device reads that channel with the exit relay as its peer. MTU drops by a
second WireGuard header, floored at 1280. The UI needs a separate exit choice, and the current
single `selection` has to become an entry/exit pair.

Exit criterion: traffic exits through the chosen exit relay's country, and a speed test does
not stall on large packets.

Risk: the largest structural change in the native core. MTU mistakes look like a healthy
tunnel that stalls on large packets.

### U5 — QUIC/MASQUE  (L)

WireGuard datagrams carried as MASQUE CONNECT-UDP datagrams inside QUIC to a proxy on the
relay, UDP 443.

Upstream: `tunnel-obfuscation/src/quic.rs`, the `mullvad-masque-proxy` crate, relay field
`features.quic` with `addr_in`, `token`, `domain`. The TLS SNI is the published domain; the
token goes in the CONNECT request.

Work: a QUIC stack plus a MASQUE client. The crate is a workspace member in the upstream
repository and is not published, so either vendor it (GPL-3.0, same as the rest) or write the
CONNECT-UDP client against `quinn`.

Exit criterion: a handshake completes through the proxy on a network that drops plain UDP.

Risk: the second-largest dependency footprint, and it only pays off on networks that allow
QUIC on 443.

### U6 — DAITA  (XL)

Constant packet sizes, decoy traffic and pacing against traffic analysis, driven by machines
handed out by the relay's config service.

Upstream: `talpid-tunnel-config-client` (gRPC to the config service on port 1337 of the ingress
relay), the `maybenot` crate, `talpid-wireguard` applying the settings to the peer. The pinned
gotatun already carries the `daita` feature, so the packet-shaping half needs a flag and
settings, not new code.

Work, in order:

1. A gRPC client and the protobuf definitions from `talpid-tunnel-config-client`.
2. A way to reach the config service before the tunnel exists. Upstream builds a temporary
   gotatun device with a userspace smoltcp stack (`talpid-netstack`) at MTU 576 and opens TCP
   to `10.64.0.1:1337` through it. That stack is the expensive part.
3. Apply the returned PSK and machines to the real device: `Peer::with_daita`, decoy and delay
   fractions, timer parameters.
4. The relay filter, which already exists.

The same negotiation returns the post-quantum PSK, so this unit also delivers the
quantum-resistant session.

Exit criterion: the relay reports DAITA machines for the session and the peer applies them
(visible in the diagnostics log), with traffic still flowing.

Risk: two large dependencies (tonic/prost, a userspace network stack) for a feature whose
effect is invisible when it works, on the protocol most likely to change upstream.

### Out of scope — per-app split tunnelling

`VpnConfig.trustedApplications` and `blockedApplications` accept bundle names, but listing the
installed applications needs `ohos.permission.GET_BUNDLE_INFO_PRIVILEGED` (system_basic) or
`ENTERPRISE_GET_INSTALLED_BUNDLE_LIST` (enterprise). A normal application can resolve a bundle
name it knows; it cannot enumerate them. An application picker cannot exist, and hand-typed
bundle names are not a feature. Recorded so it is not re-investigated.

### Sequencing

**Two or three people, three waves.** Wave 1: U0, U1, U4 — U1 is pure UI, U0 and U4 touch
disjoint files. Wave 2: U2, U3, U5 — all three start the moment U0 lands, each in its own file.
Wave 3: U6 alone, after U4, because both change the peer and ingress model.

**One person.** U1, U0, U2, U3, U5, U4, U6. That order ships something visible in the first
unit, keeps the transport work together, and leaves the two structural units for when the
ladder is comfortable.

## 8. UI backlog

**Next goal after the feature work: a UI/UX pass.** The settings screen has outgrown itself —
DNS moved to its own screen, but protocol preference, kill switch, IP version, direct
connection, diagnostics, DAITA and multihop still stack into one long scroll. The main screen
also scrolls, which it should not for a four-element page. Nothing has been checked at phone
width: the layout was built on a 2800 px tablet. The pass is: one sub-screen per concern
(Network, DNS, Privacy, Relay), a main screen that fits without scrolling at tablet height,
and a small-window run (DevEco's small-screen preview or a phone-sized emulator window) to
check every screen at 360–420 dp before calling it done.


Ordered by what the user feels first, not by what is easiest. Each item is sized in
"one visible increment" terms.

### 8.1 Connection confidence (highest value)
- **Connection details sheet**: tapping the hero card opens transport (direct/Shadowsocks),
  relay hostname, IPv6/IPv4, handshake latency, uptime, rx/tx, and a link to that attempt's
  diagnostics entry. Everything needed already exists in `VpnStatePayload`; only the UI is missing.
- **In-progress detail**: while connecting, show `attempt 3 · sg-sin-wg-001 · ipv6 direct`
  instead of a static "Trying …".
- **Persistent "connection lost" banner** in the header (not just inside the card), with the
  retry countdown while the ladder works.
- **Latency-aware Automatic**: measure handshake time per candidate (it is already logged) and
  prefer the fastest country; surface it as "automatic · 120 ms".

### 8.2 Server browser
- Replace the inline-expanding country rows with a real drill-down: country → city → relay,
  with the current relay pinned at the top and marked.
- Filter chips: DAITA, owned, recent, and (later) providers.
- Favourites and a user-ordered custom list, stored like `recents`.
- Search across country/city/hostname with result grouping, and keep the query when navigating
  back.
- Usage map shown per country as a small sparkline rather than "used 8×".

### 8.3 Settings that do what they say
- **Kill switch**: sets `isBlocking` while the tunnel is up. Verify on device that blocking holds
  while the tunnel is down, and add route policy if it does not.
- **MTU**: expose it (1280/1360/1420), since container and mobile networks differ.
- **Per-app routing**: exclude chosen bundles from the tunnel, the only way to make
  Android-in-a-box containers usable with this client.
- **DNS content blocking**: the resolver bitmask (ads/trackers/malware/adult/gambling/social)
  needs the backend first; UI after.

### 8.4 Account and devices
- Move "Manage devices" into the Account screen (it is only reachable from the login screen today).
- Expiry warning banner when the account is within 7 days of expiring.
- Show the device key fingerprint and let the user copy it (useful when debugging registration).

### 8.5 Diagnostics
- Filter chips (all / failed / connected), newest first, plus "share this entry".
- Live tail while connected, so a drop is visible without leaving the screen.

### 8.6 Platform polish
- Two-pane layout on wide screens (server list | selected server + connect), instead of a
  single 720 px column on a 2800 px tablet.
- App icon and label pass; accessibility labels on every `SymbolGlyph` button (they are
  unlabelled for screen readers today).
- Empty/loading/error states for every list.
- **About / licences screen**: GPL-3.0 source offer, third-party notices, version and build.
  Required before distributing a binary.
