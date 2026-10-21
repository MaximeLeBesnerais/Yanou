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

## 7. Feature plans

Features the upstream client has and this one does not, with the path to each. They are
ordered by cost, not by value: the DNS pair is UI work, the transports are self-contained
Rust, multihop reworks how devices are chained, and DAITA pulls in a gRPC service and a
userspace network stack.

Sizes are relative (S, M, L, XL), not durations, per the rule at the top of this file.

| Feature | Value | Size | Main risk |
|---|---|---|---|
| Custom DNS | works on every network | S | none |
| DNS content blocking | works on every network | S | none |
| LWO | reaches relays on filtered networks | M | framing must match the relay byte for byte |
| udp2tcp | works where UDP is blocked | M | depends on a fork of `udp-over-tcp` |
| Multihop | harder correlation, exit country | L | rework of the device chain, MTU |
| QUIC/MASQUE | works where UDP is blocked | L | the MASQUE client is not a published crate |
| DAITA | traffic-analysis defence | XL | gRPC config service plus a userspace stack |
| Per-app split tunnelling | privacy | out of scope | requires a system permission |

Shared groundwork, needed by most of the transport items:

- The relay model carries six fields today: hostname, IPv4, IPv6, public key, DAITA flag,
  Shadowsocks addresses. QUIC needs `features.quic` (`addr_in`, `token`, `domain`), udp2tcp
  needs `wireguard.udp2tcp_ports`, LWO needs `features.lwo` and `features.lwo_v2`. They are
  read in `api.rs`, added to `RelayCandidate`, and passed to the extension in the `Want`.
- Every transport carries an MTU overhead. The ladder already accounts for Shadowsocks; each
  new entry has to report its overhead the same way, or the tunnel black-holes large packets.
- The ladder in `VpnExtensionAbility.ets` is an array of strings. Each transport adds an entry
  and a branch in `startCandidate()`.

### 7.1 Custom DNS  (S)

The user supplies one or more resolvers instead of `10.64.0.1`.

Upstream: `mullvad-daemon/src/dns.rs` (`DnsState::Custom`), `talpid-dns`.

Needed here: an address list in settings, validation, and `VpnConfig.dnsAddresses` built from
it in the extension. Public resolvers are reached through the tunnel by the default route;
private ones should not be, which is the same split upstream makes with `is_local_address`,
and it means adding a route exclusion for RFC1918 in `setup()`.

Risk: low. The only subtle part is the split between tunnelled and non-tunnelled resolvers.

### 7.2 DNS content blocking  (S)

Mullvad's resolver blocks ads, trackers, malware, adult content, gambling and social media,
and the selection encoded in the resolver address rather than in a config file.

Upstream: `mullvad-daemon/src/dns.rs`. The address is `100.64.0.0` with a bitmask in the last
octet: ads 1, trackers 2, malware 4, adult 8, gambling 16, social 32. Blocking ads only gives
`100.64.0.1`; ads plus trackers gives `100.64.0.3`.

Needed here: six switches in settings, the mask persisted in `VpnPrefs`, and the computed
address used as the only DNS server. No Rust change.

Risk: none, but verify the resolver answers inside the tunnel before wiring the UI.

### 7.3 LWO  (M)

WireGuard packets are padded and obfuscated so they no longer look like WireGuard, without a
TCP tunnel. Two protocol versions exist; v2 adds timer parameters on the gotatun peer.

Upstream: `tunnel-obfuscation/src/lwo/mod.rs` and `v2.rs`, `talpid-wireguard/src/gotatun/mod.rs`
(`lwo_version`, `lwo_timer_params`), relay flags `features.lwo` and `features.lwo_v2`.

Needed here: a transport in `obfs.rs` beside the Shadowsocks one, keys derived from the client
and server public keys, per-version framing and padding, `Peer::dangerously_with_timer_params`
for v2, relay fields, and a ladder entry between direct and Shadowsocks.

Risk: the framing has to match the relay exactly. It is testable on a device in one session,
and there is no new dependency.

### 7.4 udp2tcp  (M)

WireGuard datagrams are length-prefixed into a TCP stream to a port on the relay, for
networks that pass TCP but drop UDP.

Upstream: `tunnel-obfuscation/src/udp2tcp.rs`, the `udp-over-tcp` crate (a Mullvad fork, pinned
by git revision), relay field `wireguard.udp2tcp_ports`.

Needed here: a TCP socket, `protect()` on its descriptor (the call is descriptor-based, so it
works for TCP the same way it does for the UDP socket), the framing from the crate, a ladder
entry, and the port list in the relay model.

Risk: the dependency is a git fork; it has to be pinned and vendored or the build is not
reproducible. Otherwise the transport is small.

### 7.5 Multihop  (L)

Traffic goes entry relay then exit relay, so no single relay sees both the client address and
the destination.

Upstream: `talpid-wireguard/src/gotatun/mod.rs` (`Multihop`, `EntryDevice`, `ExitDevice`,
`TunChannelTx`/`TunChannelRx`), `mullvad-relay-selector` for the entry and exit choices.

Needed here: two gotatun devices. The entry device has the real tun on one side and a packet
channel on the other; the exit device reads that channel and its peer is the exit relay. The
MTU drops by a second WireGuard header (upstream floors it at 1280). The UI needs a separate
exit selection, and the relay selector has to keep entry and exit distinct, which the current
single `selection` does not model.

Risk: the device chaining is the largest structural change in the native core; MTU mistakes
look like a working tunnel that stalls on large packets.

### 7.6 QUIC/MASQUE  (L)

WireGuard datagrams are carried as MASQUE CONNECT-UDP datagrams inside QUIC to a proxy on the
relay, on UDP 443.

Upstream: `tunnel-obfuscation/src/quic.rs` and the `mullvad-masque-proxy` crate, relay field
`features.quic` with `addr_in`, `token` and `domain`. The TLS SNI is the published domain, the
token goes in the CONNECT request.

Needed here: a QUIC stack and a MASQUE client. `mullvad-masque-proxy` is a workspace crate in
the upstream repository, not on crates.io, so the choice is to vendor it (it is GPL-3.0 like
the rest) or write the CONNECT-UDP client against `quinn`. Then relay fields and a ladder
entry.

Risk: the largest new dependency footprint after DAITA, and it only pays off on networks that
block UDP but allow QUIC on 443.

### 7.7 DAITA  (XL)

Defence against traffic analysis: constant packet sizes, decoy traffic and pacing, driven by
machines handed out by the relay's config service.

Upstream: `talpid-tunnel-config-client` (gRPC to the config service on port 1337 of the ingress
relay), the `maybenot` crate, `talpid-wireguard` (DAITA settings applied to the peer), and the
`daita` feature of gotatun, which this client already has available in its pinned version.

Needed here, in order:

1. A gRPC client and the protobuf definitions from `talpid-tunnel-config-client`.
2. A way to reach the config service before the tunnel exists. Upstream builds a temporary
   gotatun device with a userspace smoltcp stack (`talpid-netstack`) at MTU 576 and opens TCP
   to `10.64.0.1:1337` through it. That stack is the expensive part.
3. Apply the returned PSK and machines to the real device: `Peer::with_daita`, decoy and delay
   fractions, timer parameters.
4. The relay filter, which already exists in the settings.

The same negotiation also returns the post-quantum PSK, so a DAITA implementation buys the
quantum-resistant session for free.

Risk: two large dependencies (tonic/prost and a userspace network stack) for a feature whose
effect is invisible when it works. The wire protocol is the most likely of the group to change
between upstream releases.

### 7.8 Per-app split tunnelling  (not feasible)

`VpnConfig.trustedApplications` and `blockedApplications` accept bundle names, but listing the
installed applications needs `ohos.permission.GET_BUNDLE_INFO_PRIVILEGED` (system_basic) or
`ENTERPRISE_GET_INSTALLED_BUNDLE_LIST` (enterprise). A normal application can resolve a bundle
name it already knows; it cannot enumerate them. That makes an application picker impossible
and leaves hand-typed bundle names, which is not a feature. Recorded so it is not
re-investigated.

### 7.9 Order

7.1 and 7.2 first: UI work, no protocol, immediate value on every network. 7.3 next: one
session to implement, one session to validate against a relay. 7.4 after it, for the same
reason with one more dependency. 7.5 is the structural change that 7.6 and 7.7 will reuse, so
it comes before them even though it is not the most-requested feature. 7.6 before 7.7 because
QUIC is a transport and DAITA is a protocol stack with a control plane.

## 8. UI backlog

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
