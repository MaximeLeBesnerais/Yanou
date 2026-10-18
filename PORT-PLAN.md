# Mullvad client on HarmonyOS — feasibility and port plan

Checked against the actual sources: `mullvadvpn-app@main` (sparse clone in `source/`) and the
HarmonyOS SDK installed here (`DevEco-Studio.app/Contents/sdk/default`, API 26 / HarmonyOS 26.0.0).

> **Planning rule for this file: no durations, no dates.** Milestones are ordered by dependency and
> closed by an exit criterion that can be observed on the device or in the build.

## Verdict

It is possible, and the protocol half is smaller than you'd expect because the ecosystem already
moved: the `tun` crate has an OpenHarmony backend that takes a raw fd, `libc`/`nix` know about
`target_env = "ohos"`, and `aws-lc-sys` ships an explicit OpenHarmony build path
(`OHOS_NDK_HOME` → NDK's `ohos.toolchain.cmake`). Mullvad's WireGuard is `gotatun`, which is
pure Rust apart from the AEAD provider, so it cross-compiles once cmake is on PATH.

What is *not* small is everything around it: 89k lines of Kotlin/Compose that cannot exist on
HarmonyOS, a Rust core whose Android branches are the ones you need and whose Linux branches are
the ones that compile, and a platform model that tears the VPN down when your UI process dies.

So: **not "a big VPN bullshit"** — the VPN part is the well-supported part. The bullshit is
platform lifecycle and the fact that you are writing a new client, not porting one.

## 1. The partial clone

Yes, and the clone itself is small. Measured on this machine:

```
git clone --depth 1 --filter=blob:none --sparse https://github.com/mullvad/mullvadvpn-app.git
cd mullvadvpn-app && git sparse-checkout set android
# .git 23M, android/ 33M
```

Add the crates you actually need to read:

```
git sparse-checkout add talpid-core talpid-tunnel talpid-wireguard talpid-routing \
                        talpid-types mullvad-daemon mullvad-api mullvad-jni dist-assets
# whole thing: 26M .git, 67M working tree
```

`android/` alone is not a buildable unit, and it is not the part you port:

- `android/settings.gradle.kts` pulls in 91 Gradle modules, most of them under `android/lib/*`.
- `android/app/build.gradle.kts:346` sets `module = repoRootPath`, `libname = "mullvad-jni"` —
  the tunnel comes from the Rust workspace at the repo root, not from `android/`.
- `:165` and `:222` pull `dist-assets/relays/` in as app assets.

If you want to *build* the Android app you need the whole repo, the Android SDK/NDK, JDK 17 and
the Rust Android targets — ~10 GB, and it buys you nothing for HarmonyOS. Clone it to read.

## 2. What HarmonyOS already gives you

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
a real fd you can hand to Rust. Routes, DNS, MTU and per-app split tunnelling are all system-side,
so `talpid-routing`, `talpid-dns` and `talpid-core::firewall` do not need real implementations —
same situation as Android, where they are stubs.

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

### 3.1 Rust core — the good news and the trap

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
  (`talpid-routing/src/unix/android.rs` is already exactly that stub — reuse it).
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
  `mullvad-api` can build. **`ring` has no ohos path** — build `gotatun` with `aws-lc-rs`
  (its default), never the `ring` feature. Needs `cmake` installed; the NDK is already here.

Then:

- `talpid-tunnel/src/tun_provider/android/` (JNI `TalpidVpnService.prepareTun`/`bypass`) needs an
  `ohos/` sibling: a `ThreadsafeFunction` into ArkTS to call `vpnExtension.create()`, plus the
  `protect` callback for the WireGuard UDP socket — which the daemon gets from the same shim.
  `mullvad-jni` is only 510 lines; a `mullvad-napi` of similar size is the whole native boundary.
- Skip gRPC. On Android the Kotlin UI talks to the in-process daemon over gRPC-on-UDS; on
  HarmonyOS the UI and the VPN are different processes, so you need *some* IPC — but it does not
  have to be gRPC. Either keep `mullvad-management-interface` over a unix socket and write a small
  NAPI client (no ArkTS protobuf work), or expose the `DaemonCommandChannel` directly as NAPI and
  let the UI-process shim forward over a local socket.
- `mullvad-paths` needs the app's `filesDir` injected at init (Android does the same through
  `AndroidContext`); the rest of the daemon config is portable.

### 3.2 ArkTS shell — a rewrite, not a port

`android/` is 1187 Kotlin files / ~89k lines, Compose UI, Hilt, Play billing, Android Keystore,
`ConnectivityManager`. None of it exists on HarmonyOS. What you need is a client that speaks the
same daemon API: account login (account number → device + WireGuard key), relay list, location
picker, connect/disconnect, settings (DNS, kill switch, split tunnel, obfuscation, multihop),
status. That is where the bulk of the code you write lives, and it is ordinary app work.

Equivalent platform pieces:

| Android                            | HarmonyOS                                              |
| ---------------------------------- | ------------------------------------------------------ |
| Android Keystore                   | HUKS (`@ohos.security.huks`)                            |
| `ConnectivityManager` callbacks     | `@ohos.net.connection`                                  |
| DataStore / Room                   | `@ohos.data.preferences` / relational store             |
| Foreground service + notification   | continuous task (`backgroundTaskManager`) + `statusBarManager` |
| `PackageManager` (app list)         | **not available** — see gaps                            |

### 3.3 Gaps no amount of code fixes

- **Always-on / start at boot.** No public API for a third-party VPN. The extension is started by
  your app; if your app process dies, the system drops the VPN. You hold it with a continuous
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
- **No control-center tile, no unremovable custom notification.** See 3.4 — both are platform
  limitations, not omissions in the plan.
- DAITA, obfuscation (shadowsocks/udp-over-tcp), multihop and custom DNS live in Rust and come for
  free once the core builds — they are not gaps, they are just untested.
- **Android-in-a-box containers (EasyAbroad, DroidTong) bypass the host VPN.** Verified on device:
  with our tunnel up and moving traffic, Brave inside EasyAbroad reports the tablet's own Chinese
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
`continuousTaskId` — no title, no text, no buttons. The system draws it; `wantAgent` decides where
a tap lands. It also must be requested **from a UIAbility** ("Continuous tasks can be requested
only by the UIAbility in the stage model"), which fits the rule that the VPN dies when the process
that called `startVpnExtensionAbility` exits: the UI process holds the task.

So "permanent notification" is really two: the system's continuous-task card (unremovable, no
controls, tap → app) and a normal notification you publish and re-publish on every state change,
carrying the buttons. The continuous task itself needs a `backgroundModes` claim in
`module.json5`, and the enum has no `vpn` — `taskKeeping` and `dataTransfer` are the plausible
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
to raise the UI — it publishes an in-app common event that the VPN process subscribes to. That is
the cheapest control path, and it is exactly what the widget needs too.

**The tile.** There is no `TileService` equivalent: the API 26 SDK contains no control-center or
quick-setting API at all (`ets/api` has no `controlCenter` / `quickSetting` / tile symbol). The
same question keeps coming up on Huawei's developer forum
([example](https://developer.huawei.com/consumer/cn/forum/topic/0201202923434091911)) with no API
to point at, so treat the control center as closed to third-party apps. The two things that do
exist:

- **Service widget** — a `form` extension ability (`FormExtensionAbility` plus a form config
  profile referenced from `module.json5`), 1x1 or 2x1, with buttons that call
  `postCardAction({ action: 'message', params })`; the payload arrives in the widget's
  `onFormEvent`, which then publishes the same common event. This is the closest thing to a tile
  and it is the one I'd build.
- **Icon shortcut** — `shortcuts` in `module.json5` plus `shortcutManager` (API 20+): long-press
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

Deliberately no durations: the order is by dependency, and each milestone closes when a condition
holds, not when a date arrives.

**M0 — the pipe exists on the device.**
`VpnExtensionAbility` + `vpnExtension.create` → fd → `tun` crate → `gotatun` → one ping through a
real relay.
*Closes when:* a handshake completes, traffic leaves through the relay while the UI process is
alive, and the tunnel tears down cleanly.

**Half of M0 is verified on the tablet (2026-10-18, MatePad TGR-W00, API 24).** With the scaffold
in `app/`: the consent dialog appears, `VpnConnection.create` returns an fd, the Rust `tun` crate's
`ohos` backend reads it, the 0.0.0.0/0 route captures packets, and `VpnConnection.protect(26)`
succeeds on the relay socket. Still open: the actual WireGuard handshake — this build counts and
drops what it captures, so nothing leaves the device yet.

This is the milestone that decides whether the rest is worth doing: if `aws-lc` and the fd handoff
work, everything after it is ordinary work; if not, the design changes before any UI exists.

**M1 — the Rust core builds and runs headless for `aarch64-unknown-linux-ohos`.**
cfg policy for `target_env = "ohos"`, a tun provider replacing the JNI one, `mullvad-paths`
injected from the app sandbox, NAPI boundary, daemon in-process.
*Closes when:* connect / disconnect / status work from a test harness with no ArkTS UI.

**M2 — account and relay list.**
`mullvad-api` as-is if aws-lc cooperates; otherwise device creation and relay fetch move to the
ArkTS HTTP stack and only the tunnel stays in Rust. Plus the minimal UI: login, location, connect.
*Closes when:* a fresh account number logs in, a relay is selected from the live list, and the
connection is made with nothing hardcoded.

**M3 — lifecycle and surfaces.**
Continuous task from the UIAbility, the state-carrying notification with Connect/Disconnect
buttons, the home-screen widget, icon shortcuts, reconnect on network change, kill switch, split
tunnel, IPv6, MTU edge cases.
*Closes when:* the tunnel survives a Wi-Fi ↔ cellular switch, the UI process being backgrounded,
and a reconnection attempt after the system drops the extension; the notification reflects the
daemon's real state within one state change; a button and the widget both toggle the tunnel
without raising the UI; and the kill switch actually blocks when it should.

**M4 — parity.**
DNS blocking, multihop, obfuscation, DAITA, problem reports, translations.
*Closes when:* each feature is either verified on device or explicitly descoped in this file.

M0–M3 is the "usable client" line. M4 is open-ended by nature and gates nothing.

## 5. If you only want the tablet on Mullvad

Mullvad's account page generates per-device WireGuard configs. If a WireGuard client exists for
your HarmonyOS build, importing one replaces the whole port with a config file. Check that before
starting M1.

## 6. Open questions worth settling before M1

1. Does the VPN extension process survive a long-lived UI process with a continuous task on your
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

## 7. Roadmap

Required to call this a faithful port of the official client. Each item names the upstream
behaviour it mirrors, so the work is a port and not an invention.

### 7.1 Quantum resistance: ephemeral peer + PSK — **must have**
Upstream negotiates an ephemeral WireGuard peer and a preshared key *before* the tunnel opens,
over a temporary WireGuard device, by talking to the relay's config service at `10.64.0.1`
(`talpid-wireguard/src/ephemeral.rs`, `negotiation::negotiate_ephemeral_peers`). Default is on.
Porting it requires: the temporary device, the config-service protocol, `psk` on `PeerConfig`,
and a restart of the engine with the negotiated key/PSK. Until then the tunnel is plain
WireGuard, which the relay accepts, but the session is not quantum resistant.

### 7.2 DAITA — **must have**
Defence against AI-guided traffic analysis. Needs the same config-service negotiation plus
`Peer::with_daita`, constant packet sizes and decoy traffic, and the relay list's
`features.daita` flag (already read). The settings toggle exists but is inert.

### 7.3 Relay IP override — **must have**
`RelayOverride { ipv4_addr_in, ipv6_addr_in }` per hostname (`relay_constraints.rs:823-877`),
applied when building the tunnel parameters. This is the manual escape hatch for a network that
blackholes specific relay addresses, and it is the feature that would have made this debugging
session unnecessary.

### 7.4 Custom relay — **must have**
`RelaySettings::CustomTunnelEndpoint`: a user-supplied host, port, public key and address that
bypasses the relay selector entirely.

### 7.5 Full transport ladder
Implemented: `direct-v6 → shadowsocks-v4 → direct-v4 → shadowsocks-v6`, ladder-major (every
relay on one transport before the next), 180 s budget, fresh port and relay per attempt.
Shadowsocks targets the relay's `shadowsocks_extra_addr_in` addresses on ports 51900–51949 with
inner destination `127.0.0.1:51820`; both `direct-v6` and `shadowsocks-v4` have been verified
working on device.
Still missing from upstream's `RETRY_ORDER`: LWO (WireGuard over UDP with obfuscated framing),
QUIC/MASQUE (UDP 443, TLS to `<relay>.blockerad.eu`), udp2tcp and multihop.

### 7.6 Remaining parity items
- Multihop (entry + exit peers, extra MTU headroom).
- Persistent notification with Connect/Disconnect and the home-screen tile.
- Per-socket `protect()` for every socket the engine creates, instead of one pre-created socket.
- Real packet counters from peer stats in the UI (bytes already wired).
- DNS content-blocking bitmask (`100.64.0.x` resolver encoding) and custom DNS.
- Sigsum verification of the relay list (currently accepted unsigned, like upstream's fallback).
- Server list as country → city → relay tree, with filter chips and custom lists.
- Kill switch implemented as `isBlocking` plus route policy, not just a toggle.
- Latency-aware "Automatic": today the client prefers countries already used and then a
  random sample, so it can land on a relay on the other side of the planet. Measure the
  handshake time per candidate and keep a per-country score, like the official client's
  relay selector does.

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
  with the relay you are on pinned at the top and marked.
- Filter chips: DAITA, owned, recent, and (later) providers.
- Favourites and a user-ordered custom list, stored like `recents`.
- Search across country/city/hostname with result grouping, and keep the query when navigating
  back.
- Usage map shown per country as a small sparkline rather than "used 8×".

### 8.3 Settings that do what they say
- **Kill switch**: currently a toggle that only sets `isBlocking`. Either implement it (route
  policy + block on drop) or remove the switch; a lying toggle is worse than none.
- **Protocol preference**: let the user pin the transport ladder (Automatic / WireGuard only /
  obfuscated only) — needed on networks where one path is always better.
- **MTU**: expose it (1280/1360/1420), since container and mobile networks differ.
- **Per-app routing**: exclude chosen bundles from the tunnel — the only way to make
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
  Required before any binary leaves your hands.
