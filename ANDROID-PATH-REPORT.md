# From "Connect" to a working tunnel on Android

### And why a HarmonyOS re-implementation that dials `ipv4_addr_in:51820` may never see a handshake reply

| | |
|---|---|
| Repository | `mullvad/mullvadvpn-app`, sparse checkout at `./source` |
| Commit | `e522e99b8c2057e0168e7b9d966ca66ae2103bf5` (2026-10-16) |
| Dirs added for this analysis | `mullvad-relay-selector`, `mullvad-daemon-relay-selector`, `mullvad-management-interface`, `talpid-net`, `talpid-tunnel-config-client`, `mullvad-cli`, `docs` |
| Platform traced | `target_os = "android"` (all Android-specific `cfg` branches quoted as such) |
| gotatun | crates.io dependency, `Cargo.toml:82` → `0.10.0` (lockfile `Cargo.lock:2045-2046`); source inspected from `~/.cargo/registry/src/index.crates.io-*/gotatun-0.10.1/` |
| Client code | not read or modified; the description in the task was used. |

**Path convention:** every `path:line` reference is relative to the repository root
`./source`. Line numbers are from the commit above.

Everything below is from the upstream source unless explicitly marked **(inference)** or **(from the task description)**.

---

## TL;DR

1. The Android client does **not** use `SetTargetState` over JNI anymore. Compose → `ConnectionProxy.connect()` → gRPC `ConnectTunnel` over a Unix socket → `DaemonCommand::SetTargetState(tx, TargetState::Secured)` (`mullvad-daemon/src/management_interface.rs:79-86`) → `TunnelCommand::Connect` → `ConnectingState`.
2. The tunnel is only declared **up** when the WireGuard device has received bytes (`rx_bytes > 0` for every peer) — `talpid-wireguard/src/connectivity/check.rs:383-412`. So a handshake reply is a *hard* requirement for both clients. There is no "assume up" path.
3. The default transport on the first attempt is plain WireGuard to the relay's **`ipv4_addr_in`** on a random port from the relay list's global `port_ranges` — `mullvad-relay-selector/src/relay_selector/endpoint_set.rs:126-134, 365-382`. `ipv6_addr_in` is only used on retry attempt #2 (or if the user pins IPv6), and only if the host has IPv6.
4. The only transports that can reach a *different IP* than `ipv4_addr_in` are **Shadowsocks** (`endpoint_data.shadowsocks_extra_addr_in`) and **QUIC/MASQUE** (`features.quic.addr_in`). Plain WG, LWO and udp2tcp all reuse the WG address. The Singapore relays publish **neither** extra address, so on that relay the official client has exactly one IPv4 address and one IPv6 address to choose from. Bridges are **API-only** and can never carry tunnel traffic.
5. Therefore: on a network where the chosen relay's IPv4 is blackholed at L3 and the device has no IPv6, **the official client cannot connect either**. It would keep cycling through direct → LWO → Shadowsocks → QUIC → udp2tcp (all on blocked IPv4 addresses), never becoming `Connected`. Details and the exact escape hatches in §6.

Two *additional* independent bugs in the original description were found (they do not explain the missing handshake reply, but they would prevent traffic right after it): the tunnel address `10.64.0.1/32` is the **gateway**, not the device's assigned address, and the Shadowsocks probe from the task used port 1236 instead of the list's `shadowsocks_port_ranges`.

---

## 1. The complete call chain

### 1.1 UI: the Connect button

`android/lib/feature/home/impl/src/main/kotlin/net/mullvad/mullvadvpn/feature/home/impl/connect/button/ConnectionButton.kt:33-84`

```kotlin
fun ConnectionButton(
    modifier: Modifier = Modifier,
    state: TunnelState,
    disconnectClick: () -> Unit,
    cancelClick: () -> Unit,
    connectClick: () -> Unit,
) {
    ...
    val onClick =
        when (state) {
            is TunnelState.Disconnected -> connectClick
            is TunnelState.Connecting -> cancelClick
            ...
        }
```

Wired up in `.../connect/ConnectScreen.kt:858-864`:

```kotlin
ConnectionButton(
    modifier = Modifier.fillMaxWidth().testTag(CONNECT_BUTTON_TEST_TAG),
    state = state.tunnelState,
    disconnectClick = onDisconnectClick,
    cancelClick = onCancelClick,
    connectClick = { handleThrottledAction(onConnectClick) },
)
```

and the callback is `connectViewModel::onConnectClick` (`ConnectScreen.kt:323`).

> Note: `ConnectScreen.kt:311-315` also calls `connectViewModel.onConnectClick()` when the user returns from the location picker with `result.connect == true` (i.e. "select location and connect").

### 1.2 ViewModel

`.../connect/ConnectViewModel.kt:174-184`

```kotlin
fun onConnectClick() {
    viewModelScope.launch {
        connectionProxy.connect().onLeft { connectError ->
            when (connectError) {
                is ConnectError.Unknown -> _uiSideEffect.send(UiSideEffect.ConnectError.Generic)
                is ConnectError.NotPrepared ->
                    _uiSideEffect.send(UiSideEffect.NotPrepared(connectError.error))
            }
        }
    }
}
```

`prepareVpnSafe()` is **not** a permission dialog in the normal case — it is `VpnService.prepare(context)`, which returns `null` when the app already holds the VPN consent (`android/lib/common/src/main/kotlin/net/mullvad/mullvadvpn/lib/common/util/VpnServiceUtils.kt:36-60`). The tun itself is created later, from Rust, via JNI (§1.6).

### 1.3 Repository → gRPC

`android/lib/repository/src/main/kotlin/net/mullvad/mullvadvpn/lib/repository/ConnectionProxy.kt:44-47`

```kotlin
suspend fun connect(): Either<ConnectError, Boolean> = either {
    context.prepareVpnSafe().mapLeft(ConnectError::NotPrepared).bind()
    managementService.connect().bind()
}
```

`android/lib/grpc/src/main/kotlin/net/mullvad/mullvadvpn/lib/grpc/ManagementService.kt:342-344`

```kotlin
suspend fun connect(): Either<ConnectError, Boolean> =
    Either.catch { grpc.ConnectTunnel().execute(Unit).value }
```

The RPC is defined at `mullvad-management-interface/proto/management_interface.proto:12`:

```proto
rpc ConnectTunnel(google.protobuf.Empty) returns (google.protobuf.BoolValue) {}
```

The gRPC server runs on a Unix domain socket inside the app process. The socket path is handed to Rust at daemon startup: `MullvadVpnService.startDaemon()` → `MullvadDaemon.initialize(vpnService, rpcSocketPath, …)` (`android/app/src/main/kotlin/net/mullvad/mullvadvpn/app/service/MullvadVpnService.kt:175-186`), JNI entry `mullvad-jni/src/lib.rs:82-140` → `spawn_daemon` (`mullvad-jni/src/lib.rs:188-220`) → `Daemon::start(daemon_config, …)`.

**So the UI → daemon hop is gRPC over a Unix socket, not JNI.** JNI is used for exactly two things: starting the daemon, and `openTun` / `bypass` / `closeTun`.

### 1.4 Daemon: `ConnectTunnel` → `SetTargetState(Secured)`

`mullvad-daemon/src/management_interface.rs:79-86`

```rust
async fn connect_tunnel(&self, _: Request<()>) -> ServiceResult<bool> {
    log::debug!("connect_tunnel");

    let (tx, rx) = oneshot::channel();
    self.send_command_to_daemon(DaemonCommand::SetTargetState(tx, TargetState::Secured))?;
    let connect_issued = self.wait_for_result(rx).await?;
    Ok(Response::new(connect_issued))
}
```

`mullvad-daemon/src/lib.rs:1527` dispatches the command; the handler is `lib.rs:1911-1918`:

```rust
async fn on_set_target_state(&mut self, tx: oneshot::Sender<bool>, new_target_state: TargetState) {
    let state_change_initiated = self.set_target_state(new_target_state).await;
    ...
}
```

`lib.rs:3552-3570`:

```rust
async fn set_target_state(&mut self, new_state: TargetState) -> bool {
    if new_state != *self.target_state || self.tunnel_state.is_in_error_state() {
        log::debug!("Target state {:?} => {:?}", *self.target_state, new_state);
        self.target_state.set(new_state).await;
        match *self.target_state {
            TargetState::Secured => self.connect_tunnel(),
            TargetState::Unsecured => self.disconnect_tunnel(),
        }
        true
    } else { false }
}

fn connect_tunnel(&mut self) { self.send_tunnel_command(TunnelCommand::Connect); }
```

`send_tunnel_command` (`lib.rs:3582-3587`) pushes `TunnelCommand::Connect` into the **tunnel state machine** task (`talpid-core/src/tunnel_state_machine`).

### 1.5 Tunnel state machine → tunnel parameters

`talpid-core/src/tunnel_state_machine/disconnected_state.rs:234` answers it with the first connecting state:

```rust
Some(TunnelCommand::Connect) => NewState(ConnectingState::enter(shared_values, 0)),
```

`connecting_state.rs:55-165` is the whole "generate parameters and open the tunnel" step:

```rust
// connecting_state.rs:82-94
let ip_availability = match shared_values.connectivity.availability() {
    Some(ip_availability) => ip_availability,
    // If we're offline, enter the offline state
    None => { ... return ErrorState::enter(shared_values, ErrorStateCause::IsOffline); }
};

// connecting_state.rs:96-100
match shared_values.runtime.block_on(
    shared_values.tunnel_parameters_generator.generate(retry_attempt, ip_availability),
) { ... }

// connecting_state.rs:128-145  (Android only)
shared_values.prepare_tun_config(false);
if retry_attempt > 0
    && retry_attempt.is_multiple_of(MAX_ATTEMPTS_WITH_SAME_TUN)   // 5, connecting_state.rs:36
    && let Err(error) = shared_values.tun_provider.lock().unwrap().open_tun_forced()
{ ... }

// connecting_state.rs:147-161
let connecting_state = Self::start_tunnel(..., tunnel_parameters, ..., retry_attempt);
```

`MAX_ATTEMPTS_WITH_SAME_TUN = 5` (`connecting_state.rs:36`) is the only tun-recycling rule: every 5th attempt the Android tun fd is recreated from scratch.

### 1.6 Relay selection and construction of `TunnelParameters`

The generator is `mullvad-daemon/src/tunnel.rs` (`ParametersGenerator`).

**Selection** (`tunnel.rs:172-215`):

```rust
async fn generate(&mut self, retry_attempt: u32, ip_availability: IpAvailability)
    -> Result<TunnelParameters, Error> {
    // Custom tunnel endpoints bypass relay selection entirely.
    if let RelaySettings::CustomTunnelEndpoint(ref endpoint) = self.relay_settings { ... }

    let data = self.device().await?;                       // account + device + private key
    let selected_relay = self.relay_selector.get_relay(retry_attempt as usize, ip_availability)?;
    let GetRelay { endpoint, obfuscator, inner } = selected_relay;
    ...
    Ok(self.create_wireguard_tunnel_parameters(endpoint, data, obfuscator))
}
```

**Config construction** (`tunnel.rs:218-268`) — this is the canonical "what goes into WireGuard":

```rust
fn create_wireguard_tunnel_parameters(
    &self, mut endpoint: MullvadEndpoint, data: PrivateAccountAndDevice,
    obfuscator_config: Option<Obfuscators>,
) -> TunnelParameters {
    let tunnel_ipv4 = data.device.wg_data.addresses.ipv4_address.ip();
    let tunnel_ipv6 = data.device.wg_data.addresses.ipv6_address.ip();
    let tunnel = wireguard::TunnelConfig {
        private_key: data.device.wg_data.private_key,
        addresses: vec![IpAddr::from(tunnel_ipv4), IpAddr::from(tunnel_ipv6)],
    };

    // Deliberately filter out private IP ranges but keep the routes...
    let routes = Some(
        endpoint.exit_peer.iter().chain(std::iter::once(&endpoint.peer))
            .flat_map(|peer| peer.allowed_ips.iter()).copied().collect(),
    );

    for peer in endpoint.exit_peer.iter_mut().chain(std::iter::once(&mut endpoint.peer)) {
        peer.allowed_ips = subtract_lan_nets(&peer.allowed_ips);
    }

    wireguard::TunnelParameters {
        connection: wireguard::ConnectionConfig {
            tunnel,
            peer: endpoint.peer,
            exit_peer: endpoint.exit_peer,
            ipv4_gateway: endpoint.ipv4_gateway,
            ipv6_gateway: Some(endpoint.ipv6_gateway),
            routes,
            #[cfg(target_os = "linux")] fwmark: Some(mullvad_types::TUNNEL_FWMARK),
        },
        options: self.tunnel_options.wireguard.clone().into_talpid_tunnel_options(),
        generic_options: self.tunnel_options.generic.clone(),
        obfuscation: obfuscator_config,
    }
}
```

Where each field comes from:

| Field | Source | File:line |
|---|---|---|
| `tunnel.private_key` | the device's key, generated when the device was registered | `mullvad-daemon/src/device/service.rs:43-79` |
| `tunnel.addresses` | `ipv4_address` / `ipv6_address` returned by `POST /v1/devices` | `mullvad-api/src/device.rs:22-31, 40-70` |
| `peer.public_key` | relay list `endpoint_data.public_key` | `mullvad-relay-selector/src/relay_selector/detailer.rs:64-78` |
| `peer.endpoint` | `SocketAddr::new(<ipv4_addr_in or ipv6_addr_in>, random port in port_ranges)` | `endpoint_set.rs:126-134, 365-382` |
| `peer.psk` | `None` here; filled in by ephemeral peer negotiation | `detailer.rs:74-75`, `config.rs:166-177` |
| `peer.allowed_ips` | `0.0.0.0/0`, `::/0`, plus the two gateway /32s, minus RFC1918 (except `10/8` and `fc00:bbbb:bbbb:bb01::/64`) | `detailer.rs:64-78`, `relay_constraints.rs:549-560`, `tunnel.rs:120-165` |
| `ipv4_gateway` / `ipv6_gateway` | relay list `wireguard.ipv4_gateway` / `ipv6_gateway` (`10.64.0.1`, `fc00:bbbb:bbbb:bb01::1`) | `detailer.rs:79-84` |
| `obfuscation` | `Option<Obfuscators>` from the selector | `endpoint_set.rs:217-270` |

`subtract_lan_nets` (`tunnel.rs:120-165`) is worth noting because it explains why `10.64.0.1` must stay reachable *inside* the tunnel:

```rust
/// Private networks that may point to Mullvad services in the VPN tunnel.
const ALLOWED_IN_TUNNEL_LAN_NETS: [IpNetwork; 2] = [
    // Net including the relay IPv4 gateway. Used for DNS, tunnel config service, and connectivity
    // check.
    IpNetwork::V4(Ipv4Network::new_checked(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap()),
    IpNetwork::V6(Ipv6Network::new_checked(
        Ipv6Addr::new(0xfc00, 0xbbbb, 0xbbbb, 0xbb01, 0, 0, 0, 0), 64).unwrap()),
];
```

**Device registration** (`mullvad-daemon/src/device/service.rs:43-79`) — this is where the account device, and thus the key that ends up in `TunnelConfig`, is created:

```rust
pub fn generate_for_account(&self, account_number: AccountNumber) -> impl Future<...> {
    let private_key = PrivateKey::new_from_random();
    let pubkey = private_key.public_key();
    ...
    let (device, addresses) = retry_future(factory /* proxy.create(number, pubkey) */, ...).await?;
    Ok(PrivateAccountAndDevice {
        account_number,
        device: PrivateDevice::try_from_device(device, WireguardData { private_key, addresses, created: Utc::now() })?,
    })
}
```

with the HTTP call in `mullvad-api/src/device.rs:187-212`:

```rust
let request = self.handle.post_json(&format!("{ACCOUNTS_URL_PREFIX}/devices"), &submission);
// expected_status(&[StatusCode::CREATED])
```

`PrivateDevice::try_from_device` even asserts the invariant (`mullvad-daemon/src/device/mod.rs:197-205`): `if device.pubkey != wg_data.private_key.public_key() { … }`.

> **Relevant to the client:** the account/device public key does not need to reach the relay by any other route. It is registered once via `POST /accounts/v1/devices`, and the relay learns it from that same API. The registration is confirmed present, so this step is *not* the problem.

### 1.7 Pre-tunnel work: ephemeral peers (PQ) / DAITA, obfuscation

Android always uses GotaTun (userspace WireGuard) and applies obfuscation in-process. `talpid-wireguard/src/lib.rs:454-641`:

```rust
// lib.rs:459-471
let route_mtu = args.runtime.block_on(get_route_mtu(params, &args.route_manager));
let userspace_multihop = true;
let tunnel_mtu = calculate_tunnel_mtu(route_mtu, params, userspace_multihop);
let obfuscation_mtu = route_mtu;
let mut config = crate::config::Config::from_parameters(params, tunnel_mtu, obfuscation_mtu)?;

// lib.rs:475-486
let bypass = obfuscation::create_socket_bypass(args.tun_provider.clone());
// Android always uses GotaTun (userspace WireGuard), which applies the obfuscation
// itself. See `MaybeObfuscatingTransportFactory`.
let obfuscator = args.runtime.block_on(get_obfuscator(params, &mut config, &bypass))?;
let obfuscation = obfuscator.as_ref().map(Obfuscator::obfuscation).cloned();

// lib.rs:502   the tun device is opened BEFORE the PSK negotiation
let tun = gotatun::open_tun(&config, args.tun_provider.clone())?;
let is_new_tun = tun.is_new();

// lib.rs:517-530
let tunnel_fut = async move {
    let daita = if config.negotiates_ephemeral_peers() {
        let peers = ephemeral::negotiate_ephemeral_peers(&config, args.retry_attempt, obfuscation.as_ref(), &bypass).await?;
        config.set_ephemeral_keys(peers.private_key, peers.ingress_psk, peers.exit_psk);
        peers.daita
    } else { None };
    ...
```

`negotiates_ephemeral_peers` is `quantum_resistant || daita` (`talpid-wireguard/src/config.rs:160-163`), and **quantum resistance is ON by default**:

```rust
// mullvad-types/src/wireguard.rs:16-20
pub enum QuantumResistantState {
    #[default]
    On,
    Off,
}
// mullvad-types/src/wireguard.rs:207-214
impl Default for TunnelOptions { fn default() -> Self { TunnelOptions {
    mtu: None,
    quantum_resistant: QuantumResistantState::default(), // == On
    daita: false, userspace: false, rotation_interval: None,
}}}
```

The negotiation itself (`talpid-wireguard/src/ephemeral.rs:28-84`) is a **full WireGuard handshake with the same relay, over the same endpoint, through a temporary GotaTun device**, followed by TCP to the config service at `10.64.0.1:1337` inside that tunnel:

```rust
const INITIAL_PSK_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(8);   // :20
const MAX_PSK_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(48);      // :21
const PSK_EXCHANGE_TIMEOUT_MULTIPLIER: u32 = 2;                          // :22

// :34-36
let timeout = psk_exchange_timeout(retry_attempt);
// An unreachable relay should fail as fast as the connectivity check would.
let handshake_timeout = connectivity::establish_timeout(retry_attempt);
...
// :55-67  "Reach the ingress relay the same way as the tunnel does."
let ingress_transport = |client_public_key: &PublicKey| {
    let obfuscation = obfuscation.cloned().map(|o| o.with_client_public_key(client_public_key.clone()));
    transport_factory(false, obfuscation, config.entry_peer.endpoint, Arc::clone(bypass))
};
```

and `talpid-tunnel-config-client/src/negotiation.rs:76-103`:

```rust
pub struct NegotiationConfig {
    pub private_key: PrivateKey,
    pub tunnel_ipv4: Ipv4Addr,
    /// The address of the config service in the tunnel.
    pub config_service_ip: Ipv4Addr,
    ...
}
impl NegotiationConfig {
    fn allowed_ip(&self) -> IpNetwork {
        // Only allow tunnel to talk to the config service
        IpNetwork::from(IpAddr::V4(self.config_service_ip))
    }
}
```

`CONFIG_SERVICE_PORT` is `1337` (`talpid-tunnel-config-client/src/lib.rs:106`).

**Consequences:**
* On a blocked network the official client's *first* failure is not "no handshake reply on the tun" — it is an 8 s (then 16/32/48 s) `EphemeralPeerNegotiationTimeout` inside `negotiate_ephemeral_peers`, because it needs a working WG handshake *before* the tunnel is even opened (`lib.rs:807-809` maps that to `Error::TimeoutError`).
* Your implementation sending a 148-byte handshake-init on the tun is therefore *ahead* of where the official client would be on a blocked network. The absence of PQ/PSK is **not** an explanation for silence: a WireGuard responder answers a handshake initiation without knowing any PSK (the PSK only enters the chaining key), so a missing PSK cannot suppress a reply.

Obfuscation config → transport settings (`talpid-wireguard/src/obfuscation.rs:120-164`):

```rust
ObfuscatorConfig::Shadowsocks { endpoint } => {
    tunnel_obfuscation::Settings::Shadowsocks(shadowsocks::Settings {
        shadowsocks_endpoint: *endpoint,
        wireguard_endpoint: if endpoint.is_ipv4() {
            SocketAddr::from((Ipv4Addr::LOCALHOST, 51820))     // <-- inner target is loopback!
        } else {
            SocketAddr::from((Ipv6Addr::LOCALHOST, 51820))
        },
    })
}
ObfuscatorConfig::Quic { hostname, endpoint, auth_token } => {
    let wireguard_endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 51820));
    let settings = quic::Settings::new(*endpoint, hostname.to_owned(), auth_token.parse().unwrap(), wireguard_endpoint)
        .mtu(mtu);
    ...
}
```

### 1.8 Android VpnService: tun fd creation, routes, DNS, and `protect()`

**(a) tun creation is a JNI *call into Java* from Rust.**

`talpid-wireguard/src/gotatun/mod.rs:192-236` (`#[cfg(target_os = "android")]` branch):

```rust
let (tun, fd) = get_tunnel_for_userspace(tun_provider, config)?;   // :215
let mut tun_config = tun::Configuration::default();
tun_config.raw_fd(fd);
let mut device = tun::Device::new(&tun_config).unwrap();
device.set_mtu(config.mtu).unwrap();
let device = tun::AsyncDevice::new(device).unwrap();
```

`talpid-wireguard/src/gotatun/mod.rs:546-589`:

```rust
pub fn get_tunnel_for_userspace(tun_provider: ..., config: &Config)
    -> Result<(Tun, std::os::fd::RawFd), TunnelError> {
    let tun_config = tun_provider.config_mut();
    tun_config.addresses = config.tunnel.addresses.clone();
    tun_config.ipv4_gateway = config.ipv4_gateway;
    tun_config.ipv6_gateway = config.ipv6_gateway;
    tun_config.mtu = config.mtu;
    // Route everything into the tunnel and have WireGuard act as a firewall when blocking.
    tun_config.routes = if config.ipv6_gateway.is_some() {
        vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
    } else {
        vec!["0.0.0.0/0".parse().unwrap()]
    };
    ...
    match nix::unistd::dup(&tunnel_device) {
        Ok(fd) => return Ok((tunnel_device, fd.into_raw_fd())),
```

`talpid-tunnel/src/tun_provider/android/mod.rs:119-187` → JNI `openTun`:

```rust
pub fn open_tun(&mut self) -> Result<VpnServiceTun, Error> { /* returns cached fd if config unchanged (:129-139) */ }
pub fn open_tun_forced(&mut self) -> Result<VpnServiceTun, Error> { ... }
fn open_tun_fd(&mut self, config: VpnServiceConfig) -> Result<RawFd, Error> {
    let method_name = "openTun";
    ... "(Lnet/mullvad/talpid/model/TunConfig;)Lnet/mullvad/talpid/model/CreateTunResult;"
}
```

Java side, `android/lib/talpid/src/main/kotlin/net/mullvad/talpid/TalpidVpnService.kt:70-111`:

```kotlin
// Used by JNI
fun openTun(config: TunConfig): CreateTunResult =
    synchronized(this) { createTun(config).merge().also { activeTunStatus = it } }

private fun createTun(config: TunConfig): Either<CreateTunResult.Error, CreateTunResult.Success> = either {
    prepareVpnSafe().mapLeft { it.toCreateTunError() }.bind()
    val builder = Builder()
    val configureResult = builder.configureWith(config)
    connectivityListener.invalidateNetworkStateCache()
    val vpnInterfaceFd = builder.establishSafe()...bind()
    val tunFd = vpnInterfaceFd.detachFd()
    ...
    CreateTunResult.Success(tunFd)
}
```

and the builder itself (`TalpidVpnService.kt:114-125, 211-237`):

```kotlin
private fun Builder.configureWith(config: TunConfig): Either<Nel<ConfigError>, Unit> = either {
    setMtu(config.mtu)
    setBlocking(false)
    setMeteredIfSupported(false)
    config.excludedPackages.forEach { app -> addDisallowedApplication(app) }
    accumulate {
        accumulating { addAddressesAndRoutesSafe(config).bind() }
        accumulating { addDnsServersSafe(config).bind() }
    }
}
...
config.addresses.forEach { addAddress(address, address.prefixLength()) }  // /32 and /128
config.routes.forEach { addRoute(network, prefixLength) }
```

**(b) `protect()` is requested from Rust through `SocketBypass`, one hop per socket.**

`talpid-net/src/bypass.rs:44-84`:

```rust
pub struct BypassSocket<S> { pub socket: S, pub guard: BypassGuard }

impl<S: AsSocket> BypassSocket<S> {
    pub fn new(bypass: Arc<dyn SocketBypass>, socket: S) -> io::Result<Self> {
        let guard = BypassGuard::new(bypass, &socket)?;
        Ok(Self { socket, guard })
    }
}
...
fn new(bypass: Arc<dyn SocketBypass>, s: impl AsSocket) -> io::Result<BypassGuard> {
    let ref_ = SockRef::from(&s);
    let socket = ref_.try_clone()?;
    bypass.bypass_socket(ref_, &BypassToken(()))?;
    Ok(BypassGuard { bypass, socket })
}
```

The UDP socket is created *inside* gotatun's transport factory, and the bypass is applied at bind time (`talpid-wireguard/src/gotatun/obfuscation/mod.rs:130-143`):

```rust
async fn bind(&mut self, params: &UdpTransportFactoryParams) -> io::Result<(Self::Send, Self::Recv)> {
    let (sv, rv) = self.inner.bind(params).await?;
    let send = BypassedUdpSend(Arc::new(BypassSocket::new(self.bypass.clone(), sv)?));
    let recv = BypassedUdpRecv(BypassSocket::new(self.bypass.clone(), rv)?);
    Ok((send, recv))
}
```

Android implementation of `SocketBypass` (`talpid-wireguard/src/obfuscation.rs:299-312`):

```rust
#[cfg(target_os = "android")]
fn bypass_socket(&self, socket: socket2::SockRef<'_>, _token: &BypassToken) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    self.tun_provider.lock().unwrap()
        .bypass(&socket.as_raw_fd())
        .map_err(std::io::Error::other)
}
```

JNI hop (`talpid-tunnel/src/tun_provider/android/mod.rs:210-235`):

```rust
pub fn bypass(&mut self, socket: &impl AsRawFd) -> Result<(), Error> {
    let bypass_method = env.get_method_id(&self.class, "bypass", "(I)Z")?;
    let result = env.call_method_unchecked(self.object.as_obj(), bypass_method,
        JavaType::Primitive(Primitive::Boolean), &[JValue::Int(socket.as_raw_fd())])?;
    match result {
        JValue::Bool(0) => Err(Error::Bypass),
        JValue::Bool(_) => Ok(()),
        ...
    }
}
```

Java (`TalpidVpnService.kt:82`):

```kotlin
// Used by JNI
@Suppress("Unused") fun bypass(socket: Int): Boolean = protect(socket)
```

A *second* bypass path exists for the daemon's own API traffic while connected: `mullvad-daemon/src/api.rs:139-155` (`create_bypass_tx`) → `DaemonCommand::BypassSocket` → `talpid-core/src/tunnel_state_machine/mod.rs:696-702` → `tun_provider.bypass(&fd)`. That is how the daemon keeps its own HTTPS API client outside the tunnel.

**(c) Routes/DNS/firewall.**

* Routes on Android are *not* taken from `config.routes`; they are hardcoded to `0/0` (+ `::/0` iff an IPv6 gateway exists) at `gotatun/mod.rs:559-568`, then the real set is computed for the builder in `talpid-tunnel/src/tun_provider/android/mod.rs:325-360` (`resolve_routes`, which subtracts `ALLOWED_LAN_NETS` when LAN sharing is off but always keeps the gateways and `10.124.0.0/23` SOCKS proxies).
* DNS is baked into the tun at creation (Android cannot change DNS later). `prepare_tun_config(false)` (`talpid-core/src/tunnel_state_machine/mod.rs:725-737`) copies the configured DNS addresses into `TunConfig`; `VpnServiceConfig::resolve_dns_servers` (`talpid-tunnel/src/tun_provider/android/mod.rs:312-323`) falls back to the gateways (`10.64.0.1`, `fc00:bbbb:bbbb:bb01::1`) and drops IPv6 DNS if there is no IPv6 gateway. The route list actually handed to `Builder` is `VpnServiceConfig::resolve_routes` (`talpid-tunnel/src/tun_provider/android/mod.rs:330-380`).
* **There is no firewall on Android.** `talpid-core/src/firewall/android.rs:1-30` is a no-op stub (`apply_policy` returns `Ok(())`). Blocking is implemented by re-creating the tun with a "blocking config" (`talpid-tunnel/src/tun_provider/mod.rs:107-116, 123-148`).

### 1.9 talpid-wireguard: device construction and "is it up?"

`talpid-wireguard/src/lib.rs:532-611`:

```rust
let gotatun = gotatun::start_gotatun(tun, &config, daita.as_ref(), obfuscation, Arc::clone(&bypass)).await...;
let iface_name = gotatun.get_interface_name();
*tunnel.lock().await = Some(Box::new(gotatun) as TunnelType);

if is_new_tun {
    let expected_routes = tun_provider.lock().unwrap().real_routes();
    route_manager.wait_for_routes(expected_routes).await...   // :556-577
}

{
    let lock = tunnel.lock().await;
    let borrowed_tun = lock.as_ref().expect("The tunnel was dropped unexpectedly");
    match connectivity_monitor.establish_connectivity(borrowed_tun.as_ref()).await {
        Ok(true) => Ok(()),
        Ok(false) => { log::warn!("Timeout while checking tunnel connection"); Err(CloseMsg::PingErr) }
        Err(error) => { ...; Err(CloseMsg::PingErr) }
    }?;
}

let metadata = tunnel_metadata(iface_name, &config);
let selected_obfuscation = Obfuscator::multiplexer_committed_to(obfuscator).await...;
event_hook.on_event(TunnelEvent::Up { metadata, selected_obfuscation }).await;
```

Device construction (`talpid-wireguard/src/gotatun/mod.rs:397-464`):

```rust
let factory = transport_factory(optimize_buffer_size, obfuscation, config.entry_peer.endpoint, bypass);
let source_v4 = config.tunnel_ipv4();
let source_v6 = config.tunnel_ipv6();
...
let tun_rx = SourceFilter::new(tun_dev.clone(), source_v4, source_v6);
let device = DeviceBuilder::new()
    .with_udp(factory)
    .with_ip_pair(tun_dev, tun_rx)
    .build()
    .await?;
```

Peer configuration (`talpid-wireguard/src/gotatun/mod.rs:286-314`):

```rust
let private_key = StaticSecret::from(config.tunnel.private_key.to_bytes());
let mut entry_peer = to_gotatun_peer(&config.entry_peer, daita);
...
device.write(async |device| {
    device.clear_peers();
    device.set_private_key(private_key).await;
    device.add_peer(entry_peer);
    ...
})
```

`to_gotatun_peer` (`talpid-wireguard/src/gotatun/conversions.rs:12-35`) sets key, allowed_ips, endpoint and optional PSK — **and no persistent keepalive** (there is no such field in `PeerConfig`). Your `keepalive=25` is an addition, harmless for the handshake.

**How "up" is decided** — `talpid-wireguard/src/connectivity/check.rs`:

```rust
// :145-168
pub async fn establish_connectivity(&mut self, tunnel_handle: &dyn Tunnel) -> Result<bool, Error> {
    // Send initial ping to prod WireGuard into connecting.
    if let Err(err) = self.ping_state.ping().await { log::error!("{err}"); }
    // Also try to connect to the config service, in case ICMP is blocked...
    let config_service = SocketAddr::from((self.gateway, CONFIG_SERVICE_PORT)); // 10.64.0.1:1337
    let _tcp_ping = AbortOnDropHandle::new(tokio::spawn(TcpStream::connect(config_service)));
    self.establish_connectivity_inner(self.retry_attempt, ESTABLISH_TIMEOUT, ...).await
}

// :383-412
pub fn update(&mut self, now: Instant, new_stats: StatsMap) -> bool {
    match self {
        ConnState::Connecting { start, stats, tx_timestamp } => {
            if !new_stats.is_empty() && new_stats.values().all(|stats| stats.rx_bytes > 0) {
                ... *self = connected_state; return true;
            }
            ...
        }
```

with (`talpid-wireguard/src/connectivity/constants.rs:4-20`):

```rust
pub(crate) const BYTES_RX_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const TRAFFIC_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) const PING_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(4);
pub(crate) const ESTABLISH_TIMEOUT_MULTIPLIER: u32 = 2;
pub(crate) const MAX_ESTABLISH_TIMEOUT: Duration = PING_TIMEOUT;
```

So: the official client triggers the handshake by **sending real tunnel traffic** (ICMP to `10.64.0.1` plus a TCP connect to `10.64.0.1:1337`), and declares the tunnel up only when the WireGuard peer's `rx_bytes` counter moves. It never calls `gotatun`'s `force_handshake` (that API exists — `gotatun/src/device/mod.rs:367-398`, and it "never times out" — but `talpid-wireguard` does not use it).

### 1.10 Retry / backoff / fallback ladder

`talpid-wireguard/src/lib.rs:802-828` converts a failed connectivity check into `TimeoutError`:

```rust
match result {
    Ok(CloseMsg::EphemeralPeerNegotiationTimeout) | Ok(CloseMsg::PingErr) => Err(Error::TimeoutError),
    Ok(CloseMsg::Stop) => Ok(()),
    Ok(CloseMsg::SetupError(error)) => Err(error),
    Err(_) => Ok(()),
}
```

`talpid-core/src/tunnel_state_machine/connecting_state.rs:332-348`:

```rust
Err(error) => match error {
    tunnel_monitor::Error::TunnelMonitoring(talpid_wireguard::Error::TimeoutError) => {
        log::debug!("WireGuard tunnel timed out");
        None                                   // -> retry, not an error state
    }
    ...
```

`connecting_state.rs:652-673`:

```rust
fn handle_tunnel_close_event(self, block_reason: Option<ErrorStateCause>, shared_values: &mut SharedTunnelStateValues) -> EventConsequence {
    if let Some(block_reason) = block_reason { ... return NewState(ErrorState::enter(...)); }
    log::info!("Tunnel closed. Reconnecting, attempt {}.", self.retry_attempt + 1);
    Self::reset_routes(shared_values);
    EventConsequence::NewState(ConnectingState::enter(shared_values, self.retry_attempt + 1))
}
```

**There is no upper bound on `retry_attempt`.** Each attempt asks the relay selector for entry #`retry_attempt` of a 7-entry ladder (`mullvad-daemon-relay-selector/src/relay_selector/mod.rs:28-50`):

```rust
pub static RETRY_ORDER: LazyLock<Vec<EntrySpecificConstraints>> = LazyLock::new(|| {
    vec![
        // 1: any wireguard relay
        EntrySpecificConstraints::default(),
        // 2: prefer IPv6
        EntrySpecificConstraints::default().ip_version(IpVersion::V6),
        // 3: lwo
        EntrySpecificConstraints::lwo(),
        // 4: shadowsocks
        EntrySpecificConstraints::shadowsocks(),
        // 5: quic
        EntrySpecificConstraints::quic(),
        // 6: udp2tcp
        EntrySpecificConstraints::udp2tcp(),
        // 7: udp2tcp + IPv6
        EntrySpecificConstraints::udp2tcp().ip_version(IpVersion::V6),
    ]
});
```

and the ladder is documented as normative in `docs/relay-selector.md:40-79`:

```
- The first attempt will connect to a relay on a random port
- The second attempt will connect to a relay over IPv6 (if IPv6 is configured on the host) on a random port
- The third attempt will connect to a relay using LWO
- The fourth attempt will connect to a relay on a random port using Shadowsocks for obfuscation
- The fifth attempt will connect to a relay using QUIC for obfuscation
- The sixth attempt will connect to a relay on a random port using UDP2TCP obfuscation
- The seventh attempt will connect to a relay over IPv6 on a random port using UDP2TCP obfuscation (if IPv6 is configured on the host)
...
If no tunnel has been established after exhausting this list of attempts, the relay selector will
loop back to the first default constraint and continue its search from there.
```

Consumption of the ladder, with the IPv6 gate (`mullvad-daemon-relay-selector/src/relay_selector/mod.rs:141-176`):

```rust
let mut user_query = self.config.query.lock().unwrap().clone();
// Runtime parameters may shrink the set of usable IP versions — apply that *before*
// merging with retry_order so an IPv6-only retry attempt is correctly rejected when only
// IPv4 is available.
user_query.apply_ip_availability(runtime_ip_availability)?;
...
let maybe_relay = retry_order.iter()
    .filter_map(|retry| user_query.clone().merge_retry(retry.clone()))
    .filter_map(|query| self.get_relay_by_query(query).ok())
    .cycle().nth(retry_attempt);
```

`apply_ip_availability` (`mullvad-relay-selector/src/relay_selector/query.rs:117-140`) maps `IpAvailability::Ipv4 → Constraint::Only(IpVersion::V4)`, and `merge_retry` returns `None` on an empty intersection (`query.rs:63-67`). **On a host with no IPv6, ladder entries 2 and 7 are removed entirely.**

Backoff: there is no sleep between attempts; the delay is the failed attempt itself (4 s → 8 s → 15 s cap for the connectivity check, `constants.rs:14-18`; 8 s → 48 s for PSK exchange, `ephemeral.rs:20-22`). Tunnel parameters are regenerated from scratch each attempt, i.e. a **new random relay and a new random port** each time (`endpoint_set.rs:365-382` uses `rand::rng()`), so the client does try many (relay, port) pairs — but never two addresses of the same relay.

---

## 2. Step-by-step comparison

| # | Step | Official Android client | Your HarmonyOS client | Consequence |
|---|---|---|---|---|
| 1 | Connect trigger | Compose `ConnectionButton` → `ConnectViewModel.onConnectClick` (`ConnectionButton.kt:76-83`, `ConnectViewModel.kt:174`) | ArkTS UI → `startVpnExtensionAbility` | Equivalent |
| 2 | Transport to daemon | gRPC `ConnectTunnel` on a Unix socket (`ManagementService.kt:342`, `management_interface.proto:12`) | in-process Rust cdylib via C NAPI | Equivalent |
| 3 | Target state | `DaemonCommand::SetTargetState(Secured)` (`management_interface.rs:79-86`) → `TunnelCommand::Connect` (`lib.rs:3552-3570`) | direct call | Equivalent |
| 4 | State machine | `ConnectingState::enter(retry_attempt=0)`; unbounded retries | one shot + 5 s `force_handshake` timeout, then the client polls | The client gives up much earlier; official retries for minutes across 7 transports |
| 5 | Relay list | verified Sigsum list from `api.mullvad.net/app/v1/relays` (`mullvad-api/src/relay_list.rs:74-89`) | same list, fetched via CDN77 fronting — **the list content is identical, so this is not a difference** | none |
| 6 | Relay + address | weighted random relay; random port in `wireguard.port_ranges`; address = `ipv4_addr_in` (v4) or `ipv6_addr_in` (v6) (`endpoint_set.rs:126-134, 365-382`) | relay `ipv4_addr_in`, port 51820 (and a few others) | Same address family. You never try IPv6 because the tablet has none — same as the official client there. |
| 7 | Pre-tunnel PQ/PSK | **ON by default**: full WG handshake + TCP to `10.64.0.1:1337` before the tunnel opens (`ephemeral.rs:28-84`) | not implemented | Neither can succeed when the relay is unreachable; PQ makes the official client fail *earlier* (8 s timeout) |
| 8 | DAITA | off by default; needs config service | n/a | none |
| 9 | Obfuscation selection | one transport per attempt, cycling direct→v6→LWO→SS→QUIC→udp2tcp (`RETRY_ORDER`) | none (always direct WG); one manual SS experiment on port 1236 | You never try the only two transports that can use a *different IP* |
| 10 | Multihop | only if configured (default singlehop) | none | none for the default case |
| 11 | tun creation | Rust→JNI `openTun` → `VpnService.Builder` → `establish()` → `detachFd()` (`TalpidVpnService.kt:70-111`) | `vpnExtension.createVpnConnection().create(config)` | Equivalent |
| 12 | tun addresses | device's assigned `ipv4_address`/`ipv6_address` from `POST /devices` (`tunnel.rs:224-231`) | **`10.64.0.1/32`** — this is the *gateway* | Bug #2. `10.64.0.1` is the gateway/DNS/config-service address, so assigning it to the tun is wrong on its own terms (a probe to it becomes local). Additionally **(inference, server-side)** Mullvad programmes the peer's allowed-ips with the /32 it assigned, so inner packets sourced from `10.64.0.1` would be dropped even after a handshake succeeds. |
| 13 | routes into tun | `0/0` (+`::/0` iff IPv6 gateway) (`gotatun/mod.rs:559-568`) | `0.0.0.0/0`, `::/0` | Equivalent (harmless even without IPv6) |
| 14 | DNS | gateways `10.64.0.1` + `fc00:bbbb:bbbb:bb01::1`, IPv6 DNS dropped if no v6 (`tun_provider/android/mod.rs:312-323`) | `10.64.0.1` | Equivalent (v4) |
| 15 | MTU | computed from route MTU (`lib.rs:459-467`), typically 1380–1420 | 1420 | Cosmetic; not a handshake factor |
| 16 | socket exclusion | `SocketBypass` applied to the fd gotatun just created, inside the factory (`gotatun/obfuscation/mod.rs:130-143` → JNI `bypass`) | `vpnConnection.protect(fd)` on a pre-created fd, then wrap it | Equivalent **iff** `protect` returned true for the exact fd being used; the client's `blockedApplications` would also exclude its UID entirely (verify which of the two is actually in effect) |
| 17 | self-exclusion | `addDisallowedApplication(app)` for split-tunnel apps only (`TalpidVpnService.kt:119`) — the official app does *not* exclude itself; it uses `protect()` | `blockedApplications: [own bundle]` | Different mechanism, same intent. If HarmonyOS's `blockedApplications` does not exclude raw sockets created by native code, the client's packets go *into* the tun — see H3 |
| 18 | firewall / kill switch | no-op stub on Android (`firewall/android.rs`) | none | none |
| 19 | "tunnel up" criterion | `rx_bytes > 0` for every peer (`check.rs:390`) + ICMP/TCP probe to `10.64.0.1` (`check.rs:145-168`) | `peers()` `last_handshake` polled every 500 ms | The official client literally cannot report Connected without a reply; yours correctly reports failure. Same criterion, same outcome. |
| 20 | retry on unreachable relay | unbounded, new relay + new port every attempt, cycling the 7 transports | none | This is the biggest *behavioural* gap, and it still would not help on a fully blocked relay set |
| 21 | relay IP override | `RelayOverride { ipv4_addr_in, ipv6_addr_in }` per hostname (`relay_constraints.rs:823-877`, applied at `mullvad-daemon/src/lib.rs:762`) — and it *strips* `shadowsocks_extra_addr_in` of the overridden family | none | An escape hatch the client does not have, but it needs a reachable IP to point at |
| 22 | custom relay | `RelaySettings::CustomTunnelEndpoint` bypasses the selector entirely (`tunnel.rs:207-220`) | none | Same |

---

## 3. Which address is dialled, per transport

### 3.1 The schema

`mullvad-types/src/relay_list.rs:274-282` — every relay has exactly two IPs:

```rust
pub struct Relay {
    pub hostname: String,
    pub ipv4_addr_in: Ipv4Addr,
    pub ipv6_addr_in: Option<Ipv6Addr>,
    pub active: bool,
    pub weight: u64,
    pub location: Location,
}
```

Global endpoint data (`relay_list.rs:412-423`):

```rust
pub struct EndpointData {
    pub port_ranges: Vec<RangeInclusive<u16>>,
    pub ipv4_gateway: Ipv4Addr,
    pub ipv6_gateway: Ipv6Addr,
    /// Shadowsocks port ranges available on all WireGuard relays
    pub shadowsocks_port_ranges: Vec<RangeInclusive<u16>>,
    pub udp2tcp_ports: Vec<u16>,
}
```

Per-relay extras (`relay_list.rs:437-454`):

```rust
pub struct WireguardRelayEndpointData {
    pub public_key: wireguard::PublicKey,
    #[serde(default)] pub daita: bool,
    /// Parameters for connecting to the masque-proxy running on the relay.
    #[serde(default)] pub quic: Option<Quic>,
    #[serde(default)] pub lwo: Option<LwoVersion>,
    /// Optional IP addresses used by Shadowsocks
    #[serde(default)] pub shadowsocks_extra_addr_in: HashSet<IpAddr>,
}
```

`Quic` (`relay_list.rs:284-299`):

```rust
pub struct Quic {
    /// In-addresses for the QUIC obfuscator.
    /// The primary IPs of the relay will be included if and only if they are listed here.
    addr_in: HashSet<IpAddr>,
    token: String,
    domain: String,
}
impl Quic { pub const fn port() -> u16 { 443 } }
```

### 3.2 The code that picks the address, per mode

`mullvad-relay-selector/src/relay_selector/endpoint_set.rs:217-270`:

```rust
pub fn get_wireguard_obfuscator(
    &self, query: &Constraint<ObfuscationMode>, ip_version: Constraint<IpVersion>,
) -> Result<(SocketAddr, Option<Obfuscators>), Error> {
    ...
    // QUIC and Shadowsocks do not use the selected WireGuard endpoint, so it does not
    // need to match the requested IP version.
    let wireguard_ip_version = match query {
        Constraint::Only(ObfuscationMode::Shadowsocks(_) | ObfuscationMode::Quic) => {
            if self.wireguard.supports_ip_version(ip_version) { ip_version } else { Constraint::Any }
        }
        _ => ip_version,
    };
    let wireguard_endpoint = self.wireguard.random_endpoint(wireguard_ip_version, port)
        .ok_or(Error::NoMatchingAddresses)?;

    let obfuscator_config = match mode {
        ObfuscationMode::Off | ObfuscationMode::Port(_) => None,
        ObfuscationMode::Udp2tcp(settings) => Some(Obfuscators::Single(
            self.udp2tcp_config(wireguard_endpoint.ip(), settings.port)?)),          // WG IP
        ObfuscationMode::Shadowsocks(settings) => Some(Obfuscators::Single(
            self.shadowsocks_config(ip_version, settings.port)?)),                    // may be extra addr
        ObfuscationMode::Quic => Some(Obfuscators::Single(self.quic_config(ip_version)?)), // own addrs
        ObfuscationMode::Lwo(settings) => Some(Obfuscators::Single(
            self.lwo_config(wireguard_endpoint.ip(), settings.port)?)),               // WG IP
    };
    Ok((wireguard_endpoint, obfuscator_config))
}
```

* **Direct WireGuard** — `endpoint_set.rs:354-382`:

  ```rust
  fn random_endpoint(&self, ip_version: Constraint<IpVersion>, port: Constraint<u16>) -> Option<SocketAddr> {
      let ip = self.select_ip(ip_version)?;
      let port = random_port_in_ranges(&self.port_ranges, port)?;
      Some(SocketAddr::new(ip, port))
  }
  fn select_ip(&self, ip_version: Constraint<IpVersion>) -> Option<IpAddr> {
      match ip_version {
          Constraint::Any | Constraint::Only(IpVersion::V4) => Some(self.ipv4.into()),
          Constraint::Only(IpVersion::V6) => self.ipv6.map(|ip| ip.into()),
      }
  }
  ```

  Note `Constraint::Any` resolves to **IPv4**. There is no "happy eyeballs", no per-relay address list, no fallback within an attempt.

* **LWO** — same IP, new port: `endpoint_set.rs:315-323`.
* **udp2tcp** — same IP, TCP port from `udp2tcp_ports` (defaults `80, 443, 5001`, injected at `mullvad-api/src/relay_list.rs:235-244`): `endpoint_set.rs:296-310`.
* **Shadowsocks** — `endpoint_set.rs:423-447`:

  ```rust
  fn random_endpoint(&self, wg: &WireguardEndpoints, ip_version: Constraint<IpVersion>, port: Constraint<u16>) -> Option<SocketAddr> {
      // Try dedicated addresses first (any port is valid).
      if let Some(ip) = self.dedicated_addrs.iter()
          .filter(|&&ip| match ip_version { Constraint::Any => true,
              Constraint::Only(v) => IpVersion::from(ip) == v })
          .choose(&mut rand::rng())
      {
          let port = port.unwrap_or_else(|| rand::rng().random_range(1u16..=u16::MAX));
          return Some(SocketAddr::new(*ip, port));
      }
      // Fall back to the WireGuard address with restricted Shadowsocks port ranges.
      let addr = wg.select_ip(ip_version)?;
      let port = random_port_in_ranges(self.shadowsocks_port_ranges.as_ref()?, port)?;
      Some(SocketAddr::new(addr, port))
  }
  ```

  with `dedicated_addrs = relay.endpoint_data.shadowsocks_extra_addr_in` (`endpoint_set.rs:385-403`).

* **QUIC/MASQUE** — `endpoint_set.rs:341-351` + `QuicEndpoints::random_endpoint` (`endpoint_set.rs:520-535`): picks one of `quic.addr_in` (a set that may or may not include the relay's primary IP), **UDP port 443**, TLS/HTTP3 with SNI = `<relay>.blockerad.eu` and `Authorization: Bearer <token>` (`tunnel-obfuscation/src/quic.rs:1-90`).

* Shadowsocks parameters are fixed (`tunnel-obfuscation/src/shadowsocks.rs:17-18`):

  ```rust
  const SHADOWSOCKS_CIPHER: CipherKind = CipherKind::AES_256_GCM;
  const SHADOWSOCKS_PASSWORD: &str = "mullvad";
  ```

  and the inner destination handed to the SS server is **loopback** (`talpid-wireguard/src/obfuscation.rs:130-138`), with replies filtered on source (`shadowsocks.rs:117-133`).

### 3.3 What a real relay list actually offers

From the bundled copy of a genuine relay list — `mullvad-relay-selector/tests/relays.json` holds a real `RelayList` + `BridgeList` serialized in the *internal* representation (`{countries, wireguard}` and `{bridges, bridge_endpoint}`), i.e. the output of `mullvad-api/src/relay_list.rs:204-253`:

```
wireguard.port_ranges            : 53, 123, 4000-33433, 33565-51820, 52001-60000
wireguard.shadowsocks_port_ranges: 51900-51949
wireguard.udp2tcp_ports          : 80, 443, 5001          (injected in code)
wireguard.ipv4_gateway           : 10.64.0.1
wireguard.ipv6_gateway           : fc00:bbbb:bbbb:bb01::1
```

Per relay:

| Relay | `ipv4_addr_in` | `ipv6_addr_in` | `shadowsocks_extra_addr_in` | `quic.addr_in` |
|---|---|---|---|---|
| `sg-sin-wg-002` | 138.199.60.15 | 2a02:6ea0:d13e:2::a10f | **none** | **none** |
| `sg-sin-wg-001/003/101/102` | 138.199.60.2 / .28 / 146.70.199.194 / .130 | yes | **none** | **none** |
| `us-nyc-wg-303` | 143.244.47.91 | 2a02:6ea0:c43f:2::b52f | none | 143.244.47.103 |
| `us-nyc-wg-801` | 23.234.100.3 | 2607:9000:a000:31::f001 | 23.234.100.14 | 23.234.100.13 |
| `us-nyc-wg-701` | 23.162.8.3 | 2602:fa1f:1::f001 | 23.162.8.9 | none |
| `al-tia-wg-001` | 103.124.165.2 | 2a04:27c0:0:e::f001 | 103.124.165.17-27 + `::b002..b01f` | 103.124.165.6-16 + `::c002..c01f` |

Observations that matter for the client:

* The IPv6 address the Mac reached (`[2a02:6ea0:d13e:2::a10f]:26899`) is **exactly `sg-sin-wg-002.ipv6_addr_in`**, and 26899 lies in `4000-33433` — i.e. that session was IPv6, on a random port, on that relay. This is consistent with the client having failed attempt #1 (IPv4) and succeeded on attempt #2 (IPv6) — **(inference)** that corroborates an IPv4 blackhole even from the local network.
* **For the SG relays there is no alternative IPv4 address at all.** Shadowsocks on `sg-sin-*` can only use `ipv4_addr_in` on ports 51900-51949. QUIC is unavailable. So no client-side transport choice can reach an SG relay other than through `ipv4_addr_in` or `ipv6_addr_in`.
* The alternative addresses that do exist (SS "extra", QUIC) are almost always in the **same /24** as `ipv4_addr_in` (e.g. `23.234.100.3` vs `.13`/`.14`), i.e. they are separate daemons on the same host/rack. A prefix-level or ASN-level block catches them too.
* Ports: `51820` is in range. Your Mac's `26899` is in range. Port 1236 and 53/123 UDP probes to the relay are also in range (53 and 123 are deliberately in `port_ranges`). But **1236 is not a Shadowsocks port** — SS is only on `shadowsocks_port_ranges` (51900-51949) unless the relay has `shadowsocks_extra_addr_in` (SG does not).

### 3.4 `RelayEndpointData::Bridge` vs `Wireguard`, and `bridge.relays`

`mullvad-types/src/relay_list.rs:403-409`:

```rust
pub enum RelayEndpointData {
    Bridge,
    Wireguard(WireguardRelayEndpointData),
}
```

In this checkout the enum is effectively vestigial: `RelayEndpointData::Bridge` is **never constructed** anywhere (grep shows only the `Wireguard` payload being built, e.g. `mullvad-api/src/relay_list.rs:458-466`, and the enum is not consumed by the selector at all). What actually matters is that the bridge list is a **separate** list used **only for API traffic**:

* `mullvad-api/src/relay_list.rs:535-546` — "Mullvad Bridge servers are used for the Bridge API access method… (only used for API traffic)".
* `mullvad-daemon/src/api.rs:54-62` — `BuiltInAccessMethod::Bridge` → `get_bridge_forced()` → `CustomProxy::Shadowsocks(bridge)` → `ApiConnectionMode::Proxied`.
* `mullvad-relay-selector/src/relay_selector/mod.rs:123-129, 246-261` — `get_bridge_forced()` picks a random active bridge and its Shadowsocks endpoint (`ipv4_addr_in` + a random `bridge.shadowsocks[].port`).
* The proto says it outright: `management_interface.proto:104` — `// Bridges (Used for reaching the API)`.

**There is no code path in this version that sends tunnel traffic over a bridge.** So the fact that bridge IPs answer the client's ICMP proves only that the bridge prefix is not blocked, not that any tunnel path exists.

### 3.5 Custom relay / IP override

* `RelayOverride` (`mullvad-types/src/relay_constraints.rs:823-877`), applied at daemon startup/update (`mullvad-daemon/src/lib.rs:762`, `mullvad-daemon-relay-selector/src/relay_list/update.rs:285`):

  ```rust
  pub struct RelayOverride {
      pub hostname: Hostname,
      pub ipv4_addr_in: Option<Ipv4Addr>,
      pub ipv6_addr_in: Option<Ipv6Addr>,
  }
  ...
  // Additional IPs should be ignored when overrides are present
  relay.endpoint_data.shadowsocks_extra_addr_in.retain(|addr| {
      let not_overridden_v4 = self.ipv4_addr_in.is_none() && addr.is_ipv4();
      let not_overridden_v6 = self.ipv6_addr_in.is_none() && addr.is_ipv6();
      not_overridden_v4 || not_overridden_v6
  });
  ```

  This is the officially supported "the relay's IP is blocked, point the hostname at another IP" escape hatch. Note it deliberately drops the SS extra addresses of the overridden family (the override exists precisely because they are blocked), but it does **not** touch `quic.addr_in`.
* `RelaySettings::CustomTunnelEndpoint` (`mullvad-daemon/src/tunnel.rs:206-220`) bypasses relay selection entirely and builds parameters from a user-supplied hostname/port/key (`mullvad-types/src/custom_tunnel.rs`). Manual only.
* The endpoint the daemon reports to the UI/firewall is recomputed from the *obfuscator* when one is used (`talpid-types/src/net/wireguard.rs:27-49`, `Obfuscators::endpoints()` at `talpid-types/src/net/obfuscation.rs:80-103`) — i.e. the "next hop" is the SS/QUIC/udp2tcp address, not the WG address. That is the mechanical proof that, for those modes, the client's real destination is *not* `ipv4_addr_in`.
* `mullvad-daemon/src/tunnel.rs:192-205` also records whether the selected endpoint came from an override (`server_override`, computed by comparing the endpoint family against `overridden_ipv4/ipv6`).

---

## 4. Ranked hypotheses for "handshake-init is emitted, the relay never answers"

### H1 — The relay's IPv4 is blackholed upstream (L3). **Most likely.**

**For:**
* Your own measurements: ICMP 100 % loss to SG/Tokyo/NYC relay IPs, TCP/443 to the same IP times out (not refused), while ICMP to `1.1.1.1` and to a *bridge* IP succeeds. A timeout, not a reset, is the signature of a drop.
* Every transport the official client can use for an SG relay targets `ipv4_addr_in` (§3.3): direct, LWO, udp2tcp, and Shadowsocks-on-WG-address. There is nothing else to try.
* Your Mac's working session was over IPv6 on a random port — consistent with attempt #1 over IPv4 failing and retry #2 (IPv6) succeeding.
* The handshake bytes are produced by gotatun, the same library and version the official app uses (`Cargo.toml:82`), so a malformed-packet explanation is unlikely.

**Against:** none, except that it makes the whole project blocked until something reachable is found.

**Discriminator:** §5.

### H2 — Your Shadowsocks probe was invalid (wrong port, possibly wrong inner address), so it proves nothing about UDP reachability.

**For:**
* `shadowsocks_port_ranges` in the real list is **51900-51949**, and SG relays have no `shadowsocks_extra_addr_in` (`endpoint_set.rs:385-447`).
* The inner destination must be `127.0.0.1:51820` (`obfuscation.rs:130-138`); using the relay's public IP changes what the SS server forwards to and can be rejected.
* You observed SS with password "mullvad" and AES-256-GCM — those are correct (`shadowsocks.rs:17-18`) — but the port was not.

**Against:** the direct-WG path fails identically, and that one is not a port mistake (51820 is valid).

### H3 — Your UDP socket is not actually excluded from the tunnel, so the handshake is written into the tun and never leaves the device.

**For:**
* In the official client the socket that is protected is the one gotatun created, and the bypass happens inside the factory (`gotatun/obfuscation/mod.rs:130-143`); a pre-created fd that is later wrapped (the current design) only works if `protect()` succeeded on that exact fd, and if the wrapper does not `dup()` it.
* A handshake written into the tun would look exactly like "sent, no reply": gotatun's `tx_bytes` would increase.

**Against (strong):**
* The `blockedApplications: [own bundle]` setting should exclude *all* sockets of the app's UID, making `protect()` redundant. If HarmonyOS implements that as Android's `addDisallowedApplication`, H3 is impossible.
* You also report ICMP/TCP failures to the relay *from the device*, which is independent of the WG socket.
* Ports 53/123 attempts also failed; a routing loop would fail the same way, so this is not fully excluded — just unlikely.

**Discriminator:** capture on the uplink (or `tcpdump` on a laptop sharing the connection) while the client sends; or temporarily set `blockedApplications: []` and rely on `protect()` alone and compare.

### H4 — Wrong relay public key for the IP dialled (stale/mixed relay entries) → MAC1 mismatch → silent drop.

**For:** WireGuard silently discards handshakes whose MAC1 does not verify against the receiver's static public key. A stale relay list, or mixing `ipv4_addr_in` from relay A with `public_key` from relay B, produces exactly "no reply, ever", even on an open network.

**Against:** the client fetched the signed list, and the Mac works with the same list (over IPv6, but with the same key material). Verify that the `public_key` in use belongs to the same hostname as the IP.

**Discriminator:** dial a relay whose key is re-derived from a fresh list fetch; or run a local `wg` responder and confirm gotatun completes a handshake against it (this also tests the socket and bypass path).

### H5 — Missing PSK / PQ negotiation is the cause. **Ruled out.**

A responder does not need a PSK to answer an initiation; the PSK only enters the chaining key, so a mismatch yields an answer that fails to verify, not silence. And the official client's PSK is obtained *through* the relay (`ephemeral.rs`), so it cannot be a precondition for reaching it. Similarly, DAITA is off by default (`mullvad-types/src/wireguard.rs:207-214`).

### H6 — The relay drops the handshake because of the inner source address. **Ruled out for the handshake.**

The tun address is the gateway (`10.64.0.1/32`) instead of the device's assigned /32 (`tunnel.rs:224-231`, `mullvad-api/src/device.rs:22-31`). Mullvad programmes the peer's allowed-ips with the address it assigned to the device **(inference — server-side config is not in this repo)**, so inner packets sourced from `10.64.0.1` will be dropped — but **after** a handshake, and the handshake itself carries no inner address. This is a real, independent bug (it would also break the config-service probe, and on Android `10.64.0.1/32` is a local address so a probe to it never enters the tunnel at all).

### H7 — Wrong transport framing for SS/QUIC. **Not applicable to the WG probe.**

Even with the right port, an SS implementation that omits the `[salt][address][payload][tag]` framing, uses a wrong address encoding, or (for QUIC) omits the MASQUE CONNECT + bearer token will get silence. See `tunnel-obfuscation/src/shadowsocks.rs:104-133` and `quic.rs`. But the plain-WG probe is unaffected.

### H8 — UDP is blocked wholesale on the mobile network. **Ruled out (mostly).**

DNS to `1.1.1.1:53` produced replies (spoofed/injected, but they arrived), and the ICMP/UDP probes to bridges work. So UDP is not blanket-dropped; the drop is destination-specific.

---

## 5. The single most promising next experiment

**Force the official client to IPv4-only on a machine on the same LAN and try the same relay.**

Concretely, on the Mac that currently works over IPv6:

```
mullvad relay set ip-version v4      # wireguard_constraints.ip_version = Only(V4)
mullvad relay set location sg        # same relay set the client used
mullvad anti-censorship set mode auto
mullvad connect && mullvad status -v
```

Then repeat the failure with `mullvad anti-censorship set mode shadowsocks` (it will pick a port in
51900-51949, and a dedicated SS address on relays that publish one).

The exact CLI spellings in this checkout are `mullvad-cli/src/cmds/relay.rs:93-97, 334-343`
(`relay set ip-version`) and `mullvad-cli/src/cmds/anti_censorship.rs:24-27` (`anti-censorship set
mode`). Caution: `mullvad tunnel set ipv6 off` is a **different** setting — it only disables IPv6
*inside* the tunnel (`mullvad-daemon/src/lib.rs:2693-2697` sets
`tunnel_options.generic.enable_ipv6`), it does **not** stop the endpoint retry ladder from choosing
IPv6 on attempt #2. Only `relay set ip-version v4` does that.

Why this is the right experiment:

* It uses the official, known-good WireGuard stack, so it isolates **network** from **the client**.
* `RETRY_ORDER` means the Mac will *also* try IPv6 on attempt #2 unless IPv4 is pinned, which is what makes the test conclusive.
* If the Mac cannot connect over IPv4 either, H1 is confirmed and no amount of client-side work (obfuscation, PQ, keepalive, tun address) will produce a handshake.
* If the Mac *can* connect over IPv4 (direct or Shadowsocks), then compare the exact `(ip, port, transport)` it used against the client's with `tcpdump -ni any udp and host <relay_ip>`; that difference is the bug.

Secondary, if the Mac is not available: replay the exact 148-byte initiation the client emits from a host on the same LAN (the bytes have already been captured) and watch for any reply; silence there is conclusive for H1. And capture on the uplink while the client runs, to close out H3.

---

## 6. Would the official client connect on this network?

**No — not with the relay's IPv4 blackholed at L3 and no IPv6 on the device.**

Reasoning, strictly from the code:

1. Every tunnel transport the client can select for a relay that publishes no extra addresses (all `sg-sin-*` relays) targets either `ipv4_addr_in` (direct, LWO, udp2tcp, Shadowsocks-on-WG-address) or `ipv6_addr_in` (`endpoint_set.rs:354-382, 296-323, 423-447`).
2. Ladder entries 2 and 7 (the IPv6 ones) are removed before selection when the host has no IPv6 (`mullvad-daemon-relay-selector/src/relay_selector/mod.rs:147-152` + `query.rs:117-140` + `merge_retry`).
3. The client only reaches `Connected` when `rx_bytes > 0` on the WireGuard peer (`check.rs:383-412`), which requires a handshake reply. There is no degraded/"assume online" state.
4. So it would sit in `ConnectingState`, time out every 4–15 s, increment `retry_attempt`, and cycle direct → LWO → Shadowsocks → QUIC → udp2tcp → back to direct, forever (`connecting_state.rs:652-673`; `RETRY_ORDER` + `.cycle()`). The UI would show "Connecting…" and never "Connected". With `quantum_resistant = On` (the default) the first observable error is a PSK-negotiation timeout (8 s, `ephemeral.rs:20-22`), not a WG handshake.

**The only ways it could connect**, in order of plausibility:

1. **IPv6**: if the device had a global IPv6 address, ladder entry #2 would dial `ipv6_addr_in` on a random port — exactly what the Mac did (`[2a02:6ea0:d13e:2::a10f]:26899`).
2. **A relay that publishes a Shadowsocks dedicated address outside the blocked prefix** (`shadowsocks_extra_addr_in`, ladder entry #4). Exists for e.g. `us-nyc-wg-701..703`, `us-nyc-wg-801..808`, `al-tia-wg-001` — but these alternate addresses are in the same /24 as the blocked WG address, so a prefix-level block defeats them. **None of the SG relays have one.**
3. **A relay with a QUIC/MASQUE endpoint outside the blocked prefix** (ladder entry #5, UDP/443 + TLS to `<relay>.blockerad.eu`). Same /24 caveat; SG has none.
4. **A user-configured `RelayOverride`** pointing a hostname at an unblocked IP (needs an unblocked IP, which is the missing piece).
5. **A bridge**: not possible in this version — bridges are only an API access method (§3.4).

So: on the tested network the official client is in the same position as the client, with two extra shots (SS/QUIC alternate IPs, both absent on SG) and one unavailable shot (IPv6). **The missing handshake is not, on the evidence available, a difference between the client and the official one — the destination itself is unreachable.** The differences that *are* real (wrong inner tunnel address, no transport ladder, invalid SS port in the experiment) should be fixed, but they are downstream of reachability.

---

## Appendix: file index

| Concern | Path |
|---|---|
| Connect button / Compose | `android/lib/feature/home/impl/src/main/kotlin/net/mullvad/mullvadvpn/feature/home/impl/connect/button/ConnectionButton.kt`, `.../connect/ConnectScreen.kt` |
| ViewModel | `.../connect/ConnectViewModel.kt` |
| Repository → gRPC | `android/lib/repository/src/main/kotlin/net/mullvad/mullvadvpn/lib/repository/ConnectionProxy.kt`, `android/lib/grpc/src/main/kotlin/net/mullvad/mullvadvpn/lib/grpc/ManagementService.kt` |
| Proto | `mullvad-management-interface/proto/management_interface.proto` |
| RPC impl | `mullvad-daemon/src/management_interface.rs` |
| Daemon command loop / target state | `mullvad-daemon/src/lib.rs` |
| Tunnel parameters / relay glue | `mullvad-daemon/src/tunnel.rs` |
| Device registration | `mullvad-daemon/src/device/service.rs`, `mullvad-api/src/device.rs` |
| Relay list fetch + schema mapping | `mullvad-api/src/relay_list.rs`, `mullvad-types/src/relay_list.rs` |
| Relay selection + retry ladder | `mullvad-daemon-relay-selector/src/relay_selector/mod.rs`, `mullvad-relay-selector/src/relay_selector/{mod,query,filter,detailer,endpoint_set,helpers,relays}.rs`, `docs/relay-selector.md` |
| State machine | `talpid-core/src/tunnel_state_machine/{mod,connecting_state,connected_state,disconnecting_state,error_state,disconnected_state,tunnel_monitor}.rs` |
| WireGuard start / monitor | `talpid-wireguard/src/{lib,config,ephemeral,obfuscation,stats}.rs`, `talpid-wireguard/src/gotatun/{mod,conversions,obfuscation/mod}.rs` |
| Connectivity check | `talpid-wireguard/src/connectivity/{check,constants,monitor,pinger}` |
| Android tun + bypass | `talpid-tunnel/src/tun_provider/mod.rs`, `talpid-tunnel/src/tun_provider/android/mod.rs`, `talpid-net/src/bypass.rs` |
| Java VpnService | `android/lib/talpid/src/main/kotlin/net/mullvad/talpid/{TalpidVpnService,LifecycleVpnService}.kt` |
| App service / daemon startup | `android/app/src/main/kotlin/net/mullvad/mullvadvpn/app/service/{MullvadVpnService,MullvadDaemon,DaemonConfig}.kt`, `mullvad-jni/src/lib.rs` |
| Firewall (Android stub) | `talpid-core/src/firewall/android.rs` |
| Obfuscation transports | `tunnel-obfuscation/src/{shadowsocks,quic,udp2tcp,lwo,multiplexer}.rs` |
| Types | `talpid-types/src/net/{mod,wireguard,obfuscation,proxy}.rs`, `mullvad-types/src/{relay_constraints,endpoint,wireguard}.rs` |
| Config service client | `talpid-tunnel-config-client/src/{lib,negotiation}.rs` |
