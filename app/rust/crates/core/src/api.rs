//! Mullvad API client.
//!
//! Two connection modes, tried in this order:
//!
//! 1. **Direct** — TLS to `api.mullvad.net:443`. Correct on any network that resolves it.
//! 2. **Domain fronting** — the only way in on a network that poisons the name. A TLS
//!    connection to CDN77 with SNI `www.phpmyadmin.net`, then Mullvad's fronting protocol
//!    (`domain-fronting` crate: paired POST/GET streams keyed by `X-Mullvad-Session`),
//!    then a second TLS connection to the API inside that byte stream.
//!
//! This is why the client cannot live in ArkTS: the fronted mode is a bespoke tunnel, not
//! an HTTP request with a different Host header.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::{files_dir, log_line};

use domain_fronting::client::ProxyConnection;
use domain_fronting::DomainFronting;
use http::{header, Method, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const API_HOST: &str = "api.mullvad.net";
const API_PORT: u16 = 443;

/// Fronting configuration copied from `mullvad-api/src/domain_fronting.rs`.
const FRONT_HOST: &str = "www.phpmyadmin.net";
const FRONT_URL: &str = "https://www.phpmyadmin.net";
const PROXY_HOST: &str = "1105015943.rsc.cdn77.org";
const SESSION_KEY: &str = "X-Mullvad-Session";

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);

/// Whether the direct (unfronted) path may be attempted at all.
///
/// Default false: a direct attempt resolves `api.mullvad.net` and sends it as TLS SNI in
/// clear text, which is exactly the name a filtering network is watching for. The fronted
/// path only ever mentions the CDN front domain, so it is both the working route here and
/// the quieter one.
static DIRECT_ALLOWED: AtomicBool = AtomicBool::new(false);
/// A blocked address normally black-holes; do not spend the whole budget on it.
const DIRECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// The CDN certificate is deliberately not verified: the API connection inside the tunnel
/// is the one that has to be authentic, and it is verified against the webpki roots.
#[derive(Debug)]
struct AcceptAnyCdn;

impl ServerCertVerifier for AcceptAnyCdn {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn inner_tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn cdn_tls_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCdn))
        .with_no_client_auth();
    // CDN77 only fronts over HTTP/2, and the fronting protocol is HTTP/2 frames. Without
    // ALPN h2 the CDN answers as HTTP/1.1 and the handshake in `http2_from_stream` fails
    // with a bare hyper error.
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Arc::new(config)
}

fn server_name(host: &str) -> io::Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|_| io::Error::other("invalid server name"))
}

/// Direct TLS to the API.
async fn connect_direct() -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect((API_HOST, API_PORT)).await?;
    tcp.set_nodelay(true).ok();
    let connector = TlsConnector::from(inner_tls_config());
    connector
        .connect(server_name(API_HOST)?, tcp)
        .await
        .map_err(io::Error::other)
}

/// TLS to the CDN, then the fronting tunnel, then TLS to the API inside it.
async fn connect_fronted() -> io::Result<tokio_rustls::client::TlsStream<ProxyConnection>> {
    let front: Uri = FRONT_URL.parse().map_err(|_| io::Error::other("front uri"))?;
    let config = DomainFronting::new(front, PROXY_HOST.to_string())
        .with_session_key(SESSION_KEY.to_string());

    let proxy = config.proxy_config().await.map_err(|error| io::Error::other(format!("{error:?}")))?;
    let tcp = TcpStream::connect(proxy.addr).await?;
    tcp.set_nodelay(true).ok();

    let cdn = TlsConnector::from(cdn_tls_config())
        .connect(server_name(FRONT_HOST)?, tcp)
        .await
        .map_err(|error| io::Error::other(format!("{error:?}")))?;

    let tunnel = ProxyConnection::http2_from_stream(cdn, &config)
        .await
        .map_err(|error| io::Error::other(format!("{error:?}")))?;

    TlsConnector::from(inner_tls_config())
        .connect(server_name(API_HOST)?, tunnel)
        .await
        .map_err(io::Error::other)
}

async fn send_once<S>(stream: S, method: Method, path: &str, token: Option<&str>,
    body: Option<String>) -> io::Result<(u16, String)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, API_HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let payload = body.unwrap_or_default();
    let request = builder
        .body(Full::new(Bytes::from(payload)))
        .map_err(|error| io::Error::other(format!("{error:?}")))?;

    let response = sender.send_request(request).await.map_err(|error| io::Error::other(format!("{error:?}")))?;
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(io::Error::other)?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

#[no_mangle]
pub extern "C" fn mh_set_direct_allowed(allowed: i32) {
    DIRECT_ALLOWED.store(allowed != 0, Ordering::SeqCst);
    log_line(&format!("api direct allowed={}", allowed != 0));
}

/// After a direct attempt fails, skip it for a while: on a network where the API is
/// poisoned, every call otherwise burns a full timeout before falling back to fronting.
/// When the direct API path failed last, so the next call can skip straight to fronting.
static DIRECT_FAILED_AT: Mutex<Option<std::time::Instant>> = Mutex::new(None);
/// How long a direct failure suppresses further direct attempts.
const DIRECT_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(600);

fn direct_available() -> bool {
    let Ok(mut guard) = DIRECT_FAILED_AT.lock() else {
        return true;
    };
    match *guard {
        Some(at) if at.elapsed() < DIRECT_COOLDOWN => false,
        _ => {
            *guard = None;
            true
        }
    }
}

fn block_direct_for(seconds: u64) {
    let _ = seconds;
    if let Ok(mut guard) = DIRECT_FAILED_AT.lock() {
        // `direct_available` compares this against DIRECT_COOLDOWN.
        *guard = Some(std::time::Instant::now());
    }
}

async fn send(method: Method, path: &str, token: Option<&str>, body: Option<String>)
    -> io::Result<(u16, String)> {
    if !DIRECT_ALLOWED.load(Ordering::SeqCst) {
        let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let stream = connect_fronted().await?;
            send_once(stream, method, path, token, body).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronted request timed out"))?;
        match &result {
            Ok((status, _)) => log_line(&format!("api fronted {path} -> {status}")),
            Err(error) => log_line(&format!("api fronted {path} failed: {error}")),
        }
        return result;
    }

    if !direct_available() {
        let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let stream = connect_fronted().await?;
            send_once(stream, method, path, token, body).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronted request timed out"))?;
        match &result {
            Ok((status, _)) => log_line(&format!("api fronted {path} -> {status} (direct skipped)")),
            Err(error) => log_line(&format!("api fronted {path} failed: {error}")),
        }
        return result;
    }

    let direct = tokio::time::timeout(DIRECT_TIMEOUT, async {
        let stream = connect_direct().await?;
        send_once(stream, method.clone(), path, token, body.clone()).await
    })
    .await;

    match &direct {
        Ok(Ok(result)) => {
            log_line(&format!("api direct {path} -> {}", result.0));
            return Ok(result.clone());
        }
        Ok(Err(error)) => log_line(&format!("api direct {path} failed: {error}")),
        Err(_) => log_line(&format!("api direct {path} timed out")),
    }
    block_direct_for(600);

    // Direct failed (blocked or poisoned): the fronted path is the one that works here.
    let fronted = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let stream = connect_fronted().await?;
        send_once(stream, method, path, token, body).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronted request timed out"))?;
    match &fronted {
        Ok((status, _)) => log_line(&format!("api fronted {path} -> {status}")),
        Err(error) => log_line(&format!("api fronted {path} failed: {error}")),
    }
    fronted
}

fn error_code(body: &str) -> String {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        for key in ["type", "code"] {
            if let Some(code) = value.get(key).and_then(|v| v.as_str()) {
                return code.to_string();
            }
        }
    }
    String::new()
}

fn failure(status: u16, body: &str, extra: Option<(&str, Value)>) -> Value {
    let code = error_code(body);
    let detail = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("detail")
                .or_else(|| v.get("message"))
                .and_then(|d| d.as_str().map(str::to_string))
        })
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| body.to_string());
    let mut out = json!({
        "ok": false,
        "status": status,
        "code": code,
        "error": detail,
    });
    if let Some((key, value)) = extra {
        out[key] = value;
    }
    out
}

fn to_c(out: *mut std::os::raw::c_char, capacity: i32, value: &Value) -> i32 {
    let text = value.to_string();
    let bytes = text.as_bytes();
    if out.is_null() || capacity <= 0 {
        return -1;
    }
    let length = bytes.len().min(capacity as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, length);
        *out.add(length) = 0;
    }
    length as i32
}

fn cstr(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
}

/// `{"token": ...}` for an account number.
async fn fetch_token(account: &str) -> Result<(String, String), Value> {
    let body = json!({ "account_number": account }).to_string();
    let (status, text) = send(Method::POST, "/auth/v1/token", None, Some(body))
        .await
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))?;
    if !(200..300).contains(&status) {
        return Err(failure(status, &text, None));
    }
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))?;
    let token = parsed.get("access_token").and_then(Value::as_str).unwrap_or_default().to_string();
    let expiry = parsed.get("expiry").and_then(Value::as_str).unwrap_or_default().to_string();
    if token.is_empty() {
        return Err(json!({"ok": false, "code": "", "error": "no access_token in response"}));
    }
    Ok((token, expiry))
}

async fn fetch_devices(token: &str) -> Result<Vec<Value>, Value> {
    let (status, text) = send(Method::GET, "/accounts/v1/devices", Some(token), None)
        .await
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))?;
    if !(200..300).contains(&status) {
        return Err(failure(status, &text, None));
    }
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))?;
    Ok(parsed.as_array().cloned().unwrap_or_default())
}

async fn create_device(token: &str, public_key: &str) -> Result<Value, Value> {
    let body = json!({ "pubkey": public_key, "hijack_dns": false }).to_string();
    let (status, text) = send(Method::POST, "/accounts/v1/devices", Some(token), Some(body))
        .await
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))?;
    if !(200..300).contains(&status) {
        return Err(failure(status, &text, None));
    }
    serde_json::from_str::<Value>(&text)
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))
}

/// Signs in and returns the session, reusing an existing device with the same public key.
#[no_mangle]
pub extern "C" fn mh_api_login(account: *const std::os::raw::c_char,
    public_key: *const std::os::raw::c_char, out: *mut std::os::raw::c_char, capacity: i32) -> i32 {
    let (Some(account), Some(public_key)) = (cstr(account), cstr(public_key)) else {
        return to_c(out, capacity, &json!({"ok": false, "error": "missing arguments"}));
    };

    let result = runtime().block_on(async move {
        let (token, expiry) = match fetch_token(&account).await {
            Ok(value) => value,
            Err(error) => return error,
        };
        let devices = match fetch_devices(&token).await {
            Ok(devices) => devices,
            Err(mut error) => {
                error["token"] = Value::String(token);
                return error;
            }
        };
        let existing = devices.iter().find(|device| {
            device.get("pubkey").and_then(Value::as_str) == Some(public_key.as_str())
        });
        let device = match existing {
            Some(device) => device.clone(),
            None => match create_device(&token, &public_key).await {
                Ok(device) => device,
                Err(mut error) => {
                    error["token"] = Value::String(token);
                    return error;
                }
            },
        };
        json!({
            "ok": true,
            "session": {
                "account": account,
                "token": token,
                "expiry": expiry,
                "deviceId": device.get("id").cloned().unwrap_or(Value::Null),
                "deviceName": device.get("name").cloned().unwrap_or(Value::Null),
                "ipv4": device.get("ipv4_address").cloned().unwrap_or(Value::Null),
                "ipv6": device.get("ipv6_address").cloned().unwrap_or(Value::Null),
                "publicKey": public_key,
            }
        })
    });

    to_c(out, capacity, &result)
}

#[no_mangle]
pub extern "C" fn mh_api_devices(token: *const std::os::raw::c_char,
    out: *mut std::os::raw::c_char, capacity: i32) -> i32 {
    let Some(token) = cstr(token) else {
        return to_c(out, capacity, &json!({"ok": false, "error": "missing token"}));
    };
    let result = runtime().block_on(async move {
        match fetch_devices(&token).await {
            Ok(devices) => json!({"ok": true, "devices": devices}),
            Err(error) => error,
        }
    });
    to_c(out, capacity, &result)
}

#[no_mangle]
pub extern "C" fn mh_api_remove_device(token: *const std::os::raw::c_char,
    device_id: *const std::os::raw::c_char, out: *mut std::os::raw::c_char, capacity: i32) -> i32 {
    let (Some(token), Some(device_id)) = (cstr(token), cstr(device_id)) else {
        return to_c(out, capacity, &json!({"ok": false, "error": "missing arguments"}));
    };
    let result = runtime().block_on(async move {
        let path = format!("/accounts/v1/devices/{device_id}");
        match send(Method::DELETE, &path, Some(&token), None).await {
            Ok((status, _text)) if (200..300).contains(&status) => json!({"ok": true}),
            Ok((status, text)) => failure(status, &text, None),
            Err(error) => json!({"ok": false, "code": "", "error": error.to_string()}),
        }
    });
    to_c(out, capacity, &result)
}

#[no_mangle]
pub extern "C" fn mh_api_account(token: *const std::os::raw::c_char,
    out: *mut std::os::raw::c_char, capacity: i32) -> i32 {
    let Some(token) = cstr(token) else {
        return to_c(out, capacity, &json!({"ok": false, "error": "missing token"}));
    };
    let result = runtime().block_on(async move {
        match send(Method::GET, "/accounts/v1/accounts/me", Some(&token), None).await {
            Ok((status, text)) if (200..300).contains(&status) => {
                match serde_json::from_str::<Value>(&text) {
                    Ok(value) => json!({"ok": true, "account": value}),
                    Err(error) => json!({"ok": false, "code": "", "error": error.to_string()}),
                }
            }
            Ok((status, text)) => failure(status, &text, None),
            Err(error) => json!({"ok": false, "code": "", "error": error.to_string()}),
        }
    });
    to_c(out, capacity, &result)
}


/// Fetches the relay list through the transparency log: the signed envelope gives the
/// content digest, and the content itself is fetched by that digest.
///
/// The sigsum signature is **not** verified yet (upstream logs verification failures and
/// continues). Until it is, the list is only trustworthy because it arrives over the same
/// authenticated path as the rest of the API.
async fn fetch_relay_list() -> Result<Value, Value> {
    let (status, envelope) = send(Method::GET, "/trl/v1/timestamps/latest", None, None)
        .await
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))?;
    if !(200..300).contains(&status) {
        return Err(failure(status, &envelope, None));
    }
    let payload = envelope.split("\n\n").next().unwrap_or_default().trim();
    let meta: Value = serde_json::from_str(payload)
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))?;
    let digest = meta
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| json!({"ok": false, "code": "", "error": "no digest in envelope"}))?
        .to_string();

    let (status, body) = send(Method::GET, &format!("/trl/v1/data/{digest}"), None, None)
        .await
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))?;
    if !(200..300).contains(&status) {
        return Err(failure(status, &body, None));
    }
    serde_json::from_str::<Value>(&body)
        .map_err(|error| json!({"ok": false, "code": "", "error": error.to_string()}))
}

/// Flattens the relay list into what a list screen needs, with country/city names resolved.
fn summarize_relays(list: &Value) -> Value {
    let locations = list.get("locations").and_then(Value::as_object);
    let mut relays: Vec<Value> = Vec::new();
    if let Some(entries) = list.pointer("/wireguard/relays").and_then(Value::as_array) {
        for relay in entries {
            let location = relay.get("location").and_then(Value::as_str).unwrap_or_default();
            let place = locations.and_then(|map| map.get(location));
            let city = place.and_then(|p| p.get("city")).and_then(Value::as_str).unwrap_or_default();
            let country =
                place.and_then(|p| p.get("country")).and_then(Value::as_str).unwrap_or_default();
            // Dedicated Shadowsocks addresses: the only IPv4 escape hatch when the
            // relay's own address is blackholed.
            let ss_extra: Vec<String> = relay
                .get("shadowsocks_extra_addr_in")
                .and_then(Value::as_array)
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|addr| !addr.contains(':'))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            // The API writes a feature key only on relays that implement it (`"lwo": {}`),
            // so presence is the capability flag. `lwo_v2` is superset of `lwo`.
            let quic = relay
                .pointer("/features/quic")
                .map(|quic| {
                    let addr: Vec<Value> = quic
                        .get("addr_in")
                        .and_then(Value::as_array)
                        .map(|items| items.iter().filter(|item| item.is_string()).cloned().collect())
                        .unwrap_or_default();
                    json!({
                        "addr": addr,
                        "token": quic.get("token").cloned().unwrap_or(Value::Null),
                        "domain": quic.get("domain").cloned().unwrap_or(Value::Null),
                    })
                })
                .unwrap_or(Value::Null);
            relays.push(json!({
                "hostname": relay.get("hostname").cloned().unwrap_or(Value::Null),
                "ssExtra": ss_extra,
                "ipv4": relay.get("ipv4_addr_in").cloned().unwrap_or(Value::Null),
                "ipv6": relay.get("ipv6_addr_in").cloned().unwrap_or(Value::Null),
                "publicKey": relay.get("public_key").cloned().unwrap_or(Value::Null),
                "location": location,
                "city": city,
                "country": country,
                "active": relay.get("active").cloned().unwrap_or(Value::Bool(false)),
                "owned": relay.get("owned").cloned().unwrap_or(Value::Bool(false)),
                // `features.daita` is current, top-level `daita` is the legacy shape.
                "daita": relay.pointer("/features/daita").cloned()
                    .or_else(|| relay.get("daita").cloned())
                    .unwrap_or(Value::Bool(false)),
                "lwo": relay.pointer("/features/lwo").is_some(),
                "lwoV2": relay.pointer("/features/lwo_v2").is_some(),
                "quic": quic,
            }));
        }
    }
    // Bridges are the only way in on a network that drops the relay IPs. They are a
    // separate list and speak Shadowsocks, not WireGuard.
    let mut bridges: Vec<Value> = Vec::new();
    if let Some(entries) = list.pointer("/bridge/relays").and_then(Value::as_array) {
        for relay in entries {
            let location = relay.get("location").and_then(Value::as_str).unwrap_or_default();
            let place = locations.and_then(|map| map.get(location));
            let city = place.and_then(|p| p.get("city")).and_then(Value::as_str).unwrap_or_default();
            let country =
                place.and_then(|p| p.get("country")).and_then(Value::as_str).unwrap_or_default();
            bridges.push(json!({
                "hostname": relay.get("hostname").cloned().unwrap_or(Value::Null),
                "ipv4": relay.get("ipv4_addr_in").cloned().unwrap_or(Value::Null),
                "location": location,
                "city": city,
                "country": country,
                "active": relay.get("active").cloned().unwrap_or(Value::Bool(false)),
            }));
        }
    }

    json!({ "relays": relays, "bridges": bridges })
}

#[no_mangle]
pub extern "C" fn mh_api_relays(out: *mut std::os::raw::c_char, capacity: i32) -> i32 {
    let result = runtime().block_on(async move {
        let list = match fetch_relay_list().await {
            Ok(list) => list,
            Err(error) => return error,
        };
        let summary = summarize_relays(&list);
        let Some(dir) = files_dir() else {
            return json!({"ok": false, "code": "", "error": "files directory unknown"});
        };
        let path = format!("{dir}/relays.json");
        match std::fs::write(&path, summary.to_string()) {
            Ok(()) => {
                let count = summary
                    .get("relays")
                    .and_then(Value::as_array)
                    .map(|relays| relays.len())
                    .unwrap_or(0);
                log_line(&format!("relay list written: {count} relays"));
                json!({"ok": true, "path": path, "count": count})
            }
            Err(error) => json!({"ok": false, "code": "", "error": error.to_string()}),
        }
    });
    to_c(out, capacity, &result)
}
