//! DAITA negotiation with a relay's tunnel config service.
//!
//! The config service is a plaintext gRPC endpoint at `10.64.0.1:1337`, reachable only
//! *through* a working tunnel: the extension opens an unprotected TCP socket after the
//! tunnel is up, the socket is routed into the tun, and gotatun carries it to the ingress
//! relay. There is no userspace network stack here — the real tunnel is the network.
//!
//! Upstream (`talpid-tunnel-config-client`) uses tonic/prost. Neither is available on
//! this target, and the message set is two small messages, so the protobuf wire format
//! and the gRPC framing are written by hand below. The encoding follows proto3: scalar
//! fields with their default value are not emitted, which is also what prost does.

use std::ffi::CStr;
use std::io;
use std::os::fd::FromRawFd;
use std::os::raw::{c_char, c_int};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use gotatun::device::daita::{DaitaSettings, Machine};
use h2::client;
use http::{header, Method, Request};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{api::runtime, log_line, write_out};

/// Address of the config service inside every Mullvad tunnel.
pub(crate) const CONFIG_HOST: &str = "10.64.0.1";
/// The only port the relay's config service listens on.
pub(crate) const CONFIG_PORT: u16 = 1337;
/// Full path of the `RegisterPeerV1` RPC.
const GRPC_PATH: &str = "/ephemeralpeer.EphemeralPeer/RegisterPeerV1";
/// DAITA v2 is the protocol version the server expects from this client.
const DAITA_VERSION: u64 = 2;
/// `DaitaPlatform.linux_wg_go`. OpenHarmony has no enum value of its own; the client is
/// gotatun, whose shaping matches the wg-go implementations, and the server only uses
/// this to pick a machine set.
const DAITA_PLATFORM_LINUX_WG_GO: u64 = 2;
/// How long the whole exchange may take. A tunnel that cannot reach its own gateway
/// within this window is not going to be fixed by waiting longer.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(20);

/// What the config service returned for DAITA.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NegotiatedDaita {
    /// Serialized maybenot machines, in the order the server returned them.
    pub machines: Vec<String>,
    /// `max_padding_frac` in the proto: bandwidth allowed for decoy packets.
    pub max_padding: f64,
    /// `max_blocking_frac` in the proto: bandwidth allowed for delayed packets.
    pub max_blocking: f64,
}

impl NegotiatedDaita {
    /// Builds the settings `Peer::with_daita` takes.
    pub(crate) fn settings(&self) -> Result<DaitaSettings, String> {
        if self.machines.is_empty() {
            return Err("the config service returned no maybenot machines".to_string());
        }
        let machines = self
            .machines
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                raw.parse::<Machine>()
                    .map_err(|error| format!("DAITA machine {}: {error}", index + 1))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let max_decoy_frac = check_fraction("max_padding_frac", self.max_padding)?;
        let max_delay_frac = check_fraction("max_blocking_frac", self.max_blocking)?;
        Ok(DaitaSettings {
            maybenot_machines: machines,
            max_decoy_frac,
            max_delay_frac,
            max_delayed_packets: std::num::NonZeroUsize::new(1024).expect("non-zero"),
            min_delay_capacity: 50,
        })
    }
}

fn check_fraction(name: &str, value: f64) -> Result<f64, String> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(format!("config service returned {name}={value}, expected a fraction in [0,1]"))
    }
}

// ---------------------------------------------------------------------------
// Protobuf encoding: EphemeralPeerRequestV1 / DaitaRequestV2
// ---------------------------------------------------------------------------

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn push_tag(out: &mut Vec<u8>, field: u32, wire: u8) {
    push_varint(out, ((field as u64) << 3) | u64::from(wire));
}

fn push_bytes(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    push_tag(out, field, 2);
    push_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn push_uint(out: &mut Vec<u8>, field: u32, value: u64) {
    push_tag(out, field, 0);
    push_varint(out, value);
}

/// Encodes `EphemeralPeerRequestV1` with a `DaitaRequestV2` in field 5.
///
/// No post-quantum material is requested: that needs ML-KEM and HQC key exchange, which
/// is a different unit. DAITA alone is what this client negotiates.
pub(crate) fn encode_request(parent_pubkey: &[u8; 32], ephemeral_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut daita = Vec::new();
    push_uint(&mut daita, 1, DAITA_VERSION);
    push_uint(&mut daita, 2, DAITA_PLATFORM_LINUX_WG_GO);
    // Field 3 (`level`) is `level_default = 0`, the proto3 default, so it is omitted.

    let mut out = Vec::with_capacity(2 * (1 + 1 + 32) + 2 + daita.len());
    push_bytes(&mut out, 1, parent_pubkey);
    push_bytes(&mut out, 2, ephemeral_pubkey);
    push_bytes(&mut out, 5, &daita);
    out
}

// ---------------------------------------------------------------------------
// Protobuf decoding: EphemeralPeerResponseV1 / DaitaResponseV2
// ---------------------------------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or_else(|| "truncated varint".to_string())?;
            self.position += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("varint is longer than 10 bytes".to_string())
    }

    fn tag(&mut self) -> Result<(u32, u8), String> {
        let tag = self.varint()?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        if field == 0 {
            return Err("protobuf field 0 is invalid".to_string());
        }
        Ok((field, wire))
    }

    fn length_delimited(&mut self) -> Result<&'a [u8], String> {
        let length = self.varint()? as usize;
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| "protobuf length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err(format!(
                "truncated length-delimited field: want {length} B, have {}",
                self.bytes.len() - self.position
            ));
        }
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn fixed64(&mut self) -> Result<u64, String> {
        let end = self.position + 8;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| "truncated fixed64".to_string())?;
        self.position = end;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(slice);
        Ok(u64::from_le_bytes(bytes))
    }

    fn double(&mut self) -> Result<f64, String> {
        Ok(f64::from_bits(self.fixed64()?))
    }

    /// Skips a field this client does not know, so new server fields stay compatible.
    fn skip(&mut self, wire: u8) -> Result<(), String> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => {
                self.fixed64()?;
            }
            2 => {
                self.length_delimited()?;
            }
            5 => {
                let end = self.position + 4;
                if self.bytes.get(self.position..end).is_none() {
                    return Err("truncated fixed32".to_string());
                }
                self.position = end;
            }
            other => return Err(format!("unsupported protobuf wire type {other}")),
        }
        Ok(())
    }
}

fn decode_daita_response(bytes: &[u8]) -> Result<NegotiatedDaita, String> {
    let mut reader = Reader::new(bytes);
    let mut machines = Vec::new();
    let mut max_padding = 0.0f64;
    let mut max_blocking = 0.0f64;
    while !reader.is_empty() {
        let (field, wire) = reader.tag()?;
        match (field, wire) {
            // repeated string client_machines = 1
            (1, 2) => {
                let raw = reader.length_delimited()?;
                let machine = std::str::from_utf8(raw)
                    .map_err(|error| format!("DAITA machine is not UTF-8: {error}"))?;
                machines.push(machine.to_string());
            }
            // double max_padding_frac = 2
            (2, 1) => max_padding = reader.double()?,
            // double max_blocking_frac = 3
            (3, 1) => max_blocking = reader.double()?,
            _ => reader.skip(wire)?,
        }
    }
    let negotiated = NegotiatedDaita {
        machines,
        max_padding,
        max_blocking,
    };
    // Validate here rather than at device build: a bad fraction is a bad response, and
    // the caller should not restart a tunnel with it.
    check_fraction("max_padding_frac", negotiated.max_padding)?;
    check_fraction("max_blocking_frac", negotiated.max_blocking)?;
    Ok(negotiated)
}

/// Decodes `EphemeralPeerResponseV1`, returning the DAITA part.
///
/// Post-quantum ciphertexts (field 1) are skipped: this client does not request them.
pub(crate) fn decode_response(bytes: &[u8]) -> Result<NegotiatedDaita, String> {
    let mut reader = Reader::new(bytes);
    let mut daita: Option<NegotiatedDaita> = None;
    while !reader.is_empty() {
        let (field, wire) = reader.tag()?;
        if field == 2 && wire == 2 {
            let inner = reader.length_delimited()?;
            daita = Some(decode_daita_response(inner)?);
        } else {
            reader.skip(wire)?;
        }
    }
    daita.ok_or_else(|| "config service response carries no DAITA settings".to_string())
}

// ---------------------------------------------------------------------------
// gRPC framing
// ---------------------------------------------------------------------------

/// Prefixes one message with the gRPC length-prefixed message header.
pub(crate) fn encode_grpc_message(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("gRPC message fits in u32");
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(0); // compressed flag: 0 = not compressed
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Splits a gRPC body into its messages. Multiple messages are legal; the call here
/// returns the first, but the parser is kept general so a trial response is readable.
pub(crate) fn decode_grpc_body(mut data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut messages = Vec::new();
    while !data.is_empty() {
        if data.len() < 5 {
            return Err(format!("truncated gRPC header: {} trailing bytes", data.len()));
        }
        let compressed = data[0];
        if compressed != 0 {
            return Err("compressed gRPC messages are not supported".to_string());
        }
        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        let end = 5 + length;
        if data.len() < end {
            return Err(format!(
                "truncated gRPC message: header says {length} B, body has {}",
                data.len() - 5
            ));
        }
        messages.push(data[5..end].to_vec());
        data = &data[end..];
    }
    Ok(messages)
}

// ---------------------------------------------------------------------------
// The exchange
// ---------------------------------------------------------------------------

async fn negotiate_over_stream(
    stream: TcpStream,
    parent_pubkey: [u8; 32],
    ephemeral_pubkey: [u8; 32],
) -> Result<NegotiatedDaita, String> {
    stream
        .set_nodelay(true)
        .map_err(|error| format!("config service TCP_NODELAY: {error}"))?;
    let (mut sender, connection) = client::handshake(stream)
        .await
        .map_err(|error| format!("config service h2 handshake: {error}"))?;
    // The connection future drives every frame; without it the request never leaves.
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            log_line(&format!("daita: config service h2 connection closed: {error}"));
        }
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{CONFIG_HOST}:{CONFIG_PORT}{GRPC_PATH}"))
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::TE, "trailers")
        .header(header::USER_AGENT, "yanou-daita/1")
        .body(())
        .map_err(|error| format!("config service request: {error}"))?;
    let (response_future, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|error| format!("config service request: {error}"))?;

    let body = encode_grpc_message(&encode_request(&parent_pubkey, &ephemeral_pubkey));
    send_stream
        .send_data(Bytes::from(body), true)
        .map_err(|error| format!("config service request body: {error}"))?;

    let response = response_future
        .await
        .map_err(|error| format!("config service response: {error}"))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    if status != 200 {
        let message = headers
            .get("grpc-message")
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .unwrap_or_default();
        return Err(format!("config service answered HTTP {status}: {message}"));
    }

    // Collect DATA frames. The server may split the framed message over several frames.
    let mut body = response.into_body();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|error| format!("config service body: {error}"))?;
        data.extend_from_slice(&chunk);
    }
    let trailers = body
        .trailers()
        .await
        .map_err(|error| format!("config service trailers: {error}"))?;

    // grpc-status is normally a trailer; tolerate it in the headers as well.
    let grpc_status = trailers
        .as_ref()
        .and_then(|trailers| trailers.get("grpc-status"))
        .or_else(|| headers.get("grpc-status"));
    if let Some(status) = grpc_status {
        let status = status
            .to_str()
            .map_err(|error| format!("config service grpc-status: {error}"))?;
        if status.trim() != "0" {
            let message = trailers
                .as_ref()
                .and_then(|trailers| trailers.get("grpc-message"))
                .or_else(|| headers.get("grpc-message"))
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .unwrap_or_default();
            return Err(format!("config service RPC failed with grpc-status {status}: {message}"));
        }
    }

    log_line(&format!("daita: config service response {} B", data.len()));
    let messages = decode_grpc_body(&data)?;
    let first = messages
        .first()
        .ok_or_else(|| "config service returned an empty gRPC body".to_string())?;
    decode_response(first)
}

/// Duplicates the extension's TCP fd so the system-owned original stays valid.
///
/// `getSocketFd()` returns a descriptor the ArkTS socket owns and closes; taking it over
/// would double-close it, so the native side reads and writes a dup.
fn duplicate_stream(fd: c_int) -> Result<std::net::TcpStream, String> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(format!("dup({fd}): {}", io::Error::last_os_error()));
    }
    // SAFETY: `duplicated` is a fresh descriptor owned by this function from here on.
    Ok(unsafe { std::net::TcpStream::from_raw_fd(duplicated) })
}

fn decode_key(encoded: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|error| format!("{what}: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!("{what}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn cstr(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
}

/// Writes JSON to a caller buffer, refusing to truncate it.
fn write_json(out: *mut c_char, capacity: c_int, value: &Value) -> c_int {
    let text = value.to_string();
    if out.is_null() || capacity <= 0 {
        return -1;
    }
    if text.len() + 1 > capacity as usize {
        // A truncated JSON object would be unparseable on the ArkTS side. Replace it with
        // a complete error object small enough to fit.
        let fallback = json!({
            "ok": false,
            "error": "DAITA negotiation result is larger than the caller buffer"
        })
        .to_string();
        return write_out(out, capacity, &fallback);
    }
    write_out(out, capacity, &text)
}

/// Negotiates a DAITA peer with the relay's config service through an existing tunnel.
///
/// * `fd` — connected TCP socket to `10.64.0.1:1337`, created by the extension without
///   `protect()` so it enters the tun (see `VpnExtensionAbility.negotiateDaita`).
/// * `parent_pubkey` — base64 public key of the running tunnel (the registered device key).
/// * `ephemeral_pubkey` — base64 public key the ephemeral peer should use. Empty means
///   “generate one here”; the private key is then returned as `ephemeralKey`, to be passed
///   back to `tunnelStart`. It is a throwaway session key, never persisted.
///
/// Answers `{"ok":true,"psk":"","machines":[...],"maxPadding":x,"maxBlocking":y,
/// "ephemeralKey":"<base64>","ephemeralPublicKey":"<base64>"}` or `{"ok":false,"error":...}`.
#[no_mangle]
pub extern "C" fn mh_negotiate_daita(
    fd: c_int,
    parent_pubkey: *const c_char,
    ephemeral_pubkey: *const c_char,
    out: *mut c_char,
    capacity: c_int,
) -> c_int {
    let (Some(parent_text), Some(ephemeral_text)) = (cstr(parent_pubkey), cstr(ephemeral_pubkey))
    else {
        return write_json(
            out,
            capacity,
            &json!({"ok": false, "error": "missing parent or ephemeral public key"}),
        );
    };
    if fd < 0 {
        return write_json(
            out,
            capacity,
            &json!({"ok": false, "error": "no config service socket"}),
        );
    }

    let parent = match decode_key(&parent_text, "parent public key") {
        Ok(key) => key,
        Err(error) => return write_json(out, capacity, &json!({"ok": false, "error": error})),
    };

    // Generate the ephemeral keypair unless the caller supplied its public half. The
    // private key never leaves the process except as the session handoff string below.
    let (ephemeral_secret, ephemeral_public, generated) = if ephemeral_text.trim().is_empty() {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        (Some(secret), public, true)
    } else {
        match decode_key(&ephemeral_text, "ephemeral public key") {
            Ok(bytes) => (None, PublicKey::from(bytes), false),
            Err(error) => return write_json(out, capacity, &json!({"ok": false, "error": error})),
        }
    };
    let ephemeral_private = ephemeral_secret.as_ref().map(|secret| {
        base64::engine::general_purpose::STANDARD.encode(secret.to_bytes())
    });
    let ephemeral_public_b64 =
        base64::engine::general_purpose::STANDARD.encode(ephemeral_public.as_bytes());

    log_line(&format!(
        "daita: negotiating via {CONFIG_HOST}:{CONFIG_PORT} \
         (parent {}, ephemeral {}, {})",
        &parent_text[..parent_text.len().min(8)],
        &ephemeral_public_b64[..ephemeral_public_b64.len().min(8)],
        if generated { "generated keypair" } else { "caller-supplied key" }
    ));

    let outcome = runtime().block_on(async move {
        let stream = duplicate_stream(fd)?;
        stream
            .set_nonblocking(true)
            .map_err(|error| format!("config service socket nonblocking: {error}"))?;
        let stream = TcpStream::from_std(stream)
            .map_err(|error| format!("config service socket: {error}"))?;
        tokio::time::timeout(
            NEGOTIATION_TIMEOUT,
            negotiate_over_stream(stream, parent, *ephemeral_public.as_bytes()),
        )
        .await
        .map_err(|_| {
            format!(
                "config service did not answer within {} s",
                NEGOTIATION_TIMEOUT.as_secs()
            )
        })?
    });

    let result = match outcome {
        Ok(negotiated) => {
            // Parse the machines here as well: a response that cannot become a
            // `DaitaSettings` is a failed negotiation, not something to restart into.
            match negotiated.settings() {
                Ok(_) => {
                    log_line(&format!(
                        "daita: relay returned {} machine(s), max padding {:.3}, max blocking {:.3}",
                        negotiated.machines.len(),
                        negotiated.max_padding,
                        negotiated.max_blocking
                    ));
                    let payload = json!({
                        "ok": true,
                        // DAITA alone does not get a PSK; the field is left empty so the
                        // caller has one shape whether PQ is negotiated later or not.
                        "psk": "",
                        "machines": negotiated.machines,
                        "maxPadding": negotiated.max_padding,
                        "maxBlocking": negotiated.max_blocking,
                        // The private half is handed back only because the core is
                        // stateless between NAPI calls; it is a throwaway session key.
                        "ephemeralKey": ephemeral_private.unwrap_or_default(),
                        "ephemeralPublicKey": ephemeral_public_b64,
                        "platform": DAITA_PLATFORM_LINUX_WG_GO,
                        "version": DAITA_VERSION,
                    });
                    write_json(out, capacity, &payload)
                }
                Err(error) => {
                    log_line(&format!("daita: unusable relay config: {error}"));
                    write_json(out, capacity, &json!({"ok": false, "error": error}))
                }
            }
        }
        Err(error) => {
            log_line(&format!("daita: negotiation failed: {error}"));
            write_json(out, capacity, &json!({"ok": false, "error": error}))
        }
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn double_bytes(value: f64) -> [u8; 8] {
        value.to_bits().to_le_bytes()
    }

    #[test]
    fn request_matches_a_hand_built_protobuf_vector() {
        let parent = [0xaa; 32];
        let ephemeral = [0xbb; 32];
        let encoded = encode_request(&parent, &ephemeral);

        // field 1, wire 2 (bytes): tag 0x0a, len 32, key
        // field 2, wire 2 (bytes): tag 0x12, len 32, key
        // field 5, wire 2 (message): tag 0x2a, len 4
        //   DaitaRequestV2: field 1 varint version=2 -> 0x08 0x02
        //                   field 2 varint platform=2 -> 0x10 0x02
        // Level (field 3) is level_default=0 and is therefore not on the wire.
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x0a, 0x20]);
        expected.extend_from_slice(&parent);
        expected.extend_from_slice(&[0x12, 0x20]);
        expected.extend_from_slice(&ephemeral);
        expected.extend_from_slice(&[0x2a, 0x04, 0x08, 0x02, 0x10, 0x02]);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn response_decodes_machines_and_both_doubles() {
        let mut daita = Vec::new();
        for machine in ["02eNpjYEAHjOgCAAA0AAI=", "02-second-machine"] {
            daita.push(0x0a); // field 1, wire 2
            daita.push(machine.len() as u8);
            daita.extend_from_slice(machine.as_bytes());
        }
        daita.push(0x11); // field 2, wire 1 (fixed64)
        daita.extend_from_slice(&double_bytes(0.25));
        daita.push(0x19); // field 3, wire 1 (fixed64)
        daita.extend_from_slice(&double_bytes(0.75));

        let mut response = Vec::new();
        // post_quantum (field 1) is skipped even though no PQ was requested.
        response.extend_from_slice(&[0x0a, 0x03, 0x01, 0x02, 0x03]);
        // daita (field 2)
        response.push(0x12);
        response.push(daita.len() as u8);
        response.extend_from_slice(&daita);
        // unknown field 9, varint: tag 0x48, value 1
        response.extend_from_slice(&[0x48, 0x01]);

        let decoded = decode_response(&response).expect("decode response");
        assert_eq!(
            decoded.machines,
            vec!["02eNpjYEAHjOgCAAA0AAI=".to_string(), "02-second-machine".to_string()]
        );
        assert_eq!(decoded.max_padding.to_bits(), 0.25f64.to_bits());
        assert_eq!(decoded.max_blocking.to_bits(), 0.75f64.to_bits());
    }

    #[test]
    fn response_decoder_accepts_negative_zero_and_boundaries() {
        for (padding, blocking) in [(0.0f64, 0.0f64), (1.0, 1.0), (-0.0, 0.5)] {
            let mut daita = Vec::new();
            daita.extend_from_slice(&[0x0a, 0x01, b'm']);
            daita.push(0x11);
            daita.extend_from_slice(&double_bytes(padding));
            daita.push(0x19);
            daita.extend_from_slice(&double_bytes(blocking));
            let mut response = vec![0x12, daita.len() as u8];
            response.extend_from_slice(&daita);

            let decoded = decode_response(&response).expect("boundary fractions");
            assert_eq!(decoded.max_padding.to_bits(), padding.to_bits());
            assert_eq!(decoded.max_blocking.to_bits(), blocking.to_bits());
        }
    }

    #[test]
    fn response_decoder_rejects_invalid_fractions() {
        for invalid in [f64::NAN, f64::INFINITY, -0.5, 1.5] {
            let mut daita = Vec::new();
            daita.extend_from_slice(&[0x0a, 0x01, b'm']);
            daita.push(0x11);
            daita.extend_from_slice(&double_bytes(invalid));
            daita.push(0x19);
            daita.extend_from_slice(&double_bytes(0.5));
            let mut response = vec![0x12, daita.len() as u8];
            response.extend_from_slice(&daita);
            assert!(decode_response(&response).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn response_decoder_requires_the_daita_message() {
        // Only an (empty) post_quantum field.
        let response = [0x0a, 0x00];
        let error = decode_response(&response).expect_err("no daita");
        assert!(error.contains("no DAITA settings"), "unexpected error: {error}");
    }

    #[test]
    fn response_decoder_rejects_truncated_fields() {
        assert!(decode_response(&[0x12, 0x05, 0x0a]).is_err());
        // Declared length runs past the end of the message.
        assert!(decode_response(&[0x0a, 0x08, 0x00]).is_err());
    }

    #[test]
    fn grpc_framing_roundtrips_one_and_many_messages() {
        let one = encode_grpc_message(&[1, 2, 3]);
        assert_eq!(one, vec![0, 0, 0, 0, 3, 1, 2, 3]);
        assert_eq!(decode_grpc_body(&one).expect("one"), vec![vec![1, 2, 3]]);

        let mut many = encode_grpc_message(b"first");
        many.extend_from_slice(&encode_grpc_message(b"second"));
        assert_eq!(
            decode_grpc_body(&many).expect("many"),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn grpc_framing_rejects_truncated_and_compressed_messages() {
        assert!(decode_grpc_body(&[0, 0, 0]).is_err());
        assert!(decode_grpc_body(&[0, 0, 0, 0, 4, 1]).is_err());
        // Compressed flag 1.
        assert!(decode_grpc_body(&[1, 0, 0, 0, 1, 0]).is_err());
    }

    #[test]
    fn negotiated_settings_reject_zero_machines() {
        let negotiated = NegotiatedDaita {
            machines: vec![],
            max_padding: 0.1,
            max_blocking: 0.1,
        };
        assert!(negotiated.settings().is_err());
    }
}
