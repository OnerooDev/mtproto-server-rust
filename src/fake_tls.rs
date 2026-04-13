//! FakeTLS (secret prefix "ee") handshake handling.
//!
//! Telegram clients wrap MTProto in a fake TLS 1.3 ClientHello when using
//! FakeTLS secrets. The proxy must:
//!  1. Read the TLS ClientHello from the client.
//!  2. Validate the HMAC-SHA256 in the random field using the user secret.
//!  3. Send back a synthetic TLS ServerHello + ChangeCipherSpec + fake AppData.
//!     The ServerHello random is HMAC-SHA256(secret, client_random ‖ full_response_with_server_random_zeroed)
//!     (see TDLib `td/mtproto/TlsInit.cpp::wait_hello_response`).
//!  4. From that point on, all data is wrapped in TLS 1.3 ApplicationData records
//!     (type 0x17, version 0x0303, 2-byte length), but the inner content is plain
//!     obfuscated MTProto.

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

pub const TLS_RECORD_HEADER: usize = 5; // type(1) + version(2) + length(2)
pub const TLS_APP_DATA: u8 = 0x17;
pub const TLS_VERSION: [u8; 2] = [0x03, 0x03];

/// Max plaintext bytes per `ApplicationData` record toward the client (TDLib / mtcute).
/// Larger records can cause Telegram clients to drop the connection.
pub const FAKETLS_MAX_APP_DATA_INNER: usize = 2878;

/// Random field position inside a TLS ClientHello record.
/// record_type(1) + version(2) + size(2) + handshake_type(1) + uint24_length(3) + client_version(2)
const RANDOM_POS: usize = 1 + 2 + 2 + 1 + 3 + 2;
const RANDOM_LEN: usize = 32;

const GREASE_MASK: u16 = 0x0f0f;
const GREASE_VALUE_TYPE: u16 = 0x0a0a;
const EXT_TYPE_SNI: [u8; 2] = [0x00, 0x00];

#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    pub _random: [u8; RANDOM_LEN],
    pub _session_id: Vec<u8>,
    pub cipher_suite: u16,
}

/// Read a full TLS ClientHello. Returns the raw bytes.
pub async fn read_client_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut hdr = [0u8; TLS_RECORD_HEADER];
    r.read_exact(&mut hdr).await?;
    if hdr[0] != 0x16 {
        bail!("not a TLS handshake record (got 0x{:02x})", hdr[0]);
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;

    let mut full = hdr.to_vec();
    full.extend_from_slice(&payload);
    Ok(full)
}

/// Validate the FakeTLS ClientHello according to mtg:
/// - compute HMAC(secret, client_hello_with_random_zeroed)
/// - XOR digest with the original client random
/// - result must be all-zero except last 4 bytes which are little-endian UNIX timestamp
/// - timestamp must be within a tolerance window
pub fn validate_hello_hmac(hello: &[u8], secret: &[u8]) -> Result<()> {
    const DEFAULT_SKEW_SECS: i64 = 300; // 5 minutes
    validate_hello_hmac_with_skew(hello, secret, DEFAULT_SKEW_SECS)
}

pub fn validate_hello_hmac_with_skew(hello: &[u8], secret: &[u8], skew_secs: i64) -> Result<()> {
    if hello.len() < RANDOM_POS + RANDOM_LEN {
        bail!("ClientHello too short");
    }

    let client_random = &hello[RANDOM_POS..RANDOM_POS + RANDOM_LEN];
    let mut msg = hello.to_vec();
    msg[RANDOM_POS..RANDOM_POS + RANDOM_LEN].fill(0);

    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
    mac.update(&msg);
    let mut computed = mac.finalize().into_bytes()[..RANDOM_LEN].to_vec();
    for (c, r) in computed.iter_mut().zip(client_random.iter()) {
        *c ^= *r;
    }

    if computed[..RANDOM_LEN - 4].iter().any(|&b| b != 0) {
        debug!(
            key = %hex::encode(secret),
            "FakeTLS digest mismatch (mtg-style)"
        );
        bail!("FakeTLS HMAC mismatch");
    }

    let ts = u32::from_le_bytes(computed[RANDOM_LEN - 4..].try_into().unwrap()) as i64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if (now - ts).abs() > skew_secs {
        bail!("FakeTLS timestamp skew too large: ts={ts} now={now}");
    }

    Ok(())
}

/// Parse parts of ClientHello needed for ServerHello mirroring.
/// Returns (info, list_of_sni_hostnames_lowercased).
pub fn parse_client_hello(hello: &[u8]) -> Result<(ClientHelloInfo, Vec<String>)> {
    if hello.len() < TLS_RECORD_HEADER + 1 + 3 + 2 + RANDOM_LEN + 1 {
        bail!("ClientHello too short");
    }
    if hello[0] != 0x16 {
        bail!("not a TLS handshake record");
    }
    if hello[5] != 0x01 {
        bail!("not a ClientHello handshake");
    }

    let mut i = TLS_RECORD_HEADER;
    i += 1; // handshake type
    i += 3; // handshake len (uint24)
    i += 2; // client version

    let random: [u8; RANDOM_LEN] = hello[i..i + RANDOM_LEN].try_into().unwrap();
    i += RANDOM_LEN;

    let sid_len = hello[i] as usize;
    i += 1;
    if hello.len() < i + sid_len + 2 {
        bail!("ClientHello truncated (session id)");
    }
    let session_id = hello[i..i + sid_len].to_vec();
    i += sid_len;

    let cipher_suites_len = u16::from_be_bytes(hello[i..i + 2].try_into().unwrap()) as usize;
    i += 2;
    if hello.len() < i + cipher_suites_len + 1 {
        bail!("ClientHello truncated (cipher suites)");
    }
    let cipher_suites = &hello[i..i + cipher_suites_len];
    i += cipher_suites_len;

    let mut cipher_suite: u16 = 0;
    for cs in cipher_suites.chunks(2) {
        if cs.len() != 2 {
            continue;
        }
        let v = u16::from_be_bytes([cs[0], cs[1]]);
        if v & GREASE_MASK == GREASE_VALUE_TYPE {
            continue;
        }
        cipher_suite = v;
        break;
    }
    if cipher_suite == 0 {
        bail!("cannot find a non-GREASE cipher suite");
    }

    let comp_methods_len = hello[i] as usize;
    i += 1 + comp_methods_len;
    if hello.len() < i + 2 {
        bail!("ClientHello truncated (extensions len)");
    }
    let exts_len = u16::from_be_bytes(hello[i..i + 2].try_into().unwrap()) as usize;
    i += 2;
    if hello.len() < i + exts_len {
        bail!("ClientHello truncated (extensions)");
    }
    let exts = &hello[i..i + exts_len];

    let sni_hosts = parse_sni_hosts(exts)?;

    Ok((
        ClientHelloInfo {
            _random: random,
            _session_id: session_id,
            cipher_suite,
        },
        sni_hosts,
    ))
}

fn parse_sni_hosts(exts: &[u8]) -> Result<Vec<String>> {
    let mut i = 0usize;
    while i + 4 <= exts.len() {
        let ext_type = &exts[i..i + 2];
        let ext_len = u16::from_be_bytes(exts[i + 2..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + ext_len > exts.len() {
            break;
        }
        let ext_data = &exts[i..i + ext_len];
        i += ext_len;

        if ext_type != EXT_TYPE_SNI {
            continue;
        }

        if ext_data.len() < 2 {
            return Ok(vec![]);
        }
        let list_len = u16::from_be_bytes(ext_data[0..2].try_into().unwrap()) as usize;
        if ext_data.len() < 2 + list_len || list_len < 3 {
            return Ok(vec![]);
        }
        let mut j = 2usize;
        let list = &ext_data[2..2 + list_len];
        let mut out = vec![];
        while j + 3 <= list.len() {
            let name_type = list[j];
            j += 1;
            let name_len = u16::from_be_bytes(list[j..j + 2].try_into().unwrap()) as usize;
            j += 2;
            if j + name_len > list.len() {
                break;
            }
            if name_type == 0 {
                let name = &list[j..j + name_len];
                if let Ok(s) = std::str::from_utf8(name) {
                    out.push(s.to_ascii_lowercase());
                }
            }
            j += name_len;
        }
        return Ok(out);
    }
    Ok(vec![])
}

/// Extract the session_id bytes from a ClientHello (for mirroring back in ServerHello).
/// Layout: 5 (record hdr) + 1 (hs type) + 3 (hs len) + 2 (ver) + 32 (random) = 43
/// Byte 43: session_id length; bytes 44..44+len: session_id
pub fn extract_session_id(hello: &[u8]) -> &[u8] {
    if hello.len() < 44 {
        return &[];
    }
    let sid_len = hello[43] as usize;
    let end = 44 + sid_len;
    if hello.len() < end {
        return &[];
    }
    &hello[44..end]
}

fn build_server_hello_record_zeroed(session_id: &[u8], cipher_suite: u16) -> Vec<u8> {
    // Mirrors mtg fake-tls `server_side.go`.
    // ServerHello handshake payload:
    // - legacy_version(2)
    // - random(32) = zeros (will be overwritten by HMAC)
    // - session_id_len + session_id
    // - cipher_suite(2)
    // - serverHelloSuffix + x25519 public key (32 bytes)

    // serverHelloSuffix from mtg (46 bytes) + x25519 key (32 bytes)
    const SERVER_HELLO_SUFFIX: &[u8] = &[
        0x00, // no compression
        0x00, 0x2e, // 46 bytes
        0x00, 0x2b, // supported_versions
        0x00, 0x02, // 2 bytes
        0x03, 0x04, // TLS 1.3
        0x00, 0x33, // key_share
        0x00, 0x24, // 36 bytes
        0x00, 0x1d, // x25519
        0x00, 0x20, // 32 bytes key
    ];

    let mut hs_payload = Vec::new();
    hs_payload.extend_from_slice(&TLS_VERSION);
    hs_payload.extend_from_slice(&[0u8; RANDOM_LEN]);
    hs_payload.push(session_id.len() as u8);
    hs_payload.extend_from_slice(session_id);
    hs_payload.extend_from_slice(&cipher_suite.to_be_bytes());
    hs_payload.extend_from_slice(SERVER_HELLO_SUFFIX);

    // x25519 public key
    let mut scalar_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut scalar_bytes);
    let secret = StaticSecret::from(scalar_bytes);
    let pubkey = PublicKey::from(&secret);
    hs_payload.extend_from_slice(pubkey.as_bytes());

    // Handshake wrapper: type(1) + uint24_len(3) + payload
    let hs_len = hs_payload.len() as u32;
    let mut handshake = Vec::new();
    handshake.push(0x02); // ServerHello
    handshake.push(((hs_len >> 16) & 0xff) as u8);
    handshake.push(((hs_len >> 8) & 0xff) as u8);
    handshake.push((hs_len & 0xff) as u8);
    handshake.extend_from_slice(&hs_payload);

    // TLS record: type(1) + version(2) + len(2) + handshake
    let rec_len = handshake.len() as u16;
    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&TLS_VERSION);
    record.extend_from_slice(&rec_len.to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Build ServerHello + CCS + first ApplicationData per TDLib `wait_hello_response`:
/// `HMAC-SHA256(secret, client_random ‖ response_with_server_random_zeroed)`.
fn build_faketls_server_flight(
    client_hello: &[u8],
    session_id: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>> {
    if client_hello.len() < RANDOM_POS + RANDOM_LEN {
        bail!("ClientHello too short for server flight");
    }

    // Parse client hello to mirror cipher suite and (optionally) validate SNI elsewhere.
    let (info, _) = parse_client_hello(client_hello).context("parse ClientHello")?;

    let sh_record = build_server_hello_record_zeroed(session_id, info.cipher_suite);
    const CCS: &[u8] = &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

    // Noise: exactly ONE ApplicationData record, random size in 2500–4700 range (mtg legacy).
    let size = 2500 + (rand::thread_rng().gen::<u16>() as usize % 2200);
    let mut noise = vec![0u8; size];
    rand::thread_rng().fill(&mut noise[..]);
    let app_record = wrap_app_data(&noise);

    let mut full = Vec::new();
    full.extend_from_slice(&sh_record);
    full.extend_from_slice(CCS);
    full.extend_from_slice(&app_record);

    // mtg: HMAC(secret, client_random || packet_with_zero_random) and write into server random.
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| anyhow::anyhow!("HMAC init: {e}"))?;
    mac.update(&client_hello[RANDOM_POS..RANDOM_POS + RANDOM_LEN]);
    full[RANDOM_POS..RANDOM_POS + RANDOM_LEN].fill(0);
    mac.update(&full);
    let hmac_out = mac.finalize().into_bytes();
    full[RANDOM_POS..RANDOM_POS + RANDOM_LEN].copy_from_slice(&hmac_out[..RANDOM_LEN]);

    Ok(full)
}

/// Send ServerHello + ChangeCipherSpec + fake ApplicationData (TDLib-compatible).
pub async fn send_server_hello<W: AsyncWrite + Unpin>(
    w: &mut W,
    domain: &str,
    client_hello: &[u8],
    session_id: &[u8],
    secret: &[u8],
) -> Result<()> {
    // Optional: ensure SNI contains expected hostname (mtg behavior).
    let (_info, sni_hosts) = parse_client_hello(client_hello).context("parse ClientHello")?;
    if !sni_hosts.is_empty() && !sni_hosts.iter().any(|h| h == &domain.to_ascii_lowercase()) {
        bail!("FakeTLS SNI mismatch (expected {domain}, got {sni_hosts:?})");
    }

    let flight = build_faketls_server_flight(client_hello, session_id, secret)?;
    w.write_all(&flight).await?;
    w.flush().await?;
    debug!("send_server_hello: sent ServerHello + CCS + fake AppData");
    Ok(())
}

/// Wrap `data` in a TLS ApplicationData record.
pub fn wrap_app_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TLS_RECORD_HEADER + data.len());
    out.push(TLS_APP_DATA);
    out.extend_from_slice(&TLS_VERSION);
    let len = data.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Read one TLS ApplicationData record, returning the inner payload.
pub async fn read_app_data<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut hdr = [0u8; TLS_RECORD_HEADER];
    r.read_exact(&mut hdr).await?;
    if hdr[0] != TLS_APP_DATA {
        bail!("expected ApplicationData record (0x17), got 0x{:02x}", hdr[0]);
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Read the first MTProto ApplicationData record, skipping any TLS handshake
/// records the client sends as part of the fake TLS handshake completion:
///   - ChangeCipherSpec (0x14)
///   - Handshake / Finished (0x16)
///   - ApplicationData records that are too small to be an MTProto init (< 64 bytes),
///     which are the client's fake Finished wrapped in AppData
pub async fn read_first_app_data<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    loop {
        let mut hdr = [0u8; TLS_RECORD_HEADER];
        r.read_exact(&mut hdr).await?;
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        debug!(record_type = hdr[0], len, "read_first_app_data: got TLS record");
        match hdr[0] {
            TLS_APP_DATA => {
                let mut payload = vec![0u8; len];
                r.read_exact(&mut payload).await?;
                // Small AppData = client's fake Finished (< 64 bytes).
                // Real MTProto init is always exactly 64 bytes.
                if payload.len() >= 64 {
                    debug!(len, "read_first_app_data: returning AppData as MTProto init");
                    return Ok(payload);
                }
                debug!(len, "read_first_app_data: skipping small AppData (fake Finished)");
            }
            0x14 | 0x16 => {
                // ChangeCipherSpec or Handshake — discard
                let mut discard = vec![0u8; len];
                r.read_exact(&mut discard).await?;
                debug!(record_type = hdr[0], "read_first_app_data: discarded handshake/CCS record");
            }
            t => bail!("unexpected TLS record type 0x{:02x} before first AppData", t),
        }
    }
}
