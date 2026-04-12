//! FakeTLS (secret prefix "ee") handshake handling.
//!
//! Telegram clients wrap MTProto in a fake TLS 1.3 ClientHello when using
//! FakeTLS secrets. The proxy must:
//!  1. Read the TLS ClientHello from the client.
//!  2. Validate the HMAC-SHA256 in the session_id field using the user secret.
//!  3. Send back a synthetic TLS ServerHello + ChangeCipherSpec + ApplicationData.
//!  4. From that point on, all data is wrapped in TLS 1.3 ApplicationData records
//!     (type 0x17, version 0x0303, 2-byte length), but the inner content is plain
//!     obfuscated MTProto.

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

type HmacSha256 = Hmac<Sha256>;

pub const TLS_RECORD_HEADER: usize = 5; // type(1) + version(2) + length(2)
pub const TLS_APP_DATA: u8 = 0x17;
pub const TLS_VERSION: [u8; 2] = [0x03, 0x03];

/// Read a full TLS ClientHello. Returns the raw bytes.
pub async fn read_client_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    // TLS record header
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

/// Validate the HMAC embedded in the TLS ClientHello session_id.
///
/// Layout inside the TLS record payload (after the 5-byte header):
///   [0]    = 0x01  (ClientHello handshake type)
///   [1..3] = length (3 bytes)
///   [4..5] = TLS version (0x03, 0x03)
///   [6..37] = random (32 bytes)  — contains timestamp + 28 random bytes
///   [38]   = session_id length (should be 32)
///   [39..70] = session_id (32 bytes) — last 4 bytes are the HMAC tag
///
/// Validation: HMAC-SHA256(key=secret, msg=hello_bytes_with_session_id_zeroed)[0..4]
///             must equal session_id[28..32].
pub fn validate_hello_hmac(hello: &[u8], secret: &[u8]) -> Result<()> {
    // 5-byte TLS header + 1 (type) + 3 (len) + 2 (version) + 32 (random) = offset 43
    // session_id_len is at offset 43
    if hello.len() < 76 {
        bail!("ClientHello too short");
    }
    let session_id_offset = 5 + 1 + 3 + 2 + 32; // = 43
    let sid_len = hello[session_id_offset] as usize;
    if sid_len != 32 {
        bail!("unexpected session_id length {}", sid_len);
    }
    let sid_start = session_id_offset + 1; // 44
    let sid_end = sid_start + 32;          // 76
    if hello.len() < sid_end {
        bail!("ClientHello truncated before session_id end");
    }

    // Build message with session_id zeroed for HMAC verification
    let mut msg = hello.to_vec();
    for b in &mut msg[sid_start..sid_end] {
        *b = 0;
    }

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
    mac.update(&msg);
    let result = mac.finalize().into_bytes();

    // Try variant 2: HMAC over handshake payload only (skip 5-byte TLS record header)
    let result2 = {
        let mut msg2 = msg[5..].to_vec();
        // session_id in payload is at sid_start-5 .. sid_end-5
        for b in &mut msg2[sid_start - 5..sid_end - 5] { *b = 0; }
        let mut mac2 = HmacSha256::new_from_slice(secret)
            .map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
        mac2.update(&msg2);
        mac2.finalize().into_bytes()
    };

    let session_id = &hello[sid_start..sid_end];
    debug!(
        v1_full_record = %hex::encode(&result),
        v2_no_tls_hdr  = %hex::encode(&result2),
        session_id     = %hex::encode(session_id),
        "FakeTLS HMAC variants"
    );

    if result.as_slice() == session_id {
        return Ok(());
    }
    if result2.as_slice() == session_id {
        return Ok(());
    }
    bail!("FakeTLS HMAC mismatch — wrong secret or not a proxy client")
}

/// Send a synthetic TLS ServerHello + ChangeCipherSpec + empty ApplicationData.
pub async fn send_server_hello<W: AsyncWrite + Unpin>(w: &mut W, _domain: &str) -> Result<()> {
    // Minimal TLS 1.3-style ServerHello (TLS 1.2 on the wire)
    let server_random: [u8; 32] = rand::random();

    // ServerHello handshake message
    let mut server_hello_body = Vec::new();
    server_hello_body.extend_from_slice(&[0x03, 0x03]); // version
    server_hello_body.extend_from_slice(&server_random);
    server_hello_body.push(32); // session_id length
    server_hello_body.extend_from_slice(&[0u8; 32]); // session_id (zeros)
    server_hello_body.extend_from_slice(&[0x13, 0x01]); // cipher TLS_AES_128_GCM_SHA256
    server_hello_body.push(0x00); // compression: none

    // Extensions: supported_versions = TLS 1.3
    let exts: Vec<u8> = {
        let mut e = Vec::new();
        // supported_versions extension
        e.extend_from_slice(&[0x00, 0x2b]); // type
        e.extend_from_slice(&[0x00, 0x03]); // ext len
        e.extend_from_slice(&[0x02, 0x03, 0x04]); // selected version = TLS 1.3
        // key_share extension (empty)
        e.extend_from_slice(&[0x00, 0x33]); // type
        e.extend_from_slice(&[0x00, 0x02]); // ext len
        e.extend_from_slice(&[0x00, 0x00]); // empty key share
        e
    };
    let exts_len = exts.len() as u16;
    server_hello_body.extend_from_slice(&exts_len.to_be_bytes());
    server_hello_body.extend_from_slice(&exts);

    // Wrap in Handshake record (type=0x02 ServerHello)
    let hs_len = server_hello_body.len() as u32;
    let mut handshake = Vec::new();
    handshake.push(0x02); // ServerHello
    handshake.push(((hs_len >> 16) & 0xff) as u8);
    handshake.push(((hs_len >> 8) & 0xff) as u8);
    handshake.push((hs_len & 0xff) as u8);
    handshake.extend_from_slice(&server_hello_body);

    // TLS record: Handshake (0x16)
    let rec_len = handshake.len() as u16;
    w.write_all(&[0x16, 0x03, 0x03]).await?;
    w.write_all(&rec_len.to_be_bytes()).await?;
    w.write_all(&handshake).await?;

    // ChangeCipherSpec record
    w.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;

    w.flush().await?;
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
