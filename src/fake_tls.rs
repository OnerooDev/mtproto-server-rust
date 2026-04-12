//! FakeTLS (secret prefix "ee") handshake handling.
//!
//! Telegram clients wrap MTProto in a fake TLS 1.3 ClientHello when using
//! FakeTLS secrets. The proxy must:
//!  1. Read the TLS ClientHello from the client.
//!  2. Validate the HMAC-SHA256 in the random field using the user secret.
//!  3. Send back a synthetic TLS ServerHello + ChangeCipherSpec + fake AppData.
//!     The ServerHello random must itself be HMAC-SHA256(secret, server_hello_zeroed)
//!     because the Telegram client verifies this before proceeding.
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

/// Random field position inside a TLS record (same for ClientHello and ServerHello).
const RANDOM_POS: usize = 11;
const RANDOM_LEN: usize = 32;

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

/// Validate the HMAC embedded in the TLS ClientHello **random** field.
///
/// Protocol:
///   key    = raw_secret_bytes (16 bytes)
///   digest = hello[11..43]  (32-byte TLS random field)
///   msg    = hello with random field zeroed (hello[11..43] = 0x00 * 32)
///   hmac   = HMAC-SHA256(key, msg)
///
///   digest[0..28] must equal hmac[0..28]
///   digest[28..32] = hmac[28..32] XOR big-endian(unix_timestamp) — not checked here
pub fn validate_hello_hmac(hello: &[u8], secret: &[u8]) -> Result<()> {
    if hello.len() < RANDOM_POS + RANDOM_LEN {
        bail!("ClientHello too short");
    }

    let mut msg = hello.to_vec();
    for b in &mut msg[RANDOM_POS..RANDOM_POS + RANDOM_LEN] {
        *b = 0;
    }

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
    mac.update(&msg);
    let hmac_result = mac.finalize().into_bytes();

    // Compare first 28 bytes; last 4 bytes encode client timestamp XOR hmac[28..32]
    let digest = &hello[RANDOM_POS..RANDOM_POS + RANDOM_LEN];
    let mismatch = digest[..28]
        .iter()
        .zip(hmac_result[..28].iter())
        .any(|(a, b)| a != b);

    if mismatch {
        let _ = std::fs::write("/tmp/tg_hello.bin", hello);
        debug!(
            key      = %hex::encode(secret),
            hmac28   = %hex::encode(&hmac_result[..28]),
            digest28 = %hex::encode(&digest[..28]),
            hello_len = hello.len(),
            "FakeTLS HMAC mismatch — hello saved to /tmp/tg_hello.bin"
        );
        bail!("FakeTLS HMAC mismatch — wrong secret or not a proxy client");
    }
    Ok(())
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

/// Build the ServerHello TLS record with zeros in the random field, then
/// compute HMAC-SHA256(secret, record) and place it as the server random.
///
/// The Telegram client verifies this HMAC before sending its own data.
fn build_server_hello_record(session_id: &[u8], secret: &[u8]) -> Vec<u8> {
    // --- ServerHello body (random = 0x00 * 32 initially) ---
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    sh_body.extend_from_slice(&[0u8; RANDOM_LEN]); // random placeholder
    sh_body.push(session_id.len() as u8);
    sh_body.extend_from_slice(session_id);
    sh_body.extend_from_slice(&[0x13, 0x01]); // cipher TLS_AES_128_GCM_SHA256
    sh_body.push(0x00); // compression: none

    // Extensions: supported_versions (TLS 1.3) + key_share (empty)
    let mut exts = Vec::new();
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]); // supported_versions
    exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x00]);       // key_share (empty)
    let exts_len = exts.len() as u16;
    sh_body.extend_from_slice(&exts_len.to_be_bytes());
    sh_body.extend_from_slice(&exts);

    // --- Handshake wrapper ---
    let hs_len = sh_body.len() as u32;
    let mut handshake = Vec::new();
    handshake.push(0x02); // ServerHello type
    handshake.push(((hs_len >> 16) & 0xff) as u8);
    handshake.push(((hs_len >> 8) & 0xff) as u8);
    handshake.push((hs_len & 0xff) as u8);
    handshake.extend_from_slice(&sh_body);

    // --- TLS record wrapper ---
    let rec_len = handshake.len() as u16;
    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x03]);
    record.extend_from_slice(&rec_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    // --- Compute HMAC over record-with-zeros and place it as server random ---
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC init");
    mac.update(&record);
    let hmac_out = mac.finalize().into_bytes();
    record[RANDOM_POS..RANDOM_POS + RANDOM_LEN].copy_from_slice(&hmac_out[..RANDOM_LEN]);

    record
}

/// Send a synthetic TLS ServerHello + ChangeCipherSpec + fake server ApplicationData.
///
/// After the ServerHello, TLS 1.3 requires the server to send its encrypted
/// handshake records (EncryptedExtensions, Certificate, Finished etc.) wrapped
/// in ApplicationData records.  The Telegram client waits for these before
/// sending its own CCS + Finished + MTProto init.
pub async fn send_server_hello<W: AsyncWrite + Unpin>(
    w: &mut W,
    _domain: &str,
    session_id: &[u8],
    secret: &[u8],
) -> Result<()> {
    // ServerHello record with HMAC-computed server random
    let sh_record = build_server_hello_record(session_id, secret);
    w.write_all(&sh_record).await?;

    // ChangeCipherSpec
    w.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;

    // Fake encrypted-handshake ApplicationData records.
    // Sizes mimic: EncryptedExtensions+Certificate+CertificateVerify (~1100 bytes)
    // followed by server Finished (~52 bytes).
    let fake_cert: Vec<u8> = (0..1100).map(|_| rand::random::<u8>()).collect();
    w.write_all(&wrap_app_data(&fake_cert)).await?;

    let fake_fin: Vec<u8> = (0..52).map(|_| rand::random::<u8>()).collect();
    w.write_all(&wrap_app_data(&fake_fin)).await?;

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
        match hdr[0] {
            TLS_APP_DATA => {
                let mut payload = vec![0u8; len];
                r.read_exact(&mut payload).await?;
                // Small AppData = client's fake Finished (< 64 bytes).
                // Real MTProto init is always exactly 64 bytes.
                if payload.len() >= 64 {
                    return Ok(payload);
                }
                debug!(len, "skipping small AppData (client fake Finished)");
            }
            0x14 | 0x16 => {
                // ChangeCipherSpec or Handshake — discard
                let mut discard = vec![0u8; len];
                r.read_exact(&mut discard).await?;
            }
            t => bail!("unexpected TLS record type 0x{:02x} before first AppData", t),
        }
    }
}
