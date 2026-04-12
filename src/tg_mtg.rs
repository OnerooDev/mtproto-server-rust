//! Telegram DC link obfuscation (mtg / Telegram “transport obfuscation” compatible).
//!
//! Proxies must send a 64-byte handshake frame then AES-CTR encrypt all bytes to the DC,
//! matching `github.com/9seconds/mtg` `obfuscation.Obfuscator.SendHandshake` and `conn`.

use crate::crypto::AesCtr;
use anyhow::{bail, Result};
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};

const HF_LEN: usize = 64;
const HF_OFFSET_KEY: usize = 8;
const HF_OFFSET_IV: usize = 40;
const HF_OFFSET_CONNECTION_TYPE: usize = 56;
const HF_OFFSET_DC: usize = 60;

/// Connection-type tag used by mtg (`handshake_frame.go`).
const HF_CONNECTION_TYPE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

/// Build AES-CTR from the current frame key/iv fields (same as mtg `getCipher`).
fn cipher_from_frame(frame: &[u8; HF_LEN], secret: &[u8]) -> Result<AesCtr> {
    let key = &frame[HF_OFFSET_KEY..HF_OFFSET_IV];
    let iv = &frame[HF_OFFSET_IV..HF_OFFSET_CONNECTION_TYPE];
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(secret);
    let aes_key: [u8; 32] = hasher.finalize().into();
    let aes_iv: [u8; 16] = iv.try_into().map_err(|_| anyhow::anyhow!("iv len"))?;
    Ok(AesCtr::new(&aes_key, &aes_iv))
}

/// Reverse bytes [8..56) in place (key + iv), matching `handshakeFrame.revert`.
fn revert_frame(data: &mut [u8; HF_LEN]) {
    data[HF_OFFSET_KEY..HF_OFFSET_CONNECTION_TYPE].reverse();
}

/// Random 64-byte frame with constraints from mtg `generateHandshake`.
fn generate_handshake_frame(dc_id: i16) -> [u8; HF_LEN] {
    let mut rng = rand::thread_rng();
    loop {
        let mut data = [0u8; HF_LEN];
        rng.fill(&mut data[..]);

        if data[0] == 0xef {
            continue;
        }

        let w0 = u32::from_le_bytes(data[0..4].try_into().unwrap());
        match w0 {
            0x4441_4548 | 0x5453_4f50 | 0x2054_4547 | 0x4954_504f | 0x0201_0316 | 0xdddd_dddd
            | 0xeeee_eeee => continue,
            _ => {}
        }

        if (data[4] | data[5] | data[6] | data[7]) == 0 {
            continue;
        }

        data[HF_OFFSET_CONNECTION_TYPE..HF_OFFSET_CONNECTION_TYPE + 4].copy_from_slice(&HF_CONNECTION_TYPE);
        data[HF_OFFSET_DC..HF_OFFSET_DC + 2].copy_from_slice(&(dc_id as u16).to_le_bytes());
        return data;
    }
}

/// Send the 64-byte handshake to Telegram and return `(recv_cipher, send_cipher)` for the socket.
///
/// Mirrors mtg `Obfuscator.SendHandshake`: encrypts the frame with `send_cipher`, then restores
/// plaintext key/iv regions before writing; `send_cipher` keystream is advanced by 64 bytes.
pub async fn send_telegram_handshake<W: AsyncWrite + Unpin>(
    w: &mut W,
    secret: &[u8],
    dc_id: i16,
) -> Result<(AesCtr, AesCtr)> {
    if secret.is_empty() {
        bail!("empty proxy secret");
    }

    let copy_frame = generate_handshake_frame(dc_id);
    let mut frame = copy_frame;

    let mut send_cipher = cipher_from_frame(&frame, secret)?;
    revert_frame(&mut frame);
    let recv_cipher = cipher_from_frame(&frame, secret)?;

    send_cipher.apply(&mut frame);

    frame[HF_OFFSET_KEY..HF_OFFSET_IV].copy_from_slice(&copy_frame[HF_OFFSET_KEY..HF_OFFSET_IV]);
    frame[HF_OFFSET_IV..HF_OFFSET_CONNECTION_TYPE]
        .copy_from_slice(&copy_frame[HF_OFFSET_IV..HF_OFFSET_CONNECTION_TYPE]);

    w.write_all(&frame).await?;
    w.flush().await?;

    Ok((recv_cipher, send_cipher))
}
