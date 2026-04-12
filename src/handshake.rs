//! MTProto obfuscation handshake (the 64-byte init packet).
//!
//! The client sends 64 random-looking bytes. After AES-CTR decryption with
//! the session key derived from bytes [8..56] (the "pre_key"), the layout is:
//!
//!   [0..7]   random
//!   [8..55]  pre_key (48 bytes used for key derivation)
//!   [56..59] protocol tag (identifies which framing the client wants)
//!   [60..61] DC id (little-endian i16)
//!   [62..63] padding / reserved
//!   [64..]   optional continuation (e.g. timestamp in some variants)
//!
//! Protocol tags:
//!   0xefefefef — Abridged
//!   0xeeeeeeee — Intermediate
//!   0xdddddddd — Secure Intermediate (with padding)

use anyhow::{bail, Result};

pub const PROTO_TAG_ABRIDGED:   u32 = 0xefefefef;
pub const PROTO_TAG_INTERMEDIATE: u32 = 0xeeeeeeee;
pub const PROTO_TAG_SECURE:     u32 = 0xdddddddd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Abridged,
    Intermediate,
    /// Secure Intermediate: each frame prefixed with 0–3 bytes random padding
    Secure,
}

#[derive(Debug)]
pub struct HandshakeInfo {
    pub protocol: Protocol,
    pub dc_id: i16,
}

/// Inspect the decrypted 64-byte init buffer.
pub fn parse_handshake(decrypted: &[u8; 64]) -> Result<HandshakeInfo> {
    let tag = u32::from_le_bytes(decrypted[56..60].try_into().unwrap());
    let protocol = match tag {
        PROTO_TAG_ABRIDGED    => Protocol::Abridged,
        PROTO_TAG_INTERMEDIATE => Protocol::Intermediate,
        PROTO_TAG_SECURE       => Protocol::Secure,
        _ => bail!("unknown protocol tag 0x{:08x}", tag),
    };
    let dc_id = i16::from_le_bytes(decrypted[60..62].try_into().unwrap());
    Ok(HandshakeInfo { protocol, dc_id })
}
