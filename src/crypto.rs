use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub struct AesCtr {
    cipher: Aes256Ctr,
}

impl AesCtr {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes256Ctr::new(key.into(), iv.into()),
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

/// Derive the client→proxy (decrypt) and proxy→client (encrypt) AES-CTR keys from
/// the 64-byte handshake and the user secret.
///
/// Handshake layout (after obfuscation reversal):
///   bytes  0..7   — random
///   bytes  8..55  — pre_key (48 bytes)
///   bytes 56..59  — protocol tag
///   bytes 60..63  — DC ID (little-endian i16 + 2 padding)
///   bytes 64..    — timestamp (4 bytes, if present)
///
/// Key derivation :
///   key_material = sha256(pre_key[0..32] + secret)
///   iv           = pre_key[32..48]       (16 bytes)
///   reverse_key  = sha256(pre_key[0..32] reversed + secret)
pub fn derive_keys(
    handshake: &[u8; 64],
    secret: &[u8],
) -> ([u8; 32], [u8; 16], [u8; 32], [u8; 16]) {
    let pre_key = &handshake[8..56]; // 48 bytes

    // client→proxy decrypt key
    let dec_key: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&pre_key[0..32]);
        h.update(secret);
        h.finalize().into()
    };
    let dec_iv: [u8; 16] = pre_key[32..48].try_into().unwrap();

    // proxy→client encrypt key (reversed pre_key[0..32])
    let enc_key: [u8; 32] = {
        let mut rev = pre_key[0..32].to_vec();
        rev.reverse();
        let mut h = Sha256::new();
        h.update(&rev);
        h.update(secret);
        h.finalize().into()
    };
    let enc_iv: [u8; 16] = {
        let mut iv: [u8; 16] = pre_key[32..48].try_into().unwrap();
        iv.reverse();
        iv
    };

    (dec_key, dec_iv, enc_key, enc_iv)
}
