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

/// MTProto transport obfuscation ciphers, compatible with `mtg`:
/// - recv cipher is derived from the *as-received* frame key/iv
/// - send cipher is derived after reversing bytes [8..56) (key+iv as one 48-byte block)
///
/// If `secret` is non-empty, AES key is `sha256(frame_key || secret)`.
/// If `secret` is empty, AES key is `frame_key` directly.
pub fn derive_mtg_client_ciphers(
    init_encrypted: &[u8; 64],
    secret: &[u8],
) -> (AesCtr, AesCtr) {
    let key0: [u8; 32] = init_encrypted[8..40].try_into().unwrap();
    let iv0: [u8; 16] = init_encrypted[40..56].try_into().unwrap();
    let recv = mtg_cipher(&key0, &iv0, secret);

    let mut reversed = *init_encrypted;
    reversed[8..56].reverse();
    let key1: [u8; 32] = reversed[8..40].try_into().unwrap();
    let iv1: [u8; 16] = reversed[40..56].try_into().unwrap();
    let send = mtg_cipher(&key1, &iv1, secret);

    (recv, send)
}

fn mtg_cipher(key: &[u8; 32], iv: &[u8; 16], secret: &[u8]) -> AesCtr {
    if secret.is_empty() {
        return AesCtr::new(key, iv);
    }
    let mut h = Sha256::new();
    h.update(key);
    h.update(secret);
    let out: [u8; 32] = h.finalize().into();
    AesCtr::new(&out, iv)
}
