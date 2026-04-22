//! Rust implementation of the [3ncr.org](https://3ncr.org/) v1 string
//! encryption standard.
//!
//! The v1 envelope is
//! `3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>` using AES-256-GCM
//! with a 12-byte random IV and base64 without padding. The envelope is
//! agnostic of how the 32-byte AES key was derived; pick a constructor based
//! on the entropy of the input secret.
//!
//! ```no_run
//! use tokencrypt::TokenCrypt;
//!
//! let tc = TokenCrypt::from_sha3("some-high-entropy-api-token");
//! let enc = tc.encrypt_3ncr("hello");
//! assert_eq!(tc.decrypt_if_3ncr(&enc).unwrap(), "hello");
//! ```

use std::borrow::Cow;
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use hmac::Hmac;
use sha3::{Digest, Sha3_256};

/// 3ncr.org v1 envelope header.
pub const HEADER_V1: &str = "3ncr.org/1#";

const AES_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

// 3ncr.org recommended Argon2id parameters (see https://3ncr.org/1/ — Key
// Derivation section).
const ARGON2ID_MEMORY_KIB: u32 = 19456;
const ARGON2ID_TIME_COST: u32 = 2;
const ARGON2ID_PARALLELISM: u32 = 1;
const ARGON2ID_MIN_SALT_BYTES: usize = 16;

/// Errors returned by [`TokenCrypt`].
#[derive(Debug)]
pub enum TokenCryptError {
    /// Salt supplied to `from_argon2id` was shorter than 16 bytes.
    SaltTooShort(usize),
    /// Base64 payload after the header is not valid.
    InvalidBase64,
    /// Payload is shorter than `IV + TAG` and therefore cannot be a 3ncr token.
    Truncated,
    /// GCM authentication tag verification failed (wrong key or tampered data).
    DecryptionFailed,
    /// Decrypted bytes are not valid UTF-8.
    InvalidUtf8,
    /// Argon2id KDF reported an internal error (e.g. invalid parameters).
    Argon2,
}

impl fmt::Display for TokenCryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SaltTooShort(n) => write!(
                f,
                "salt must be at least {ARGON2ID_MIN_SALT_BYTES} bytes, got {n}"
            ),
            Self::InvalidBase64 => f.write_str("invalid base64 payload"),
            Self::Truncated => f.write_str("truncated 3ncr token"),
            Self::DecryptionFailed => f.write_str("authentication tag verification failed"),
            Self::InvalidUtf8 => f.write_str("decrypted bytes are not valid UTF-8"),
            Self::Argon2 => f.write_str("argon2id key derivation failed"),
        }
    }
}

impl std::error::Error for TokenCryptError {}

/// A 3ncr.org v1 encrypter/decrypter bound to a 32-byte AES key.
pub struct TokenCrypt {
    cipher: Aes256Gcm,
}

impl TokenCrypt {
    /// Build a `TokenCrypt` from a raw 32-byte AES-256 key.
    ///
    /// Use this when your secret is already high-entropy and exactly 32 bytes
    /// (for example, loaded from a key-management service).
    pub fn from_raw_key(key: [u8; AES_KEY_SIZE]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }

    /// Derive the AES key from a high-entropy secret via a single SHA3-256
    /// hash.
    ///
    /// Suitable for random pre-shared keys, UUIDs, or long random API tokens —
    /// inputs that already carry at least 128 bits of unique entropy. For
    /// low-entropy inputs such as user passwords, prefer
    /// [`TokenCrypt::from_argon2id`].
    pub fn from_sha3(secret: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(secret.as_ref());
        let digest = hasher.finalize();
        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(&digest);
        Self::from_raw_key(key)
    }

    /// Derive the AES key from a low-entropy secret via Argon2id using the
    /// 3ncr.org v1 recommended parameters (m=19456 KiB, t=2, p=1).
    ///
    /// `salt` must be at least 16 bytes. For deterministic derivation across
    /// implementations, pass the same salt.
    pub fn from_argon2id(
        secret: impl AsRef<[u8]>,
        salt: impl AsRef<[u8]>,
    ) -> Result<Self, TokenCryptError> {
        let salt = salt.as_ref();
        if salt.len() < ARGON2ID_MIN_SALT_BYTES {
            return Err(TokenCryptError::SaltTooShort(salt.len()));
        }
        let params = Params::new(
            ARGON2ID_MEMORY_KIB,
            ARGON2ID_TIME_COST,
            ARGON2ID_PARALLELISM,
            Some(AES_KEY_SIZE),
        )
        .map_err(|_| TokenCryptError::Argon2)?;
        let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; AES_KEY_SIZE];
        ctx.hash_password_into(secret.as_ref(), salt, &mut key)
            .map_err(|_| TokenCryptError::Argon2)?;
        Ok(Self::from_raw_key(key))
    }

    /// Derive the AES key via PBKDF2-HMAC-SHA3-256 (legacy KDF).
    ///
    /// Kept for backward compatibility with data encrypted by earlier 3ncr.org
    /// libraries. New callers should use [`TokenCrypt::from_argon2id`] for
    /// passwords or [`TokenCrypt::from_raw_key`] / [`TokenCrypt::from_sha3`]
    /// for high-entropy secrets. See <https://3ncr.org/1/#kdf>.
    #[deprecated(
        since = "1.0.0",
        note = "legacy KDF; use from_argon2id for passwords or from_raw_key / from_sha3 for high-entropy secrets"
    )]
    pub fn from_pbkdf2_sha3(
        secret: impl AsRef<[u8]>,
        salt: impl AsRef<[u8]>,
        iterations: u32,
    ) -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        pbkdf2::pbkdf2::<Hmac<Sha3_256>>(secret.as_ref(), salt.as_ref(), iterations, &mut key)
            .expect("pbkdf2 with a 32-byte output length never fails");
        Self::from_raw_key(key)
    }

    /// Encrypt a UTF-8 string and return a `3ncr.org/1#...` value.
    pub fn encrypt_3ncr(&self, plaintext: &str) -> String {
        let mut iv = [0u8; IV_SIZE];
        getrandom::getrandom(&mut iv).expect("system RNG unavailable");
        let nonce = Nonce::from_slice(&iv);
        let ct_and_tag = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("aes-gcm encryption never fails on valid input");
        let mut buf = Vec::with_capacity(IV_SIZE + ct_and_tag.len());
        buf.extend_from_slice(&iv);
        buf.extend_from_slice(&ct_and_tag);
        let mut out = String::with_capacity(HEADER_V1.len() + ((buf.len() * 4) / 3) + 4);
        out.push_str(HEADER_V1);
        STANDARD_NO_PAD.encode_string(&buf, &mut out);
        out
    }

    /// Decrypt `value` if it carries the `3ncr.org/1#` header; otherwise
    /// return it unchanged. This makes it safe to route every configuration
    /// value through it regardless of whether it was encrypted.
    pub fn decrypt_if_3ncr<'a>(&self, value: &'a str) -> Result<Cow<'a, str>, TokenCryptError> {
        match value.strip_prefix(HEADER_V1) {
            Some(body) => self.decrypt(body).map(Cow::Owned),
            None => Ok(Cow::Borrowed(value)),
        }
    }

    fn decrypt(&self, body: &str) -> Result<String, TokenCryptError> {
        // Spec emits no padding; decoders accept both for robustness.
        let stripped = body.trim_end_matches('=');
        let buf = STANDARD_NO_PAD
            .decode(stripped)
            .map_err(|_| TokenCryptError::InvalidBase64)?;
        if buf.len() < IV_SIZE + TAG_SIZE {
            return Err(TokenCryptError::Truncated);
        }
        let (iv, ct_and_tag) = buf.split_at(IV_SIZE);
        let nonce = Nonce::from_slice(iv);
        let plaintext = self
            .cipher
            .decrypt(nonce, ct_and_tag)
            .map_err(|_| TokenCryptError::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| TokenCryptError::InvalidUtf8)
    }
}

impl fmt::Debug for TokenCrypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenCrypt").finish_non_exhaustive()
    }
}
