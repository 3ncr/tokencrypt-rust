//! Integration tests for the Rust implementation of 3ncr.org v1.

use tokencrypt::{TokenCrypt, TokenCryptError, HEADER_V1};

/// Canonical v1 envelope test vectors — shared with Go, Node, PHP, Python, and
/// other implementations. The 32-byte AES key was originally derived via the
/// legacy PBKDF2-SHA3-256 KDF with secret="a", salt="b", iterations=1000;
/// this Rust library only supports the modern KDFs, so the derived key is
/// hardcoded here so we can still verify envelope-level interop.
const CANONICAL_KEY: [u8; 32] = [
    0x2f, 0x84, 0x15, 0x18, 0x69, 0xd7, 0xd2, 0x25, 0x5d, 0x62, 0xb3, 0x32, 0x0e, 0x97, 0x42, 0x9b,
    0xde, 0x5a, 0xac, 0x04, 0xa0, 0x57, 0x3b, 0x24, 0x68, 0x52, 0x9a, 0x74, 0x17, 0x51, 0x5f, 0x87,
];

const CANONICAL_VECTORS: &[(&str, &str)] = &[
    ("a", "3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8"),
    (
        "test",
        "3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc",
    ),
    (
        "08019215-B205-4416-B2FB-132962F9952F",
        "3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ",
    ),
    (
        "перевірка",
        "3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ",
    ),
];

fn canonical() -> TokenCrypt {
    TokenCrypt::from_raw_key(CANONICAL_KEY)
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("system RNG");
    k
}

#[test]
fn decrypts_all_canonical_vectors() {
    let tc = canonical();
    for (plaintext, encrypted) in CANONICAL_VECTORS {
        let decoded = tc.decrypt_if_3ncr(encrypted).unwrap();
        assert_eq!(decoded.as_ref(), *plaintext);
    }
}

#[test]
fn round_trips_canonical_plaintexts() {
    let tc = canonical();
    for (plaintext, _) in CANONICAL_VECTORS {
        let enc = tc.encrypt_3ncr(plaintext);
        assert!(enc.starts_with(HEADER_V1));
        assert_eq!(tc.decrypt_if_3ncr(&enc).unwrap().as_ref(), *plaintext);
    }
}

#[test]
fn round_trips_edge_cases() {
    let tc = TokenCrypt::from_raw_key(random_key());
    let cases: &[&str] = &[
        "",
        "x",
        "hello, world",
        "08019215-B205-4416-B2FB-132962F9952F",
        "перевірка 🌍 中文 ✓",
        &"a".repeat(4096),
    ];
    for p in cases {
        let enc = tc.encrypt_3ncr(p);
        assert_eq!(tc.decrypt_if_3ncr(&enc).unwrap().as_ref(), *p);
    }
}

#[test]
fn non_3ncr_returned_unchanged() {
    let tc = TokenCrypt::from_raw_key(random_key());
    let s = "plain config value";
    let out = tc.decrypt_if_3ncr(s).unwrap();
    assert_eq!(out.as_ref(), s);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
}

#[test]
fn empty_string_returned_unchanged() {
    let tc = TokenCrypt::from_raw_key(random_key());
    let out = tc.decrypt_if_3ncr("").unwrap();
    assert_eq!(out.as_ref(), "");
}

#[test]
fn iv_uniqueness_across_encryptions() {
    let tc = TokenCrypt::from_raw_key(random_key());
    let a = tc.encrypt_3ncr("same plaintext");
    let b = tc.encrypt_3ncr("same plaintext");
    assert_ne!(a, b);
}

#[test]
fn tampered_payload_is_rejected() {
    let tc = TokenCrypt::from_raw_key(random_key());
    let enc = tc.encrypt_3ncr("sensitive value");
    let body = &enc[HEADER_V1.len()..];
    let idx = body.len() / 2;
    let mut bytes = body.as_bytes().to_vec();
    bytes[idx] = if bytes[idx] != b'A' { b'A' } else { b'B' };
    let tampered = format!("{HEADER_V1}{}", std::str::from_utf8(&bytes).unwrap());
    match tc.decrypt_if_3ncr(&tampered) {
        Err(TokenCryptError::DecryptionFailed | TokenCryptError::InvalidBase64) => {}
        other => panic!("expected tampered payload to be rejected, got {other:?}"),
    }
}

#[test]
fn truncated_payload_is_rejected() {
    let tc = TokenCrypt::from_raw_key(random_key());
    let bad = format!("{HEADER_V1}AAAA");
    assert!(matches!(
        tc.decrypt_if_3ncr(&bad),
        Err(TokenCryptError::Truncated)
    ));
}

#[test]
fn decoder_accepts_padded_input() {
    let tc = canonical();
    let (plaintext, encrypted) = CANONICAL_VECTORS[0];
    let body = &encrypted[HEADER_V1.len()..];
    let pad = "=".repeat((4 - body.len() % 4) % 4);
    let padded = format!("{HEADER_V1}{body}{pad}");
    assert_eq!(tc.decrypt_if_3ncr(&padded).unwrap().as_ref(), plaintext);
}

#[test]
fn encoder_emits_no_padding() {
    let tc = TokenCrypt::from_raw_key(random_key());
    let enc = tc.encrypt_3ncr("some value");
    assert!(!enc.contains('='));
}

#[test]
fn from_sha3_round_trip() {
    let tc = TokenCrypt::from_sha3("some-high-entropy-api-token");
    let enc = tc.encrypt_3ncr("hello");
    assert_eq!(tc.decrypt_if_3ncr(&enc).unwrap().as_ref(), "hello");
}

#[test]
fn from_argon2id_round_trip() {
    let tc = TokenCrypt::from_argon2id("correct horse battery staple", b"0123456789abcdef")
        .expect("argon2id");
    for (p, _) in CANONICAL_VECTORS {
        let enc = tc.encrypt_3ncr(p);
        assert_eq!(tc.decrypt_if_3ncr(&enc).unwrap().as_ref(), *p);
    }
}

#[test]
fn from_argon2id_rejects_short_salt() {
    match TokenCrypt::from_argon2id("secret", b"short") {
        Err(TokenCryptError::SaltTooShort(5)) => {}
        other => panic!("expected SaltTooShort(5), got {other:?}"),
    }
}

#[test]
fn from_argon2id_wrong_secret_fails_to_decrypt() {
    let salt = b"0123456789abcdef";
    let tc = TokenCrypt::from_argon2id("right secret", salt).unwrap();
    let enc = tc.encrypt_3ncr("hello");
    let other = TokenCrypt::from_argon2id("wrong secret", salt).unwrap();
    assert!(matches!(
        other.decrypt_if_3ncr(&enc),
        Err(TokenCryptError::DecryptionFailed)
    ));
}
