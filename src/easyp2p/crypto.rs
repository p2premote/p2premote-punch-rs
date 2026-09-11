//! Byte-exact port of easyp2p's topic derivation, secure payload encryption
//! and P-256 key exchange (p2p.go: CalculateMD5/deriveKey*/encryptAES).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{P2pError, Result};

/// securePayload on the MQTT wire.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurePayload {
    pub nonce: String,
    pub data: String,
}

pub fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

#[allow(dead_code)]
pub fn b64_raw() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD_NO_PAD
}

pub fn calculate_md5(input: &str) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(input.as_bytes());
    hex(&h.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// deriveKeyForTopic: hex(sha256(salt || md5hex(uid)))[:16]
pub fn derive_key_for_topic(salt: &str, uid: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(calculate_md5(uid).as_bytes());
    hex(&h.finalize())[..16].to_string()
}

/// deriveKeyForPayload: sha256("gonc-p2p-payload" || md5hex(uid)); ascii → hex[:8]
pub fn derive_key_for_payload(uid: &str, ascii: bool) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"gonc-p2p-payload");
    h.update(calculate_md5(uid).as_bytes());
    let sum = h.finalize();
    if ascii {
        hex(&sum)[..8].as_bytes().to_vec()
    } else {
        sum[..8].to_vec()
    }
}

/// deriveKey: sha256(sha256("nc-p2p-tool" || salt || uid))
pub fn derive_key(salt: &str, uid: &str) -> [u8; 32] {
    let salt0 = b"nc-p2p-tool";
    let mut h = Sha256::new();
    h.update(salt0);
    h.update(salt.as_bytes());
    h.update(uid.as_bytes());
    let inner = h.finalize();
    let mut out = Sha256::new();
    out.update(inner);
    out.finalize().into()
}

pub fn topic_from_salt_and_session_uid(topic_salt: &str, session_uid: &str) -> String {
    format!("{}{}", super::topic_exchange(), derive_key_for_topic(topic_salt, session_uid))
}

/// MQTT_GenerateClientID: "{desc[:2]}-{cidhash[:8]}-{8 random alnum}" (≤23 chars).
/// Go seeds math/rand from crypto/rand; uniqueness is all that matters.
pub fn mqtt_generate_client_id(topic_desc: &str, session_uid: &str) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..8)
        .map(|_| CHARSET[rand::Rng::gen_range(&mut rng, 0..CHARSET.len())] as char)
        .collect();
    let cid_l8 = derive_key_for_topic("mqtt-topic-gonc-cid", session_uid)[..8].to_string();
    format!("{}-{}-{}", &topic_desc[..2.min(topic_desc.len())], cid_l8, suffix)
}

#[allow(deprecated)]
pub fn encrypt_aes(key: &[u8; 32], plaintext: &[u8]) -> Result<SecurePayload> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| P2pError::msg(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload::from(plaintext))
        .map_err(|_| P2pError::msg("aes-gcm encrypt failed"))?;
    Ok(SecurePayload {
        nonce: b64().encode(nonce_bytes),
        data: b64().encode(ciphertext),
    })
}

#[allow(deprecated)]
pub fn decrypt_aes(key: &[u8; 32], payload: &SecurePayload) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| P2pError::msg(e.to_string()))?;
    let nonce_bytes = b64()
        .decode(payload.nonce.as_bytes())
        .map_err(|e| P2pError::msg(format!("failed to decode nonce: {}", e)))?;
    let ciphertext = b64()
        .decode(payload.data.as_bytes())
        .map_err(|e| P2pError::msg(format!("failed to decode data: {}", e)))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), Payload::from(ciphertext.as_slice()))
        .map_err(|_| P2pError::msg("aes-gcm decrypt failed"))
}

// ============ P-256 key exchange ============

pub struct EcdhKeyPair {
    secret: SecretKey,
    pub public_b64: String,
}

impl EcdhKeyPair {
    /// Fixed-secret constructor for cross-implementation vectors only.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn from_secret_slice(bytes: &[u8; 32]) -> Result<Self> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| P2pError::msg("invalid secret"))?;
        let public = secret.public_key();
        Ok(EcdhKeyPair {
            public_b64: b64().encode(public.to_sec1_bytes()),
            secret,
        })
    }

    pub fn generate() -> Result<Self> {
        let secret = SecretKey::random(&mut rand::rngs::OsRng);
        let public = secret.public_key();
        // Go: elliptic.Marshal → uncompressed SEC1 (0x04 || X || Y, 65 bytes).
        let sec1 = public.to_sec1_bytes();
        if sec1.len() != 65 {
            return Err(P2pError::msg("unexpected P-256 public key encoding"));
        }
        Ok(EcdhKeyPair {
            secret,
            public_b64: b64().encode(sec1),
        })
    }

    /// sha256 of the ECDH shared X coordinate, mirroring Go's
    /// `sha256.Sum256(sharedX.Bytes())` (leading zero bytes stripped).
    pub fn shared_key(&self, peer_public_b64: &str) -> Result<[u8; 32]> {
        let peer_bytes = b64()
            .decode(peer_public_b64.as_bytes())
            .map_err(|e| P2pError::msg(format!("failed to decode peer's public key: {}", e)))?;
        let peer_public = PublicKey::from_sec1_bytes(&peer_bytes)
            .map_err(|_| P2pError::msg("invalid peer public key"))?;
        let shared = diffie_hellman(self.secret.to_nonzero_scalar(), *peer_public.as_affine());
        let raw: &[u8; 32] = shared.raw_secret_bytes().as_ref();
        let stripped = raw
            .iter()
            .position(|b| *b != 0)
            .map(|i| &raw[i..])
            .unwrap_or(&raw[0..0]);
        let mut h = Sha256::new();
        h.update(stripped);
        Ok(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors generated by the Go implementation (see tests/go_vectors.md).
    #[test]
    fn md5_matches_go() {
        assert_eq!(calculate_md5(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(calculate_md5("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn topic_derivation_is_stable() {
        // Go: deriveKeyForTopic("wgvpn-kx/", "demo-token-kx")
        let topic = derive_key_for_topic("wgvpn-kx/", "demo-token-kx");
        assert_eq!(topic.len(), 16);
        // Manual sha256 check: sha256("wgvpn-kx/" || md5hex("demo-token-kx"))[:16]
        let md5hex = calculate_md5("demo-token-kx");
        let mut h = Sha256::new();
        h.update(b"wgvpn-kx/");
        h.update(md5hex.as_bytes());
        assert_eq!(topic, hex(&h.finalize())[..16]);
    }

    #[test]
    fn punch_payload_is_8_ascii_chars() {
        let p = derive_key_for_payload("token", true);
        assert_eq!(p.len(), 8);
        assert!(p.iter().all(|b| b.is_ascii()));
    }

    #[test]
    fn punch_payload_binary_matches_sha256_prefix() {
        let p = derive_key_for_payload("token", false);
        let md5hex = calculate_md5("token");
        let mut h = Sha256::new();
        h.update(b"gonc-p2p-payload");
        h.update(md5hex.as_bytes());
        assert_eq!(&p[..], &h.finalize()[..8]);
    }

    #[test]
    fn secure_payload_roundtrip() {
        let key = derive_key("mqtt-exchange-gonc-v2.2.0", "uid");
        let plaintext = b"{\"addrs\":[],\"pk\":\"\"}";
        let payload = encrypt_aes(&key, plaintext).unwrap();
        let decoded = decrypt_aes(&key, &payload).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn derive_key_matches_nested_sha256() {
        // Go: deriveKey(salt, uid) = sha256(sha256("nc-p2p-tool" || salt || uid))
        let key = derive_key("mqtt-exchange-gonc-v2.2.0", "abc");
        let mut h = Sha256::new();
        h.update(b"nc-p2p-tool");
        h.update(b"mqtt-exchange-gonc-v2.2.0");
        h.update(b"abc");
        let inner = h.finalize();
        let mut h2 = Sha256::new();
        h2.update(inner);
        assert_eq!(key.as_slice(), &h2.finalize()[..]);
    }

    #[test]
    fn ecdh_shared_key_symmetry() {
        let a = EcdhKeyPair::generate().unwrap();
        let b = EcdhKeyPair::generate().unwrap();
        let ka = a.shared_key(&b.public_b64).unwrap();
        let kb = b.shared_key(&a.public_b64).unwrap();
        assert_eq!(ka, kb);
    }

    // ===== Cross-implementation vectors generated by tests/go-vector/main.go =====

    #[test]
    fn go_vectors_topics_and_payloads() {
        assert_eq!(calculate_md5("demo-token-kx"), "6de54b2c7e3b829a818a25f54feb84a1");
        assert_eq!(derive_key_for_topic("wgvpn-kx/", "demo-token-kx"), "385311916d1473c9");
        assert_eq!(derive_key_for_topic("gonc-exchange-address", "p2p-token"), "1eaa4255f9986798");
        assert_eq!(derive_key_for_topic("mqtt-topic-gonc-cid", "p2p-token")[..8], *"611b3d2b");
        assert_eq!(derive_key_for_payload("p2p-token", true), b"5504bc1f".to_vec());
        assert_eq!(hex(&derive_key_for_payload("p2p-token", false)), "5504bc1ff686341a");
        let key = derive_key("mqtt-exchange-gonc-v2.2.0", "uid-123");
        assert_eq!(
            hex(&key),
            "128d1064cf027b86e3663a6cf5538f795c14e9d8379bcde628ba12d4b0cb8955"
        );
    }

    #[test]
    fn go_vector_aes_decrypt() {
        // Encrypted by Go with derive_key("mqtt-exchange-gonc-v2.2.0", "uid-123").
        let key = derive_key("mqtt-exchange-gonc-v2.2.0", "uid-123");
        let payload = SecurePayload {
            nonce: "dBu4GjZC89v4o4U0".into(),
            data: "SKdaqQa8Cxuv+Nryw6xNLzc3g5RhvaLQVOn6lErkBdRfrWiZ".into(),
        };
        let plain = decrypt_aes(&key, &payload).unwrap();
        assert_eq!(plain, br#"{"addrs":[],"pk":""}"#.to_vec());
    }

    #[test]
    fn go_vector_ecdh_fixed_scalars() {
        let d1: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x13, 0x24, 0x35, 0x46,
            0x57, 0x68, 0x79, 0x2f,
        ];
        let d2: [u8; 32] = [
            0x04, 0x56, 0x89, 0xac, 0xdf, 0x11, 0x24, 0x57, 0x8a, 0xce, 0x01, 0x34, 0x67, 0x9a,
            0xcd, 0xf0, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0x0f, 0x1e, 0xc1,
        ];
        let a = EcdhKeyPair::from_secret_slice(&d1).unwrap();
        let b = EcdhKeyPair::from_secret_slice(&d2).unwrap();
        // Go: elliptic.Marshal(d1 pub) base64
        assert_eq!(
            a.public_b64,
            "BPY5ZQK2i6lqLZE9QDW+7FYZc5pWYrCOig5MaJ16hDHz/lWYnZGGWux0vVCQXjCGw7HwJqlfYvS/8h03voSnqXA="
        );
        let shared = a.shared_key(&b.public_b64).unwrap();
        assert_eq!(
            hex(&shared),
            "011e364f9f70359f0b1cd866ff58109dded964b8b5e8202fdf43c806cc1fccb4"
        );
    }
}
