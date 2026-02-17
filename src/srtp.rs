/// SRTP AES-128-CM + HMAC-SHA1-80 (RFC 3711).
///
/// Implements SDES key exchange via SDP a=crypto lines.
/// Provides encrypt_rtp() and decrypt_rtp() for the RTP data path.

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;

/// AES-128 in counter mode (custom implementation per RFC 3711 section 4.1.1).
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type HmacSha1 = Hmac<Sha1>;

/// SRTP auth tag length (10 bytes for HMAC-SHA1-80).
const AUTH_TAG_LEN: usize = 10;
/// Master key length (16 bytes for AES-128).
const MASTER_KEY_LEN: usize = 16;
/// Master salt length (14 bytes).
const MASTER_SALT_LEN: usize = 14;

/// SRTP key derivation labels (RFC 3711 section 4.3.1).
const LABEL_CIPHER_KEY: u8 = 0x00;
const LABEL_AUTH_KEY: u8 = 0x01;
const LABEL_SALT_KEY: u8 = 0x02;

/// SRTP context for encrypting/decrypting RTP packets.
pub struct SrtpContext {
    /// Derived session cipher key (16 bytes).
    cipher_key: [u8; 16],
    /// Derived session authentication key (20 bytes).
    auth_key: [u8; 20],
    /// Derived session salt (14 bytes).
    salt: [u8; 14],
    /// Roll-over counter (upper 32 bits of packet index).
    roc: u32,
    /// Last seen sequence number (for ROC tracking).
    last_seq: u16,
    /// Whether we've seen any packet yet.
    initialized: bool,
}

impl SrtpContext {
    /// Create a new SRTP context from master key and salt.
    pub fn new(master_key: &[u8], master_salt: &[u8]) -> Self {
        assert_eq!(master_key.len(), MASTER_KEY_LEN);
        assert_eq!(master_salt.len(), MASTER_SALT_LEN);

        let cipher_key = derive_key(master_key, master_salt, LABEL_CIPHER_KEY, 16);
        let auth_key = derive_key(master_key, master_salt, LABEL_AUTH_KEY, 20);
        let salt_key = derive_key(master_key, master_salt, LABEL_SALT_KEY, 14);

        let mut ck = [0u8; 16];
        ck.copy_from_slice(&cipher_key);
        let mut ak = [0u8; 20];
        ak.copy_from_slice(&auth_key);
        let mut sk = [0u8; 14];
        sk.copy_from_slice(&salt_key);

        Self {
            cipher_key: ck,
            auth_key: ak,
            salt: sk,
            roc: 0,
            last_seq: 0,
            initialized: false,
        }
    }

    /// Generate a random master key and salt for use in SDP.
    pub fn generate_key_salt() -> ([u8; MASTER_KEY_LEN], [u8; MASTER_SALT_LEN]) {
        let mut key = [0u8; MASTER_KEY_LEN];
        let mut salt = [0u8; MASTER_SALT_LEN];
        for b in key.iter_mut() { *b = rand::random(); }
        for b in salt.iter_mut() { *b = rand::random(); }
        (key, salt)
    }

    /// Format key+salt for SDP a=crypto inline parameter.
    pub fn key_salt_to_base64(key: &[u8], salt: &[u8]) -> String {
        use base64::Engine;
        let mut combined = Vec::with_capacity(key.len() + salt.len());
        combined.extend_from_slice(key);
        combined.extend_from_slice(salt);
        base64::engine::general_purpose::STANDARD.encode(&combined)
    }

    /// Parse key+salt from SDP a=crypto inline parameter.
    pub fn parse_key_salt(b64: &str) -> Option<([u8; MASTER_KEY_LEN], [u8; MASTER_SALT_LEN])> {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        if data.len() < MASTER_KEY_LEN + MASTER_SALT_LEN {
            return None;
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        let mut salt = [0u8; MASTER_SALT_LEN];
        key.copy_from_slice(&data[..MASTER_KEY_LEN]);
        salt.copy_from_slice(&data[MASTER_KEY_LEN..MASTER_KEY_LEN + MASTER_SALT_LEN]);
        Some((key, salt))
    }

    /// Encrypt an RTP packet in-place and append auth tag.
    ///
    /// Input: complete RTP packet (header + payload).
    /// Output: RTP header (unchanged) + encrypted payload + 10-byte auth tag.
    pub fn encrypt_rtp(&mut self, packet: &[u8]) -> Vec<u8> {
        if packet.len() < 12 {
            return packet.to_vec();
        }

        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        self.update_roc(seq);
        let index = ((self.roc as u64) << 16) | seq as u64;

        // Generate keystream
        let iv = self.compute_iv(ssrc, index);
        let payload_start = rtp_header_len(packet);
        let mut result = packet.to_vec();

        // Encrypt payload in-place
        let mut cipher = Aes128Ctr::new(
            (&self.cipher_key).into(),
            (&iv).into(),
        );
        cipher.apply_keystream(&mut result[payload_start..]);

        // Compute and append auth tag over header + encrypted payload + ROC
        let tag = self.compute_auth_tag(&result, self.roc);
        result.extend_from_slice(&tag);

        result
    }

    /// Decrypt an SRTP packet. Verifies auth tag and decrypts payload.
    ///
    /// Returns the decrypted RTP packet (without auth tag), or error.
    pub fn decrypt_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>, &'static str> {
        if packet.len() < 12 + AUTH_TAG_LEN {
            return Err("packet too short for SRTP");
        }

        let auth_portion_len = packet.len() - AUTH_TAG_LEN;
        let received_tag = &packet[auth_portion_len..];
        let rtp_data = &packet[..auth_portion_len];

        let seq = u16::from_be_bytes([rtp_data[2], rtp_data[3]]);
        let ssrc = u32::from_be_bytes([rtp_data[8], rtp_data[9], rtp_data[10], rtp_data[11]]);
        self.update_roc(seq);
        let index = ((self.roc as u64) << 16) | seq as u64;

        // Verify auth tag
        let expected_tag = self.compute_auth_tag(rtp_data, self.roc);
        if !constant_time_eq(received_tag, &expected_tag) {
            return Err("SRTP auth tag mismatch");
        }

        // Decrypt payload
        let iv = self.compute_iv(ssrc, index);
        let payload_start = rtp_header_len(rtp_data);
        let mut result = rtp_data.to_vec();

        let mut cipher = Aes128Ctr::new(
            (&self.cipher_key).into(),
            (&iv).into(),
        );
        cipher.apply_keystream(&mut result[payload_start..]);

        Ok(result)
    }

    /// Compute the AES-CM IV per RFC 3711 section 4.1.1.
    fn compute_iv(&self, ssrc: u32, index: u64) -> [u8; 16] {
        let mut iv = [0u8; 16];
        // IV = (salt XOR (ssrc || index)) left-padded to 16 bytes
        // salt is 14 bytes, placed at iv[2..16]
        // SSRC at iv[4..8], index at iv[8..14]
        iv[2..16].copy_from_slice(&self.salt);

        let ssrc_bytes = ssrc.to_be_bytes();
        for i in 0..4 {
            iv[4 + i] ^= ssrc_bytes[i];
        }

        let index_bytes = index.to_be_bytes();
        // index is 48-bit, use bytes 2..8 of the u64
        for i in 0..6 {
            iv[8 + i] ^= index_bytes[2 + i];
        }

        iv
    }

    /// Compute HMAC-SHA1-80 auth tag.
    fn compute_auth_tag(&self, rtp_data: &[u8], roc: u32) -> [u8; AUTH_TAG_LEN] {
        let mut mac = HmacSha1::new_from_slice(&self.auth_key)
            .expect("HMAC key length");
        mac.update(rtp_data);
        mac.update(&roc.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&result[..AUTH_TAG_LEN]);
        tag
    }

    /// Update ROC based on received sequence number.
    fn update_roc(&mut self, seq: u16) {
        if !self.initialized {
            self.last_seq = seq;
            self.initialized = true;
            return;
        }

        let delta = seq.wrapping_sub(self.last_seq) as i16;
        if delta > 0 {
            // Normal forward
            if seq < self.last_seq {
                // Wrapped around
                self.roc += 1;
            }
            self.last_seq = seq;
        }
        // For late/reordered packets, don't update ROC
    }
}

/// Derive a session key using SRTP KDF (RFC 3711 section 4.3).
fn derive_key(master_key: &[u8], master_salt: &[u8], label: u8, out_len: usize) -> Vec<u8> {
    // x = label || 0x000000 (7 bytes for RTP, padded to 14 bytes with salt)
    let mut x = [0u8; 14];
    x[7] = label; // label at byte 7

    // r = x XOR salt
    let mut r = [0u8; 14];
    for i in 0..14 {
        r[i] = x[i] ^ master_salt[i];
    }

    // Generate key stream using AES-CM with key_index = 0
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&r);
    // iv[14..16] = block counter, starts at 0

    let mut output = vec![0u8; out_len];
    let mut cipher = Aes128Ctr::new(
        master_key.into(),
        (&iv).into(),
    );
    cipher.apply_keystream(&mut output);

    output
}

/// Get RTP header length including CSRC and extension.
fn rtp_header_len(packet: &[u8]) -> usize {
    if packet.len() < 12 {
        return packet.len();
    }
    let cc = (packet[0] & 0x0F) as usize;
    let has_extension = (packet[0] >> 4) & 0x01 != 0;
    let mut offset = 12 + cc * 4;

    if has_extension && packet.len() >= offset + 4 {
        let ext_len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        offset += 4 + ext_len * 4;
    }

    offset.min(packet.len())
}

/// Constant-time comparison for auth tags.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srtp_roundtrip() {
        let (key, salt) = SrtpContext::generate_key_salt();
        let mut encrypt_ctx = SrtpContext::new(&key, &salt);
        let mut decrypt_ctx = SrtpContext::new(&key, &salt);

        // Build a test RTP packet
        let mut rtp = vec![0u8; 12 + 160]; // header + payload
        rtp[0] = 0x80; // V=2
        rtp[1] = 0; // PT=0
        rtp[2] = 0; rtp[3] = 1; // seq=1
        rtp[4..8].copy_from_slice(&100u32.to_be_bytes()); // timestamp
        rtp[8..12].copy_from_slice(&0xDEADBEEFu32.to_be_bytes()); // SSRC
        for i in 12..rtp.len() {
            rtp[i] = (i as u8).wrapping_mul(7); // test payload
        }

        let original = rtp.clone();
        let encrypted = encrypt_ctx.encrypt_rtp(&rtp);

        // Encrypted packet should be larger (auth tag)
        assert_eq!(encrypted.len(), rtp.len() + AUTH_TAG_LEN);
        // Payload should be different (encrypted)
        assert_ne!(&encrypted[12..12 + 160], &rtp[12..]);

        // Decrypt
        let decrypted = decrypt_ctx.decrypt_rtp(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_srtp_tampered_packet() {
        let (key, salt) = SrtpContext::generate_key_salt();
        let mut encrypt_ctx = SrtpContext::new(&key, &salt);
        let mut decrypt_ctx = SrtpContext::new(&key, &salt);

        let mut rtp = vec![0x80, 0, 0, 1, 0, 0, 0, 100, 0xDE, 0xAD, 0xBE, 0xEF];
        rtp.extend_from_slice(&[42u8; 160]);

        let mut encrypted = encrypt_ctx.encrypt_rtp(&rtp);
        // Tamper with payload
        encrypted[20] ^= 0xFF;

        let result = decrypt_ctx.decrypt_rtp(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_salt_base64_roundtrip() {
        let (key, salt) = SrtpContext::generate_key_salt();
        let b64 = SrtpContext::key_salt_to_base64(&key, &salt);
        let (key2, salt2) = SrtpContext::parse_key_salt(&b64).unwrap();
        assert_eq!(key, key2);
        assert_eq!(salt, salt2);
    }

    #[test]
    fn test_srtp_multiple_packets() {
        let (key, salt) = SrtpContext::generate_key_salt();
        let mut enc = SrtpContext::new(&key, &salt);
        let mut dec = SrtpContext::new(&key, &salt);

        for seq in 0u16..100 {
            let mut rtp = vec![0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            rtp[2..4].copy_from_slice(&seq.to_be_bytes());
            rtp[4..8].copy_from_slice(&(seq as u32 * 160).to_be_bytes());
            rtp.extend_from_slice(&[seq as u8; 160]);

            let encrypted = enc.encrypt_rtp(&rtp);
            let decrypted = dec.decrypt_rtp(&encrypted).unwrap();
            assert_eq!(decrypted, rtp);
        }
    }
}
