use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::Mac;
use rustls::CipherSuite;
use sha2::{Sha256, Sha384};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub struct CipherSuiteInfo {
    pub suite: CipherSuite,
}

impl CipherSuiteInfo {
    pub fn from_id(id: u16) -> Option<Self> {
        let suite = CipherSuite::from(id);
        let name = format!("{:?}", suite);

        // Reject unknown suites
        if name.starts_with("Unknown") {
            return None;
        }

        // Only support AEAD suites (GCM or ChaCha20-Poly1305)
        if !name.contains("GCM") && !name.contains("CHACHA20") {
            return None;
        }

        Some(Self { suite })
    }

    pub fn key_len(&self) -> usize {
        let name = format!("{:?}", self.suite);
        // AES-128-GCM uses 16-byte key, AES-256-GCM and ChaCha20-Poly1305 use 32-byte key
        if name.contains("128") {
            16
        } else {
            32
        }
    }

    pub fn uses_sha384(&self) -> bool {
        let name = format!("{:?}", self.suite);
        name.contains("SHA384")
    }
}

#[derive(Debug, Clone)]
pub struct TlsSecrets {
    pub client_randoms: HashMap<String, ClientSecrets>,
    pub traffic_secrets: HashMap<String, TrafficSecrets>,
}

#[derive(Debug, Clone, Default)]
pub struct ClientSecrets {
    pub master_secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct TrafficSecrets {
    pub client_handshake_traffic_secret: Option<Vec<u8>>,
    pub server_handshake_traffic_secret: Option<Vec<u8>>,
    pub client_traffic_secret_0: Option<Vec<u8>>,
    pub server_traffic_secret_0: Option<Vec<u8>>,
    pub exporter_secret: Option<Vec<u8>>,
}

impl TlsSecrets {
    pub fn new() -> Self {
        TlsSecrets {
            client_randoms: HashMap::new(),
            traffic_secrets: HashMap::new(),
        }
    }

    pub fn parse_keylog(&mut self, data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let label = parts[0];
            let client_random = parts[1].to_lowercase();
            let Ok(secret) = hex::decode(parts[2]) else {
                continue;
            };

            match label {
                "CLIENT_RANDOM" => {
                    self.client_randoms.entry(client_random).or_default().master_secret = Some(secret);
                }
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => {
                    self.traffic_secrets.entry(client_random).or_default().client_handshake_traffic_secret = Some(secret);
                }
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                    self.traffic_secrets.entry(client_random).or_default().server_handshake_traffic_secret = Some(secret);
                }
                "CLIENT_TRAFFIC_SECRET_0" => {
                    self.traffic_secrets.entry(client_random).or_default().client_traffic_secret_0 = Some(secret);
                }
                "SERVER_TRAFFIC_SECRET_0" => {
                    self.traffic_secrets.entry(client_random).or_default().server_traffic_secret_0 = Some(secret);
                }
                "EXPORTER_SECRET" => {
                    self.traffic_secrets.entry(client_random).or_default().exporter_secret = Some(secret);
                }
                _ => {}
            }
        }
    }
}

impl Default for TlsSecrets {
    fn default() -> Self {
        Self::new()
    }
}

pub fn derive_key_iv(secret: &[u8], key_len: usize) -> (Vec<u8>, Vec<u8>) {
    let key_info = hkdf_expand_label(b"key", b"", key_len);
    let iv_info = hkdf_expand_label(b"iv", b"", 12);
    let mut key = vec![0u8; key_len];
    let mut iv = vec![0u8; 12];

    if secret.len() >= 48 {
        let hkdf = Hkdf::<Sha384>::from_prk(secret).unwrap();
        hkdf.expand(&key_info, &mut key).unwrap();
        hkdf.expand(&iv_info, &mut iv).unwrap();
    } else {
        let hkdf = Hkdf::<Sha256>::from_prk(secret).unwrap();
        hkdf.expand(&key_info, &mut key).unwrap();
        hkdf.expand(&iv_info, &mut iv).unwrap();
    }

    (key, iv)
}

fn hkdf_expand_label(label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());

    let tls_label = [b"tls13 ", label].concat();
    info.push(tls_label.len() as u8);
    info.extend_from_slice(&tls_label);

    info.push(context.len() as u8);
    info.extend_from_slice(context);

    info
}

pub struct DecryptedRecord {
    pub content_type: u8,
    pub data: Vec<u8>,
}

pub fn decrypt_tls13_record(
    ciphertext: &[u8],
    secret: &[u8],
    sequence_number: u64,
    record_length: u16,
) -> Option<Vec<u8>> {
    decrypt_tls13_record_full(ciphertext, secret, sequence_number, record_length)
        .filter(|r| r.content_type == 23)
        .map(|r| r.data)
}

pub fn decrypt_tls13_record_full(
    ciphertext: &[u8],
    secret: &[u8],
    sequence_number: u64,
    record_length: u16,
) -> Option<DecryptedRecord> {
    if ciphertext.len() < 16 {
        return None;
    }

    let key_len = if secret.len() >= 48 { 32 } else { 16 };
    let (key, iv) = derive_key_iv(secret, key_len);

    let mut nonce = iv.clone();
    let seq_bytes = sequence_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }

    let nonce = Nonce::from_slice(&nonce);
    let aad = [
        23u8,
        0x03, 0x03,
        (record_length >> 8) as u8,
        (record_length & 0xff) as u8,
    ];

    let payload = Payload {
        msg: ciphertext,
        aad: &aad,
    };

    let result = if key_len == 32 {
        Aes256Gcm::new_from_slice(&key).ok()?.decrypt(nonce, payload).ok()?
    } else {
        Aes128Gcm::new_from_slice(&key).ok()?.decrypt(nonce, payload).ok()?
    };

    if result.is_empty() {
        return None;
    }

    let mut end = result.len();
    while end > 0 && result[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return None;
    }

    let content_type = result[end - 1];
    Some(DecryptedRecord {
        content_type,
        data: result[..end - 1].to_vec(),
    })
}

#[derive(Debug)]
pub struct TlsRecord {
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
    pub payload: Vec<u8>,
}

pub fn parse_tls_records(data: &[u8]) -> Vec<TlsRecord> {
    let mut records = Vec::new();
    let mut pos = 0;

    while pos + 5 <= data.len() {
        let content_type = data[pos];
        let version = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
        let length = u16::from_be_bytes([data[pos + 3], data[pos + 4]]);

        let payload_end = pos + 5 + length as usize;
        if payload_end > data.len() {
            break;
        }

        records.push(TlsRecord {
            content_type,
            version,
            length,
            payload: data[pos + 5..payload_end].to_vec(),
        });

        pos = payload_end;
    }

    records
}

pub fn extract_client_random(data: &[u8]) -> Option<String> {
    if data.len() < 38 || data[0] != 1 {
        return None;
    }
    Some(hex::encode(&data[6..38]))
}

pub fn extract_server_random(data: &[u8]) -> Option<String> {
    if data.len() < 38 || data[0] != 2 {
        return None;
    }
    Some(hex::encode(&data[6..38]))
}

pub fn extract_cipher_suite(data: &[u8]) -> Option<u16> {
    if data.len() < 39 || data[0] != 2 {
        return None;
    }

    let session_id_len = data[38] as usize;
    let offset = 39 + session_id_len;

    if data.len() < offset + 2 {
        return None;
    }

    Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn tls12_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    type HmacSha256 = Hmac<Sha256>;

    let mut result = Vec::with_capacity(output_len);
    let mut full_seed = label.to_vec();
    full_seed.extend_from_slice(seed);
    let mut a = full_seed.clone();

    while result.len() < output_len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).unwrap();
        mac.update(&a);
        a = mac.finalize().into_bytes().to_vec();

        let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).unwrap();
        mac.update(&a);
        mac.update(&full_seed);
        result.extend_from_slice(&mac.finalize().into_bytes());
    }

    result.truncate(output_len);
    result
}

fn tls12_prf_sha384(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    type HmacSha384 = Hmac<Sha384>;

    let mut result = Vec::with_capacity(output_len);
    let mut full_seed = label.to_vec();
    full_seed.extend_from_slice(seed);
    let mut a = full_seed.clone();

    while result.len() < output_len {
        let mut mac = <HmacSha384 as Mac>::new_from_slice(secret).unwrap();
        mac.update(&a);
        a = mac.finalize().into_bytes().to_vec();

        let mut mac = <HmacSha384 as Mac>::new_from_slice(secret).unwrap();
        mac.update(&a);
        mac.update(&full_seed);
        result.extend_from_slice(&mac.finalize().into_bytes());
    }

    result.truncate(output_len);
    result
}

pub struct Tls12Keys {
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

pub fn derive_tls12_keys(
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    cipher_info: &CipherSuiteInfo,
) -> Tls12Keys {
    let mut seed = server_random.to_vec();
    seed.extend_from_slice(client_random);

    let key_len = cipher_info.key_len();
    let iv_len = 4; // GCM implicit IV
    let key_block_len = 2 * key_len + 2 * iv_len;

    let key_block = if cipher_info.uses_sha384() {
        tls12_prf_sha384(master_secret, b"key expansion", &seed, key_block_len)
    } else {
        tls12_prf_sha256(master_secret, b"key expansion", &seed, key_block_len)
    };

    let mut pos = 0;
    let client_write_key = key_block[pos..pos + key_len].to_vec();
    pos += key_len;
    let server_write_key = key_block[pos..pos + key_len].to_vec();
    pos += key_len;
    let client_write_iv = key_block[pos..pos + iv_len].to_vec();
    pos += iv_len;
    let server_write_iv = key_block[pos..pos + iv_len].to_vec();

    Tls12Keys {
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    }
}

pub fn decrypt_tls12_record(
    ciphertext: &[u8],
    key: &[u8],
    implicit_iv: &[u8],
    sequence_number: u64,
    content_type: u8,
) -> Option<Vec<u8>> {
    if ciphertext.len() < 24 {
        return None;
    }

    let explicit_nonce = &ciphertext[0..8];
    let encrypted = &ciphertext[8..];

    let mut nonce = implicit_iv.to_vec();
    nonce.extend_from_slice(explicit_nonce);

    let plaintext_len = encrypted.len().checked_sub(16)?;
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&sequence_number.to_be_bytes());
    aad.push(content_type);
    aad.extend_from_slice(&[0x03, 0x03]);
    aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

    let nonce = Nonce::from_slice(&nonce);
    let payload = Payload {
        msg: encrypted,
        aad: &aad,
    };

    if key.len() == 32 {
        Aes256Gcm::new_from_slice(key).ok()?.decrypt(nonce, payload).ok()
    } else {
        Aes128Gcm::new_from_slice(key).ok()?.decrypt(nonce, payload).ok()
    }
}
