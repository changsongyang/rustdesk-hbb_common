use crate::config::Config;
use sodiumoxide::base64;
use std::sync::{Arc, RwLock};

/// 密码加密错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptError {
    /// 密钥派生失败
    KeyDerivationFailed,
    /// Nonce 长度无效
    InvalidNonceLength,
    /// 解密失败
    DecryptionFailed,
    /// 数据为空
    EmptyData,
}

impl std::fmt::Display for CryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptError::KeyDerivationFailed => write!(f, "密钥派生失败"),
            CryptError::InvalidNonceLength => write!(f, "Nonce 长度无效"),
            CryptError::DecryptionFailed => write!(f, "解密失败"),
            CryptError::EmptyData => write!(f, "数据为空"),
        }
    }
}

impl std::error::Error for CryptError {}

/// 密码加密使用的固定盐值（32字节）
///
/// 安全设计说明：
/// 1. 使用固定盐值是**有意为之**，目的是确保同一设备（相同 UUID）始终派生相同的密钥
/// 2. 这允许跨会话保持加密数据的可解密性，无需存储额外的盐值
/// 3. 安全性依赖于：
///    - UUID 的保密性（设备唯一且不公开）
///    - 高强度的 Argon2id KDF 算法
///    - 足够的计算复杂度（OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE）
/// 4. 如果 UUID 泄露，固定盐值确实会降低暴力破解难度，但由于使用了 Argon2id，
///    攻击者仍需付出巨大的计算代价
///
/// 兼容性说明：
/// - 修改此盐值将导致现有加密数据无法解密
/// - 如需升级，应实现版本化密钥派生机制
const ENCRYPTION_KEY_SALT: sodiumoxide::crypto::pwhash::Salt = sodiumoxide::crypto::pwhash::Salt([
    0x72, 0x75, 0x73, 0x74, 0x64, 0x65, 0x73, 0x6b, // "rustdesk"
    0x5f, 0x6b, 0x65, 0x79, 0x73, 0x61, 0x6c, 0x74, // "_keysalt"
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

lazy_static::lazy_static! {
    /// 临时密码的全局存储（线程安全）
    pub static ref TEMPORARY_PASSWORD: Arc<RwLock<String>> =
        Arc::new(RwLock::new(get_auto_password()));
}

/// 密码验证方式枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationMethod {
    /// 仅使用临时密码
    OnlyUseTemporaryPassword,
    /// 仅使用永久密码
    OnlyUsePermanentPassword,
    /// 两种密码都可使用
    UseBothPasswords,
}

/// 批准模式枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveMode {
    /// 密码和点击都需要
    Both,
    /// 仅需要密码
    Password,
    /// 仅需要点击确认
    Click,
}

/// 生成自动密码
fn get_auto_password() -> String {
    let len = temporary_password_length();
    if Config::get_bool_option(crate::config::keys::OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD) {
        Config::get_auto_numeric_password(len)
    } else {
        Config::get_auto_password(len)
    }
}

/// 更新临时密码（仅应在服务端调用）
pub fn update_temporary_password() {
    *TEMPORARY_PASSWORD.write().unwrap() = get_auto_password();
}

/// 获取临时密码（仅应在服务端调用）
pub fn temporary_password() -> String {
    TEMPORARY_PASSWORD.read().unwrap().clone()
}

/// 获取当前配置的密码验证方式
fn verification_method() -> VerificationMethod {
    let method = Config::get_option("verification-method");
    if method == "use-temporary-password" {
        VerificationMethod::OnlyUseTemporaryPassword
    } else if method == "use-permanent-password" {
        VerificationMethod::OnlyUsePermanentPassword
    } else {
        VerificationMethod::UseBothPasswords // 默认值
    }
}

/// 获取临时密码长度
pub fn temporary_password_length() -> usize {
    Config::get_option("temporary-password-length")
        .parse()
        .unwrap_or(6)
}

pub fn temporary_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUsePermanentPassword
}

pub fn permanent_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUseTemporaryPassword
}

pub fn has_valid_password() -> bool {
    temporary_enabled() && !temporary_password().is_empty()
        || permanent_enabled() && Config::has_permanent_password()
}

pub fn approve_mode() -> ApproveMode {
    let mode = Config::get_option("approve-mode");
    if mode == "password" {
        ApproveMode::Password
    } else if mode == "click" {
        ApproveMode::Click
    } else {
        ApproveMode::Both
    }
}

pub fn hide_cm() -> bool {
    approve_mode() == ApproveMode::Password
        && verification_method() == VerificationMethod::OnlyUsePermanentPassword
        && crate::config::option2bool("allow-hide-cm", &Config::get_option("allow-hide-cm"))
}

const VERSION_LEN: usize = 2;

/// Current password encryption version
pub const PASSWORD_ENC_VERSION: &str = "00";

// Check if data is already encrypted by verifying:
// 1) version prefix "00"
// 2) valid base64 payload
// 3) decoded payload length >= secretbox::MACBYTES
//
// We intentionally avoid trying to decrypt here because key mismatch would cause
// false negatives.
// Reference: secretbox::seal returns ciphertext length = plaintext length + MACBYTES
// https://github.com/sodiumoxide/sodiumoxide/blob/3057acb1a030ad86ed8892a223d64036ab5e8523/src/crypto/secretbox/xsalsa20poly1305.rs#L67
fn is_encrypted(v: &[u8]) -> bool {
    if v.len() <= VERSION_LEN || !v.starts_with(b"00") {
        return false;
    }
    match base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
        Ok(decoded) => decoded.len() >= sodiumoxide::crypto::secretbox::MACBYTES,
        Err(_) => false,
    }
}

pub fn encrypt_str_or_original(s: &str, version: &str, max_len: usize) -> String {
    if is_encrypted(s.as_bytes()) {
        log::warn!("重复加密，返回原始数据");
        return s.to_owned();
    }
    if s.chars().count() > max_len {
        return String::default();
    }
    if version == "00" {
        if let Ok(s) = encrypt(s.as_bytes()) {
            return version.to_owned() + &s;
        }
    }
    s.to_owned()
}

// String: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
// note: s.len() return length in bytes, s.chars().count() return char count
//       &[..2] return the left 2 bytes, s.chars().take(2) return the left 2 chars
pub fn decrypt_str_or_original(s: &str, current_version: &str) -> (String, bool, bool) {
    if s.len() > VERSION_LEN && s.starts_with("00") {
        if let Ok(v) = decrypt(&s.as_bytes()[VERSION_LEN..]) {
            return (
                String::from_utf8_lossy(&v).to_string(),
                true,
                "00" != current_version,
            );
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (
        s.to_owned(),
        false,
        !s.is_empty() && !is_encrypted(s.as_bytes()),
    )
}

pub fn encrypt_vec_or_original(v: &[u8], version: &str, max_len: usize) -> Vec<u8> {
    if is_encrypted(v) {
        log::warn!("重复加密，返回原始数据");
        return v.to_owned();
    }
    if v.len() > max_len {
        return vec![];
    }
    if version == "00" {
        if let Ok(s) = encrypt(v) {
            let mut version = version.to_owned().into_bytes();
            version.append(&mut s.into_bytes());
            return version;
        }
    }
    v.to_owned()
}

// Vec<u8>: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
pub fn decrypt_vec_or_original(v: &[u8], current_version: &str) -> (Vec<u8>, bool, bool) {
    if v.len() > VERSION_LEN {
        let version = String::from_utf8_lossy(&v[..VERSION_LEN]);
        if version == "00" {
            if let Ok(v) = decrypt(&v[VERSION_LEN..]) {
                return (v, true, version != current_version);
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (v.to_owned(), false, !v.is_empty() && !is_encrypted(v))
}

fn encrypt(v: &[u8]) -> Result<String, CryptError> {
    if !v.is_empty() {
        symmetric_crypt(v, true).map(|v| base64::encode(v, base64::Variant::Original))
    } else {
        Err(CryptError::EmptyData)
    }
}

fn decrypt(v: &[u8]) -> Result<Vec<u8>, CryptError> {
    if !v.is_empty() {
        base64::decode(v, base64::Variant::Original)
            .map_err(|_| CryptError::DecryptionFailed)
            .and_then(|v| symmetric_crypt(&v, false))
    } else {
        Err(CryptError::EmptyData)
    }
}

/// 使用 XSalsa20-Poly1305 算法进行对称加密/解密
///
/// 安全性说明：
/// - 使用设备 UUID 通过 KDF 派生加密密钥
/// - 每次加密使用随机生成的 nonce（24字节）
/// - 密文格式：[nonce(24字节)][ciphertext + tag(16字节)]
///
/// # 参数
/// - `data`: 要加密或解密的数据
/// - `encrypt`: true 表示加密，false 表示解密
///
/// # 返回值
/// - Ok(Vec<u8>): 成功时返回加密/解密后的数据
/// - Err(CryptError): 失败时返回具体错误类型
pub fn symmetric_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, CryptError> {
    use sodiumoxide::crypto::pwhash;
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    if data.is_empty() {
        return Err(CryptError::EmptyData);
    }

    // 获取设备 UUID 作为密钥派生的输入
    let uuid = crate::get_uuid();

    // 使用密码学安全的密钥派生函数 KDF
    // 使用固定盐值确保同一设备上的 UUID 始终派生相同的密钥
    let mut key = [0u8; secretbox::KEYBYTES];
    pwhash::derive_key(
        &mut key,
        uuid.as_slice(),
        &ENCRYPTION_KEY_SALT,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| CryptError::KeyDerivationFailed)?;
    let key = secretbox::Key(key);

    if encrypt {
        // 生成随机 nonce（避免密钥重用攻击）
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(data, &nonce, &key);
        // 将 nonce 附加到密文前面，解密时需要使用相同的 nonce
        let mut result = Vec::with_capacity(nonce.0.len() + encrypted.len());
        result.extend_from_slice(&nonce.0);
        result.extend_from_slice(&encrypted);
        Ok(result)
    } else {
        // 从数据开头提取 nonce
        if data.len() < secretbox::NONCEBYTES {
            return Err(CryptError::InvalidNonceLength);
        }
        let nonce_bytes: [u8; secretbox::NONCEBYTES] = data[..secretbox::NONCEBYTES]
            .try_into()
            .map_err(|_| CryptError::InvalidNonceLength)?;
        let nonce = secretbox::Nonce(nonce_bytes);
        let ciphertext = &data[secretbox::NONCEBYTES..];

        let res = secretbox::open(ciphertext, &nonce, &key);

        // 降级处理：如果使用 UUID 解密失败，尝试使用公钥（兼容旧版本）
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if res.is_err() {
            if let Some(key_pair) = Config::get_existing_key_pair() {
                let pk = key_pair.1;
                if pk != uuid {
                    let mut pk_key = [0u8; secretbox::KEYBYTES];
                    pwhash::derive_key(
                        &mut pk_key,
                        pk.as_slice(),
                        &ENCRYPTION_KEY_SALT,
                        pwhash::OPSLIMIT_INTERACTIVE,
                        pwhash::MEMLIMIT_INTERACTIVE,
                    )
                    .map_err(|_| CryptError::KeyDerivationFailed)?;
                    let pk_key = secretbox::Key(pk_key);
                    return secretbox::open(ciphertext, &nonce, &pk_key)
                        .map_err(|_| CryptError::DecryptionFailed);
                }
            }
        }
        res.map_err(|_| CryptError::DecryptionFailed)
    }
}

mod test {

    #[test]
    fn test() {
        use super::*;
        use rand::{thread_rng, Rng};
        use std::time::Instant;

        let version = "00";
        let max_len = 128;

        println!("test str");
        let data = "1ü1111";
        let encrypted = encrypt_str_or_original(data, version, max_len);
        let (decrypted, succ, store) = decrypt_str_or_original(&encrypted, version);
        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(version, &encrypted[..2]);
        assert!(succ);
        assert!(!store);
        let (_, _, store) = decrypt_str_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_str_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_str_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test vec");
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        let encrypted = encrypt_vec_or_original(&data, version, max_len);
        let (decrypted, succ, store) = decrypt_vec_or_original(&encrypted, version);
        println!("data: {data:?}");
        println!("encrypted: {encrypted:?}");
        println!("decrypted: {decrypted:?}");
        assert_eq!(data, decrypted);
        assert_eq!(version.as_bytes(), &encrypted[..2]);
        assert!(!store);
        assert!(succ);
        let (_, _, store) = decrypt_vec_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_vec_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_vec_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test original");
        let data = version.to_string() + "Hello World";
        let (decrypted, succ, store) = decrypt_str_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let verbytes = version.as_bytes();
        let data: Vec<u8> = vec![verbytes[0], verbytes[1], 1, 2, 3, 4, 5, 6];
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let (_, succ, store) = decrypt_str_or_original("", version);
        assert!(!store);
        assert!(!succ);
        let (_, succ, store) = decrypt_vec_or_original(&[], version);
        assert!(!store);
        assert!(!succ);
        let data = "1ü1111";
        assert_eq!(decrypt_str_or_original(data, version).0, data);
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        assert_eq!(decrypt_vec_or_original(&data, version).0, data);

        // Base64-shaped "00" prefixed values shorter than MACBYTES are treated
        // as original/plain values and should be stored.
        let data = "00YWJjZA==";
        let (decrypted, succ, store) = decrypt_str_or_original(data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
        let data = b"00YWJjZA==".to_vec();
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);

        // When decoded length reaches MACBYTES, it is treated as encrypted-like
        // and should not trigger repeated store.
        let exact_mac = vec![0u8; sodiumoxide::crypto::secretbox::MACBYTES];
        let exact_mac_b64 =
            sodiumoxide::base64::encode(&exact_mac, sodiumoxide::base64::Variant::Original);
        let data = format!("00{exact_mac_b64}");
        let (_, succ, store) = decrypt_str_or_original(&data, version);
        assert!(!succ);
        assert!(!store);
        let data = data.into_bytes();
        let (_, succ, store) = decrypt_vec_or_original(&data, version);
        assert!(!succ);
        assert!(!store);

        println!("test speed");
        let test_speed = |len: usize, name: &str| {
            let mut data: Vec<u8> = vec![];
            let mut rng = thread_rng();
            for _ in 0..len {
                data.push(rng.gen_range(0..255));
            }
            let start: Instant = Instant::now();
            let encrypted = encrypt_vec_or_original(&data, version, len);
            assert_ne!(data, decrypted);
            let t1 = start.elapsed();
            let start = Instant::now();
            let (decrypted, _, _) = decrypt_vec_or_original(&encrypted, version);
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("{name}");
            println!("encrypt:{:?}, decrypt:{:?}", t1, t2);

            let start: Instant = Instant::now();
            let encrypted = base64::encode(&data, base64::Variant::Original);
            let t1 = start.elapsed();
            let start = Instant::now();
            let decrypted = base64::decode(&encrypted, base64::Variant::Original).unwrap();
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("base64, encrypt:{:?}, decrypt:{:?}", t1, t2,);
        };
        test_speed(128, "128");
        test_speed(1024, "1k");
        test_speed(1024 * 1024, "1M");
        test_speed(10 * 1024 * 1024, "10M");
        test_speed(100 * 1024 * 1024, "100M");
    }

    #[test]
    fn test_is_encrypted() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;

        // Empty data should not be considered encrypted
        assert!(!is_encrypted(b""));
        assert!(!is_encrypted(b"0"));
        assert!(!is_encrypted(b"00"));

        // Data without "00" prefix should not be considered encrypted
        assert!(!is_encrypted(b"01abcd"));
        assert!(!is_encrypted(b"99abcd"));
        assert!(!is_encrypted(b"hello world"));

        // Data with "00" prefix but invalid base64 should not be considered encrypted
        assert!(!is_encrypted(b"00!!!invalid base64!!!"));
        assert!(!is_encrypted(b"00@#$%"));

        // Data with "00" prefix and valid base64 but shorter than MACBYTES is not encrypted
        assert!(!is_encrypted(b"00YWJjZA==")); // "abcd" in base64
        assert!(!is_encrypted(b"00SGVsbG8gV29ybGQ=")); // "Hello World" in base64

        // Data with "00" prefix and valid base64 with decoded len == MACBYTES is considered encrypted
        let exact_mac = vec![0u8; secretbox::MACBYTES];
        let exact_mac_b64 = encode(&exact_mac, Variant::Original);
        let exact_mac_candidate = format!("00{exact_mac_b64}");
        assert!(is_encrypted(exact_mac_candidate.as_bytes()));

        // Real encrypted data should be detected
        let version = "00";
        let max_len = 128;
        let encrypted_str = encrypt_str_or_original("1", version, max_len);
        assert!(is_encrypted(encrypted_str.as_bytes()));
        let encrypted_vec = encrypt_vec_or_original(b"1", version, max_len);
        assert!(is_encrypted(&encrypted_vec));

        // Original unencrypted data should not be detected as encrypted
        assert!(!is_encrypted(b"1"));
        assert!(!is_encrypted("1".as_bytes()));
    }

    #[test]
    fn test_encrypted_payload_min_len_macbytes() {
        use super::*;
        use sodiumoxide::base64::{decode, Variant};
        use sodiumoxide::crypto::secretbox;

        let version = "00";
        let max_len = 128;

        let encrypted_str = encrypt_str_or_original("1", version, max_len);
        let decoded = decode(&encrypted_str.as_bytes()[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );

        let encrypted_vec = encrypt_vec_or_original(b"1", version, max_len);
        let decoded = decode(&encrypted_vec[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );
    }

    /// 测试降级解密：当数据使用 key_pair 加密但解密尝试使用 machine_uid 时
    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_with_pk_fallback() {
        use super::ENCRYPTION_KEY_SALT;
        use sodiumoxide::crypto::pwhash;
        use sodiumoxide::crypto::secretbox;

        let uuid = crate::get_uuid();
        let pk = crate::config::Config::get_key_pair().1;

        // 确保 uuid != pk，否则无法测试降级分支
        if uuid == pk {
            eprintln!("skip: uuid == pk, fallback branch won't be tested");
            return;
        }

        let data = b"test password 123";
        let nonce = secretbox::gen_nonce();

        // 使用 KDF 派生 pk 密钥（与 symmetric_crypt 保持一致）
        let mut pk_key = [0u8; secretbox::KEYBYTES];
        pwhash::derive_key(
            &mut pk_key,
            pk.as_slice(),
            &ENCRYPTION_KEY_SALT,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let pk_key = secretbox::Key(pk_key);

        // Encrypt with pk (simulating machine_uid failure during encryption)
        let ciphertext = secretbox::seal(data, &nonce, &pk_key);

        // 将 nonce 附加到密文前面（与 symmetric_crypt 格式一致）
        let mut encrypted = Vec::with_capacity(nonce.0.len() + ciphertext.len());
        encrypted.extend_from_slice(&nonce.0);
        encrypted.extend_from_slice(&ciphertext);

        // Decrypt using symmetric_crypt (should fallback to pk since uuid differs)
        let decrypted = super::symmetric_crypt(&encrypted, false);
        if let Err(e) = &decrypted {
            panic!("解密失败: {}", e);
        }
        assert_eq!(decrypted.unwrap(), data);
    }
}
