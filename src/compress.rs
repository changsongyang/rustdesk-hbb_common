//! zstd 压缩和解压缩模块
//!
//! 提供高性能的 zstd 压缩和解压缩功能，具有自动容错和线程安全。
//!
//! # 示例
//!
//! ```
//! let data = b"Hello, World!";
//! let compressed = compress(data);
//! let decompressed = decompress(&compressed);
//! assert_eq!(data, decompressed.as_slice());
//! ```

use std::{cell::RefCell, io};
use zstd::bulk::Compressor;

/// 最大支持的压缩数据大小（100MB），防止过大的内存分配
const MAX_COMPRESS_SIZE: usize = 100 * 1024 * 1024;

/// zstd 压缩级别常量（参考文档）
/// - 支持 1-22 级，级别越高压缩率越高但速度越慢
/// - 默认级别为 3（由 ZSTD_CLEVEL_DEFAULT 定义）
/// - 0 表示使用默认级别
const _ZSTD_MIN_LEVEL: i32 = 1;
const _ZSTD_MAX_LEVEL: i32 = 22;

/// 线程局部的 zstd 压缩器
///
/// 使用线程局部存储以避免每次压缩时重新初始化压缩器
/// 压缩器状态：RefCell 用于内部可变性，io::Result 用于处理初始化失败
thread_local! {
    static COMPRESSOR: RefCell<io::Result<Compressor<'static>>> = RefCell::new(Compressor::new(crate::config::COMPRESS_LEVEL));
}

/// 使用 zstd 算法压缩数据
///
/// # 参数
/// - `data`: 要压缩的字节切片
///
/// # 返回值
/// - 压缩后的数据，如果压缩失败则返回原始数据
///
/// # 特性
/// - 线程安全
/// - 自动容错：压缩失败时返回原始数据
/// - 自动恢复：压缩器失败时会自动重新初始化
/// - 备用方案：线程局部压缩器不可用时使用一次性压缩
///
/// # 示例
/// ```
/// let data = b"Test data for compression";
/// let compressed = compress(data);
/// ```
pub fn compress(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    if data.len() > MAX_COMPRESS_SIZE {
        crate::log::warn!(
            "Data size {} exceeds maximum compress size {}, returning original data",
            data.len(),
            MAX_COMPRESS_SIZE
        );
        return data.to_vec();
    }

    let mut result = data.to_vec();
    let mut used_thread_local = false;

    COMPRESSOR.with(|compressor_cell| {
        match compressor_cell.try_borrow_mut() {
            Ok(mut cell) => {
                if cell.is_err() {
                    crate::log::debug!("Reinitializing zstd compressor after previous failure");
                    *cell = Compressor::new(crate::config::COMPRESS_LEVEL);
                }

                match &mut *cell {
                    Ok(compressor) => {
                        match compressor.compress(data) {
                            Ok(compressed) => {
                                result = compressed;
                                used_thread_local = true;
                            }
                            Err(err) => {
                                crate::log::debug!("Failed to compress with thread-local: {}", err);
                            }
                        }
                    }
                    Err(err) => {
                        crate::log::debug!("Failed to initialize zstd compressor: {}", err);
                    }
                }
            }
            Err(_) => {
                crate::log::debug!("zstd compressor is already borrowed, will try one-time compression");
            }
        }
    });

    if !used_thread_local {
        match zstd::bulk::compress(data, crate::config::COMPRESS_LEVEL) {
            Ok(res) => result = res,
            Err(err) => {
                crate::log::debug!("One-time compression also failed: {}", err);
            }
        }
    }

    result
}

/// 解压缩 zstd 压缩的数据
///
/// # 参数
/// - `data`: 要解压缩的字节切片
///
/// # 返回值
/// - 解压缩后的数据，如果解压缩失败则返回原始数据
///
/// # 特性
/// - 容错设计：能处理无效或损坏的 zstd 数据
/// - 空数据安全：对空输入返回空
///
/// # 示例
/// ```
/// let compressed = compress(b"Test data");
/// let decompressed = decompress(&compressed);
/// ```
pub fn decompress(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    if data.len() > MAX_COMPRESS_SIZE {
        crate::log::warn!(
            "Data size {} exceeds maximum decompress size {}, returning original data",
            data.len(),
            MAX_COMPRESS_SIZE
        );
        return data.to_vec();
    }

    match zstd::decode_all(data) {
        Ok(decompressed) => decompressed,
        Err(_) => data.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let original = b"Hello, World! This is a comprehensive test string for zstd compression and decompression.";
        let compressed = compress(original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed.as_slice());
    }

    #[test]
    fn test_compress_empty_data() {
        let original = b"";
        let compressed = compress(original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed.as_slice());
    }

    #[test]
    fn test_compress_random_data() {
        let original: Vec<u8> = (0..=255).collect();
        let compressed = compress(&original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_compress_large_data() {
        let original = vec![0u8; 1024 * 1024];
        let compressed = compress(&original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_compress_large_random_data() {
        let original: Vec<u8> = (0..100000).map(|i| (i % 256) as u8).collect();
        let compressed = compress(&original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_decompress_invalid_data() {
        let invalid_data = b"this is definitely not valid zstd compressed data";
        let result = decompress(invalid_data);
        assert_eq!(result, invalid_data.to_vec());
    }

    #[test]
    fn test_decompress_partial_zstd_header() {
        let partial_header = &[0x28, 0xb5, 0x2f, 0xfd];
        let result = decompress(partial_header);
        assert_eq!(result, partial_header.to_vec());
    }

    #[test]
    fn test_decompress_corrupted_zstd() {
        let original = vec![0u8; 100];
        let compressed = compress(&original);
        let mut corrupted = compressed.clone();
        if !corrupted.is_empty() {
            let mid = corrupted.len() / 2;
            corrupted[mid] ^= 0xAA;
        }
        let result = decompress(&corrupted);
        assert_eq!(result, corrupted);
    }

    #[test]
    fn test_multiple_compress_decompress_calls() {
        let original = b"Testing multiple consecutive compression and decompression operations";
        
        for i in 0..20 {
            let compressed = compress(original);
            let decompressed = decompress(&compressed);
            assert_eq!(original, decompressed.as_slice(), "Failed at iteration {}", i);
        }
    }

    #[test]
    fn test_single_byte() {
        let original = &[42u8];
        let compressed = compress(original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed.as_slice());
    }

    #[test]
    fn test_single_byte_max() {
        let original = &[0xFFu8];
        let compressed = compress(original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed.as_slice());
    }

    #[test]
    fn test_repeating_pattern() {
        let original = b"RustDesk".repeat(5000);
        let compressed = compress(&original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_decompress_empty() {
        let result = decompress(b"");
        assert!(result.is_empty());
    }

    #[test]
    fn test_unicode_data() {
        let original = "你好，世界！こんにちは！Hello!".as_bytes();
        let compressed = compress(original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed.as_slice());
    }

    #[test]
    fn test_binary_data() {
        let original: Vec<u8> = (0..1000).map(|i| (i * 17) % 256).collect();
        let compressed = compress(&original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_various_sizes() {
        for size in [1, 10, 100, 1000, 10000, 100000] {
            let original: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let compressed = compress(&original);
            let decompressed = decompress(&compressed);
            assert_eq!(original, decompressed, "Failed for size {}", size);
        }
    }

    #[test]
    fn test_very_small_compression() {
        let small_data = b"xyz";
        let compressed = compress(small_data);
        let decompressed = decompress(&compressed);
        assert_eq!(small_data, decompressed.as_slice());
    }

    #[test]
    fn test_high_entropy_data() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let original: Vec<u8> = (0..5000).map(|_| rng.gen()).collect();
        let compressed = compress(&original);
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed);
    }
}
