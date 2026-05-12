use std::{cell::RefCell, io};
use zstd::bulk::Compressor;

// The library supports regular compression levels from 1 up to ZSTD_maxCLevel(),
// which is currently 22. Levels >= 20
// Default level is ZSTD_CLEVEL_DEFAULT==3.
// value 0 means default, which is controlled by ZSTD_CLEVEL_DEFAULT
thread_local! {
    static COMPRESSOR: RefCell<io::Result<Compressor<'static>>> = RefCell::new(Compressor::new(crate::config::COMPRESS_LEVEL));
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut used_thread_local = false;
    let mut out = Vec::new();
    COMPRESSOR.with(|c| {
        if let Ok(mut c) = c.try_borrow_mut() {
            match &mut *c {
                Ok(c) => match c.compress(data) {
                    Ok(res) => {
                        out = res;
                        used_thread_local = true;
                    },
                    Err(err) => {
                        crate::log::debug!("Failed to compress with thread-local: {}", err);
                    }
                },
                Err(err) => {
                    crate::log::debug!("Failed to get compressor: {}", err);
                }
            }
        }
    });
    if !used_thread_local {
        if let Ok(res) = zstd::bulk::compress(data, crate::config::COMPRESS_LEVEL) {
            out = res;
        }
    }
    out
}

pub fn decompress(data: &[u8]) -> Vec<u8> {
    zstd::decode_all(data).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let original = b"Hello, World! This is a test string for compression.";
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
        let original = vec![0u8; 1024 * 1024]; // 1MB of zeros
        let compressed = compress(&original);
        // Compression should reduce size significantly for repetitive data
        assert!(compressed.len() < original.len());
        let decompressed = decompress(&compressed);
        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_decompress_invalid_data() {
        let invalid_data = b"not valid zstd data";
        let result = decompress(invalid_data);
        // Should return empty vec for invalid data (unwrap_or_default)
        assert!(result.is_empty());
    }
}
