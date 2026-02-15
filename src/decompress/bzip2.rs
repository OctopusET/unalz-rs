use std::io::{Read, Write};

use crate::crypto::ZipCrypto;
use crate::error::{AlzError, AlzResult};

/// ALZ uses a modified bzip2 format incompatible with standard bzip2.
/// Not yet implemented.
pub fn extract_bzip2<R: Read, W: Write>(
    _reader: &mut R,
    _writer: &mut W,
    _compressed_size: u64,
    _crypto: Option<&mut ZipCrypto>,
) -> AlzResult<u32> {
    Err(AlzError::Bzip2Failed(
        "bzip2 decompression not yet supported".to_string(),
    ))
}
