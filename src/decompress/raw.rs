use std::io::{Read, Write};

use crate::crypto::ZipCrypto;
use crate::error::{AlzError, AlzResult};

const BUF_SIZE: usize = 32768;

/// Extract uncompressed data, optionally decrypting.
/// Returns the CRC32 of the extracted data.
pub fn extract_raw<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    size: u64,
    mut crypto: Option<&mut ZipCrypto>,
) -> AlzResult<u32> {
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = [0u8; BUF_SIZE];
    let mut remaining = size;

    while remaining > 0 {
        let to_read = (remaining as usize).min(BUF_SIZE);
        reader.read_exact(&mut buf[..to_read])?;

        let data = &mut buf[..to_read];
        if let Some(ref mut c) = crypto {
            c.decrypt(data);
        }

        hasher.update(data);
        writer.write_all(data).map_err(AlzError::CantOpenDestFile)?;
        remaining -= to_read as u64;
    }

    Ok(hasher.finalize())
}
