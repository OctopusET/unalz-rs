use std::io::{Read, Write};

use crate::crypto::ZipCrypto;
use crate::error::{AlzError, AlzResult};

/// ALZ bzip2 block header: "DLZ\x01"
const ALZ_BLOCK_MAGIC: [u8; 4] = [b'D', b'L', b'Z', 0x01];
/// ALZ bzip2 end-of-stream: "DLZ\x02"
const ALZ_EOS_MAGIC: [u8; 4] = [b'D', b'L', b'Z', 0x02];

/// Standard bzip2 stream header: "BZh9"
const BZ_STREAM_HEADER: [u8; 4] = [b'B', b'Z', b'h', b'9'];
/// Standard bzip2 block magic (48 bits, big-endian): pi digits 0x314159265359
const BZ_BLOCK_MAGIC: [u8; 6] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
/// Standard bzip2 end-of-stream magic (48 bits): sqrt(pi) digits 0x177245385090
const BZ_EOS_MAGIC: [u8; 6] = [0x17, 0x72, 0x45, 0x38, 0x50, 0x90];

/// Reconstruct a standard bzip2 stream from ALZ-modified bzip2 data.
///
/// ALZ bzip2 differs from standard bzip2:
/// - Stream header "BZh9" is absent (blockSize hardcoded to 9)
/// - Block magic is "DLZ\x01" (4 bytes) instead of 0x314159265359 (6 bytes)
/// - Per-block CRC (4 bytes) is absent
/// - Randomised bit (1 bit) is absent (hardcoded to 0)
/// - End-of-stream is "DLZ\x02" instead of 0x177245385090 + combined CRC
/// - Block payload (Huffman/MTF/BWT data) is identical
///
/// The reconstruction inserts a 0 randomised bit before origPtr, which
/// shifts all subsequent bits by 1 position. This is handled by a
/// bitstream writer.
fn alz_to_bzip2(alz_data: &[u8]) -> AlzResult<Vec<u8>> {
    let mut reader = BitReader::new(alz_data);
    let mut writer = BitWriter::new();

    // Stream header.
    writer.write_bytes(&BZ_STREAM_HEADER);

    loop {
        // Read ALZ block/EOS header (4 bytes from bitstream).
        let mut hdr = [0u8; 4];
        for b in &mut hdr {
            *b = reader.read_bits(8)? as u8;
        }

        if hdr == ALZ_EOS_MAGIC {
            // Write standard EOS magic + fake combined CRC.
            for &b in &BZ_EOS_MAGIC {
                writer.write_bits(b as u32, 8);
            }
            writer.write_bits(0, 32); // fake combined CRC
            break;
        }

        if hdr != ALZ_BLOCK_MAGIC {
            return Err(AlzError::Bzip2Failed(format!(
                "expected ALZ block header, got {:02x?}",
                hdr
            )));
        }

        // Write standard block magic.
        for &b in &BZ_BLOCK_MAGIC {
            writer.write_bits(b as u32, 8);
        }

        // Write fake block CRC (4 bytes).
        writer.write_bits(0, 32);

        // Write randomised = 0 (1 bit). This is absent in ALZ.
        writer.write_bits(0, 1);

        // Copy remaining bits until next block header.
        // We can't know the block boundary without decoding, so for
        // each block we copy bits one at a time until we peek "DLZ"
        // or run out of data.
        //
        // Since block headers are read via GET_UCHAR (8-bit reads from
        // the bitstream), we need to detect the DLZ pattern at the
        // current bit position. We peek 32 bits ahead to check.
        loop {
            if reader.bits_remaining() < 32 {
                // Copy remaining bits.
                while reader.bits_remaining() > 0 {
                    let n = reader.bits_remaining().min(8);
                    let v = reader.read_bits(n)?;
                    writer.write_bits(v, n);
                }
                break;
            }

            // Peek next 32 bits to check for ALZ header.
            let peek = reader.peek_bits(32)?;
            let peek_bytes = peek.to_be_bytes();
            if peek_bytes == ALZ_BLOCK_MAGIC || peek_bytes == ALZ_EOS_MAGIC {
                break; // Don't consume; outer loop reads the header.
            }

            // Not a header; copy 1 bit.
            let bit = reader.read_bits(1)?;
            writer.write_bits(bit, 1);
        }
    }

    writer.flush();
    Ok(writer.into_bytes())
}

/// Extract ALZ-modified bzip2 data.
/// Returns the CRC32 of the decompressed data.
pub fn extract_bzip2<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    compressed_size: u64,
    mut crypto: Option<&mut ZipCrypto>,
) -> AlzResult<u32> {
    // ALZ bzip2 blocks are at most 900KB uncompressed; reject absurdly large sizes.
    const MAX_BZ2_COMPRESSED: u64 = 512 * 1024 * 1024;
    if compressed_size > MAX_BZ2_COMPRESSED {
        return Err(AlzError::Bzip2Failed(format!(
            "compressed size {compressed_size} exceeds limit"
        )));
    }

    // Read all compressed data.
    let mut alz_data = vec![0u8; compressed_size as usize];
    reader.read_exact(&mut alz_data)?;
    if let Some(ref mut c) = crypto {
        c.decrypt(&mut alz_data);
    }

    // Reconstruct standard bzip2 stream.
    let bz_data = alz_to_bzip2(&alz_data)?;

    // Decompress using standard bzip2.
    let mut decompressor = bzip2::Decompress::new(false);
    let mut input_pos = 0;
    let mut hasher = crc32fast::Hasher::new();
    let mut tmp = [0u8; 32768];

    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();

        let result = decompressor.decompress(&bz_data[input_pos..], &mut tmp);

        let consumed = (decompressor.total_in() - before_in) as usize;
        let produced = (decompressor.total_out() - before_out) as usize;
        input_pos += consumed;

        if produced > 0 {
            hasher.update(&tmp[..produced]);
            writer
                .write_all(&tmp[..produced])
                .map_err(AlzError::CantOpenDestFile)?;
        }

        match result {
            Ok(bzip2::Status::Ok) => continue,
            Ok(bzip2::Status::MemNeeded) => {
                if consumed == 0 && produced == 0 {
                    break; // No progress.
                }
            }
            Ok(bzip2::Status::FlushOk | bzip2::Status::FinishOk) => continue,
            Ok(bzip2::Status::StreamEnd) => break,
            Ok(bzip2::Status::RunOk) => continue,
            Err(_) => {
                // CRC error from fake CRCs is expected; if we got data, accept it.
                if decompressor.total_out() > 0 {
                    break;
                }
                return Err(AlzError::Bzip2Failed("bzip2 decompression failed".into()));
            }
        }
    }

    Ok(hasher.finalize())
}

/// MSB-first bit reader.
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0-7, 0 = MSB
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn bits_remaining(&self) -> usize {
        if self.byte_pos >= self.data.len() {
            return 0;
        }
        (self.data.len() - self.byte_pos) * 8 - self.bit_pos as usize
    }

    fn read_bits(&mut self, n: usize) -> AlzResult<u32> {
        if n > 32 || self.bits_remaining() < n {
            return Err(AlzError::Bzip2Failed("unexpected end of bzip2 data".into()));
        }
        let mut val: u32 = 0;
        for _ in 0..n {
            val = (val << 1) | self.read_bit() as u32;
        }
        Ok(val)
    }

    fn read_bit(&mut self) -> u8 {
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        bit
    }

    fn peek_bits(&self, n: usize) -> AlzResult<u32> {
        if n > 32 || self.bits_remaining() < n {
            return Err(AlzError::Bzip2Failed("unexpected end of bzip2 data".into()));
        }
        let mut byte_pos = self.byte_pos;
        let mut bit_pos = self.bit_pos;
        let mut val: u32 = 0;
        for _ in 0..n {
            val = (val << 1) | ((self.data[byte_pos] >> (7 - bit_pos)) & 1) as u32;
            bit_pos += 1;
            if bit_pos == 8 {
                bit_pos = 0;
                byte_pos += 1;
            }
        }
        Ok(val)
    }
}

/// MSB-first bit writer.
struct BitWriter {
    data: Vec<u8>,
    current: u8,
    bit_pos: u8, // 0-7, 0 = MSB (next bit to write)
}

impl BitWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            current: 0,
            bit_pos: 0,
        }
    }

    fn write_bits(&mut self, val: u32, n: usize) {
        for i in (0..n).rev() {
            let bit = (val >> i) & 1;
            self.current |= (bit as u8) << (7 - self.bit_pos);
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.data.push(self.current);
                self.current = 0;
                self.bit_pos = 0;
            }
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_bits(b as u32, 8);
        }
    }

    fn flush(&mut self) {
        if self.bit_pos > 0 {
            self.data.push(self.current);
            self.current = 0;
            self.bit_pos = 0;
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}
