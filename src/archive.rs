use std::io::{Read, Seek, SeekFrom};

use crate::crypto::ENCR_HEADER_LEN;
use crate::encoding::cp949_to_utf8;
use crate::error::{AlzError, AlzResult};
use crate::multivolume::MultiVolumeReader;

// ALZ signatures (little-endian u32)
const SIG_ALZ_FILE_HEADER: u32 = 0x015a4c41; // "ALZ\x01"
const SIG_LOCAL_FILE_HEADER: u32 = 0x015a4c42; // "BLZ\x01"
const SIG_CENTRAL_DIRECTORY: u32 = 0x015a4c43; // "CLZ\x01"
const SIG_END_OF_CENTRAL_DIR: u32 = 0x025a4c43; // "CLZ\x02"
const SIG_COMMENT: u32 = 0x015a4c45; // "ELZ\x01"
const SIG_SPLIT_MARKER: u32 = 0x035a4c43; // "CLZ\x03"

// File descriptor flags
const DESC_ENCRYPTED: u8 = 0x01;
const DESC_DATA_DESCR: u8 = 0x08;

// File attributes
pub const ATTR_READONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_SYMLINK: u8 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Store,   // 0
    Bzip2,   // 1
    Deflate, // 2
    Unknown(u8),
}

impl CompressionMethod {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Store,
            1 => Self::Bzip2,
            2 => Self::Deflate,
            n => Self::Unknown(n),
        }
    }
}

impl std::fmt::Display for CompressionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store => write!(f, "Store"),
            Self::Bzip2 => write!(f, "BZip2"),
            Self::Deflate => write!(f, "Deflate"),
            Self::Unknown(n) => write!(f, "Unknown({n})"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AlzFileEntry {
    pub file_name: String,
    pub file_attribute: u8,
    pub file_time_date: u32,
    pub file_descriptor: u8,
    pub compression_method: CompressionMethod,
    pub file_crc: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub data_pos: u64,
    pub enc_check: Option<[u8; ENCR_HEADER_LEN]>,
}

impl AlzFileEntry {
    pub fn is_encrypted(&self) -> bool {
        self.file_descriptor & DESC_ENCRYPTED != 0
    }

    pub fn is_directory(&self) -> bool {
        self.file_attribute & ATTR_DIRECTORY != 0
    }

    pub fn is_symlink(&self) -> bool {
        self.file_attribute & ATTR_SYMLINK != 0
    }

    pub fn has_data_descriptor(&self) -> bool {
        self.file_descriptor & DESC_DATA_DESCR != 0
    }
}

pub struct AlzArchive {
    pub reader: MultiVolumeReader,
    pub entries: Vec<AlzFileEntry>,
    pub is_encrypted: bool,
    pub is_data_descr: bool,
}

impl AlzArchive {
    pub fn open(path: &str) -> AlzResult<Self> {
        let reader = MultiVolumeReader::open(path)?;
        let mut archive = AlzArchive {
            reader,
            entries: Vec::new(),
            is_encrypted: false,
            is_data_descr: false,
        };
        archive.parse()?;
        Ok(archive)
    }

    pub fn from_bytes(data: Vec<u8>) -> AlzResult<Self> {
        let reader = MultiVolumeReader::from_bytes(data);
        let mut archive = AlzArchive {
            reader,
            entries: Vec::new(),
            is_encrypted: false,
            is_data_descr: false,
        };
        archive.parse()?;
        Ok(archive)
    }

    fn parse(&mut self) -> AlzResult<()> {
        let mut seen_alz_header = false;

        // Parse endInfos from the 16-byte file tail.
        let tail = *self.reader.tail();
        let comment_section_size = u32::from_le_bytes([tail[4], tail[5], tail[6], tail[7]]) as u64;

        while let Ok(sig) = self.read_u32_le() {
            match sig {
                SIG_ALZ_FILE_HEADER => {
                    self.read_alz_header()?;
                    seen_alz_header = true;
                }
                SIG_LOCAL_FILE_HEADER => {
                    self.read_local_file_header()?;
                }
                SIG_CENTRAL_DIRECTORY => {
                    self.read_central_directory()?;
                }
                SIG_END_OF_CENTRAL_DIR => {
                    break;
                }
                SIG_COMMENT => {
                    self.skip_comment_section(comment_section_size)?;
                }
                SIG_SPLIT_MARKER => {}
                _ => {
                    if seen_alz_header {
                        return Err(AlzError::CorruptedFile);
                    } else {
                        return Err(AlzError::NotAlzFile);
                    }
                }
            }
        }

        Ok(())
    }

    fn read_alz_header(&mut self) -> AlzResult<()> {
        // 2 bytes version + 2 bytes ID
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(())
    }

    fn read_local_file_header(&mut self) -> AlzResult<()> {
        // Fixed header: 9 bytes
        let mut head = [0u8; 9];
        self.reader.read_exact(&mut head)?;

        let file_name_length = u16::from_le_bytes([head[0], head[1]]) as usize;
        let file_attribute = head[2];
        let file_time_date = u32::from_le_bytes([head[3], head[4], head[5], head[6]]);
        let file_descriptor = head[7];
        let _unknown2 = head[8];

        // Check encryption
        if file_descriptor & DESC_ENCRYPTED != 0 {
            self.is_encrypted = true;
        }
        if file_descriptor & DESC_DATA_DESCR != 0 {
            self.is_data_descr = true;
        }

        // Size field width from descriptor bits 4-7
        let byte_len = match file_descriptor & 0xF0 {
            0x00 => 0,
            0x10 => 1,
            0x20 => 2,
            0x40 => 4,
            0x80 => 8,
            _ => return Err(AlzError::InvalidSizeFieldWidth(file_descriptor & 0xF0)),
        };

        let mut compression_method = CompressionMethod::Store;
        let mut file_crc: u32 = 0;
        let mut compressed_size: u64 = 0;
        let mut uncompressed_size: u64 = 0;

        if byte_len > 0 {
            // compression method (1 byte)
            let mut cm = [0u8; 1];
            self.reader.read_exact(&mut cm)?;
            compression_method = CompressionMethod::from_byte(cm[0]);

            // unknown (1 byte)
            let mut unk = [0u8; 1];
            self.reader.read_exact(&mut unk)?;

            // file CRC (4 bytes)
            let mut crc_buf = [0u8; 4];
            self.reader.read_exact(&mut crc_buf)?;
            file_crc = u32::from_le_bytes(crc_buf);

            // compressed size (byte_len bytes)
            compressed_size = self.read_var_int(byte_len)?;

            // uncompressed size (byte_len bytes)
            uncompressed_size = self.read_var_int(byte_len)?;
        }

        // File name
        if file_name_length == 0 || file_name_length > 4096 {
            return Err(AlzError::InvalidFilenameLength);
        }
        let mut name_buf = vec![0u8; file_name_length];
        self.reader.read_exact(&mut name_buf)?;
        let file_name = cp949_to_utf8(&name_buf);

        // Encryption header
        let enc_check = if file_descriptor & DESC_ENCRYPTED != 0 {
            let mut buf = [0u8; ENCR_HEADER_LEN];
            self.reader.read_exact(&mut buf)?;
            Some(buf)
        } else {
            None
        };

        // Record data position and skip file data
        let data_pos = self.reader.stream_position()?;
        let skip: i64 = compressed_size
            .try_into()
            .map_err(|_| AlzError::CorruptedFile)?;
        self.reader.seek(SeekFrom::Current(skip))?;

        self.entries.push(AlzFileEntry {
            file_name,
            file_attribute,
            file_time_date,
            file_descriptor,
            compression_method,
            file_crc,
            compressed_size,
            uncompressed_size,
            data_pos,
            enc_check,
        });

        Ok(())
    }

    fn read_central_directory(&mut self) -> AlzResult<()> {
        // Central directory structure head: 12 bytes (3 x u32)
        let mut buf = [0u8; 12];
        self.reader.read_exact(&mut buf)?;
        Ok(())
    }

    fn skip_comment_section(&mut self, total_size: u64) -> AlzResult<()> {
        // total_size includes the 4-byte signature we already read.
        if total_size > 4 {
            let skip: i64 = (total_size - 4)
                .try_into()
                .map_err(|_| AlzError::CorruptedFile)?;
            self.reader.seek(SeekFrom::Current(skip))?;
        }
        Ok(())
    }

    fn read_u32_le(&mut self) -> AlzResult<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a variable-width little-endian integer (1, 2, 4, or 8 bytes).
    fn read_var_int(&mut self, byte_len: usize) -> AlzResult<u64> {
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf[..byte_len])?;
        Ok(u64::from_le_bytes(buf))
    }
}
