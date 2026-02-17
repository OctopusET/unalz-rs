use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{AlzError, AlzResult};

trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

const MAX_VOLUMES: usize = 1000;
const MULTIVOL_HEAD_SIZE: u64 = 8;
const MULTIVOL_TAIL_SIZE: u64 = 16;

struct Volume {
    file: Box<dyn ReadSeek>,
    file_size: u64,
    header_size: u64,
    tail_size: u64,
}

impl Volume {
    fn data_size(&self) -> u64 {
        self.file_size - self.header_size - self.tail_size
    }
}

/// Virtual reader over multi-volume ALZ archives (.alz, .a00, .a01, ...).
/// Transparently handles seeking and reading across volume boundaries.
pub struct MultiVolumeReader {
    volumes: Vec<Volume>,
    cur_volume: usize,
    virtual_pos: u64,
    tail: [u8; 16],
}

impl MultiVolumeReader {
    /// Open a multi-volume archive starting from the given .alz path.
    /// Discovers .a00, .a01, ... .a99, .b00, ... automatically.
    pub fn open<P: AsRef<Path>>(path: P) -> AlzResult<Self> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();

        if path_str.len() < 4 {
            return Err(AlzError::CantOpenFile(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path too short",
            )));
        }

        let prefix = &path_str[..path_str.len() - 3];
        let mut volumes = Vec::new();

        for i in 0..MAX_VOLUMES {
            let vol_path = if i == 0 {
                path_str.clone()
            } else {
                let letter = (b'a' + ((i - 1) / 100) as u8) as char;
                let num = (i - 1) % 100;
                format!("{prefix}{letter}{num:02}")
            };

            let file = match File::open(&vol_path) {
                Ok(f) => f,
                Err(_) => break,
            };

            let file_size = file.metadata()?.len();
            let header_size = if i == 0 { 0 } else { MULTIVOL_HEAD_SIZE };
            let tail_size = MULTIVOL_TAIL_SIZE; // corrected for last volume below

            volumes.push(Volume {
                file: Box::new(file),
                file_size,
                header_size,
                tail_size,
            });
        }

        if volumes.is_empty() {
            return Err(AlzError::CantOpenFile(io::Error::new(
                io::ErrorKind::NotFound,
                format!("can't open: {path_str}"),
            )));
        }

        // Last volume has no tail.
        if let Some(last) = volumes.last_mut() {
            last.tail_size = 0;
        }

        // Read the 16-byte file tail from the first volume.
        let mut tail = [0u8; 16];
        let vol0 = &mut volumes[0];
        if vol0.file_size >= 16 {
            vol0.file.seek(SeekFrom::Start(vol0.file_size - 16))?;
            vol0.file.read_exact(&mut tail)?;
        }

        let mut reader = MultiVolumeReader {
            volumes,
            cur_volume: 0,
            virtual_pos: 0,
            tail,
        };
        // Position at the data start of volume 0.
        reader.seek_to_virtual(0)?;
        Ok(reader)
    }

    /// Create a single-volume reader from in-memory data (e.g. stdin).
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let len = data.len() as u64;
        let mut tail = [0u8; 16];
        if data.len() >= 16 {
            tail.copy_from_slice(&data[data.len() - 16..]);
        }
        MultiVolumeReader {
            volumes: vec![Volume {
                file: Box::new(io::Cursor::new(data)),
                file_size: len,
                header_size: 0,
                tail_size: 0,
            }],
            cur_volume: 0,
            virtual_pos: 0,
            tail,
        }
    }

    /// The 16-byte file tail (endInfos) from the first volume.
    pub fn tail(&self) -> &[u8; 16] {
        &self.tail
    }

    /// Total virtual data size across all volumes.
    pub fn total_size(&self) -> u64 {
        self.volumes.iter().map(|v| v.data_size()).sum()
    }

    fn seek_to_virtual(&mut self, offset: u64) -> AlzResult<()> {
        self.virtual_pos = offset;
        let mut remain = offset;

        for (i, vol) in self.volumes.iter_mut().enumerate() {
            let data_size = vol.data_size();
            if remain <= data_size {
                let phys_pos = remain + vol.header_size;
                vol.file.seek(SeekFrom::Start(phys_pos))?;
                self.cur_volume = i;
                return Ok(());
            }
            remain -= data_size;
        }

        Err(AlzError::CorruptedFile)
    }
}

impl Read for MultiVolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.cur_volume >= self.volumes.len() {
            return Ok(0);
        }

        let mut total_read = 0;

        while total_read < buf.len() && self.cur_volume < self.volumes.len() {
            let vol = &mut self.volumes[self.cur_volume];
            let phys_pos = vol.file.stream_position()?;
            let data_end = vol.file_size - vol.tail_size;
            let avail = data_end.saturating_sub(phys_pos) as usize;

            if avail == 0 {
                // Move to next volume.
                self.cur_volume += 1;
                if self.cur_volume >= self.volumes.len() {
                    break;
                }
                let next_vol = &mut self.volumes[self.cur_volume];
                next_vol.file.seek(SeekFrom::Start(next_vol.header_size))?;
                continue;
            }

            let to_read = avail.min(buf.len() - total_read);
            let n = vol.file.read(&mut buf[total_read..total_read + to_read])?;
            if n == 0 {
                break;
            }
            total_read += n;
            self.virtual_pos += n as u64;
        }

        Ok(total_read)
    }
}

impl Seek for MultiVolumeReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.virtual_pos + delta as u64
                } else {
                    self.virtual_pos
                        .checked_sub((-delta) as u64)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "seek before start")
                        })?
                }
            }
            SeekFrom::End(delta) => {
                let total = self.total_size() as i64;
                (total + delta) as u64
            }
        };

        self.seek_to_virtual(new_pos)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(self.virtual_pos)
    }
}
