use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use filetime::FileTime;

use crate::archive::{AlzArchive, AlzFileEntry, CompressionMethod};
use crate::crypto::ZipCrypto;
use crate::decompress::{bzip2, deflate, raw};
use crate::dostime::dos_datetime_to_systime;
use crate::error::{AlzError, AlzResult};

/// Extract a single file entry from the archive.
pub fn extract_entry(
    archive: &mut AlzArchive,
    entry: &AlzFileEntry,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
) -> AlzResult<()> {
    // Validate password for encrypted files.
    let mut crypto = if entry.is_encrypted() {
        let pwd = password.ok_or(AlzError::PasswordNotSet)?;
        let enc_chk = entry.enc_check.as_ref().ok_or(AlzError::PasswordNotSet)?;
        let mut c = ZipCrypto::new(pwd.as_bytes());
        if !c.check_header(
            enc_chk,
            entry.file_crc,
            entry.file_time_date,
            entry.has_data_descriptor(),
        ) {
            return Err(AlzError::InvalidPassword);
        }
        // Re-initialize for actual decryption.
        let mut c = ZipCrypto::new(pwd.as_bytes());
        // Re-process the encryption header to advance key state.
        let mut hdr_copy = *enc_chk;
        c.decrypt(&mut hdr_copy);
        Some(c)
    } else {
        None
    };

    // Build destination path.
    let file_name = entry.file_name.replace('\\', "/");

    // Security: reject path traversal.
    if file_name.contains("../") || file_name.contains("..\\") {
        return Err(AlzError::PathTraversal(file_name));
    }

    let dest_path = dest_dir.join(&file_name);

    // Security: reject absolute paths and any remaining traversal.
    if !pipe_mode {
        let canonical_dest = fs::canonicalize(dest_dir)?;
        // dest_path may not exist yet; resolve via its parent directory.
        let resolved = if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
            fs::canonicalize(parent)?.join(dest_path.file_name().unwrap_or_default())
        } else {
            dest_path.clone()
        };
        if !resolved.starts_with(&canonical_dest) {
            return Err(AlzError::PathTraversal(file_name));
        }
    }

    // Handle directories.
    if entry.is_directory() {
        if !pipe_mode {
            fs::create_dir_all(&dest_path)?;
        }
        return Ok(());
    }

    // Handle symlinks.
    if entry.is_symlink() {
        archive.reader.seek(SeekFrom::Start(entry.data_pos))?;
        let mut limited = (&mut archive.reader).take(entry.compressed_size);
        let mut buf = Vec::new();
        let crc = decompress_to(&mut limited, &mut buf, entry, crypto.as_mut())?;
        if crc != entry.file_crc {
            return Err(AlzError::InvalidFileCrc {
                expected: entry.file_crc,
                got: crc,
            });
        }
        let target = String::from_utf8_lossy(&buf);
        if pipe_mode {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            out.write_all(target.as_bytes())
                .map_err(AlzError::CantOpenDestFile)?;
        } else {
            let target_path = Path::new(target.as_ref());
            if target.contains("../") || target.contains("..\\") || target_path.has_root() {
                return Err(AlzError::PathTraversal(target.into_owned()));
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(target.as_ref(), &dest_path)?;
            #[cfg(not(unix))]
            fs::write(&dest_path, target.as_bytes())?;
        }
        return Ok(());
    }

    // Seek to data position.
    archive.reader.seek(SeekFrom::Start(entry.data_pos))?;

    // Create a limited reader for exactly compressed_size bytes.
    let mut limited = (&mut archive.reader).take(entry.compressed_size);

    // Decompress and write.
    let crc = if pipe_mode {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        decompress_to(&mut limited, &mut out, entry, crypto.as_mut())?
    } else {
        let mut file = fs::File::create(&dest_path).map_err(AlzError::CantOpenDestFile)?;
        let crc = decompress_to(&mut limited, &mut file, entry, crypto.as_mut())?;
        file.flush().map_err(AlzError::CantOpenDestFile)?;
        drop(file);

        // Set file modification time.
        if let Some(systime) = dos_datetime_to_systime(entry.file_time_date) {
            let ft = FileTime::from_system_time(systime);
            let _ = filetime::set_file_mtime(&dest_path, ft);
        }

        crc
    };

    // Verify CRC.
    if crc != entry.file_crc {
        if !pipe_mode {
            let _ = fs::remove_file(&dest_path);
        }
        return Err(AlzError::InvalidFileCrc {
            expected: entry.file_crc,
            got: crc,
        });
    }

    Ok(())
}

fn decompress_to<R: io::Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    entry: &AlzFileEntry,
    crypto: Option<&mut ZipCrypto>,
) -> AlzResult<u32> {
    match entry.compression_method {
        CompressionMethod::Store => raw::extract_raw(reader, writer, entry.compressed_size, crypto),
        CompressionMethod::Deflate => {
            deflate::extract_deflate(reader, writer, entry.compressed_size, crypto)
        }
        CompressionMethod::Bzip2 => {
            bzip2::extract_bzip2(reader, writer, entry.compressed_size, crypto)
        }
        CompressionMethod::Unknown(n) => Err(AlzError::UnknownCompressionMethod(n)),
    }
}

/// Extract all entries from the archive.
pub fn extract_all(
    archive: &mut AlzArchive,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
    quiet: bool,
) -> AlzResult<()> {
    let entries: Vec<AlzFileEntry> = archive.entries.clone();
    for entry in &entries {
        if !quiet && !pipe_mode {
            eprint!(
                "\nunalziiiing : {} ({}bytes) ",
                entry.file_name, entry.uncompressed_size
            );
        }
        extract_entry(archive, entry, dest_dir, password, pipe_mode)?;
        if !quiet && !pipe_mode {
            eprint!(".. ok");
        }
    }
    Ok(())
}

/// Extract specific files by name.
pub fn extract_files(
    archive: &mut AlzArchive,
    dest_dir: &Path,
    file_names: &[String],
    password: Option<&str>,
    pipe_mode: bool,
    quiet: bool,
) -> AlzResult<()> {
    let entries: Vec<AlzFileEntry> = archive.entries.clone();
    for name in file_names {
        if let Some(entry) = entries.iter().find(|e| e.file_name == *name) {
            if !quiet && !pipe_mode {
                eprint!(
                    "\nunalziiiing : {} ({}bytes) ",
                    entry.file_name, entry.uncompressed_size
                );
            }
            extract_entry(archive, entry, dest_dir, password, pipe_mode)?;
            if !quiet && !pipe_mode {
                eprint!(".. ok");
            }
        } else if !quiet && !pipe_mode {
            eprintln!("\nfilename not matched : {name}");
        }
    }
    Ok(())
}
