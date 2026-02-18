//! Tests using local testdata/ files. Skipped if testdata is absent.

use std::path::{Path, PathBuf};

use unalz_rs::archive::{AlzArchive, CompressionMethod};

fn alz(name: &str) -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/alz")
        .join(name);
    path.exists().then(|| path.to_str().unwrap().to_string())
}

fn source(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/source")
        .join(name);
    std::fs::read(path).unwrap()
}

macro_rules! skip {
    ($name:expr) => {
        match alz($name) {
            Some(p) => p,
            None => {
                eprintln!("SKIP: testdata/alz/{} not found", $name);
                return;
            }
        }
    };
}

fn extract_to(path: &str, password: Option<&str>, tag: &str) -> PathBuf {
    let mut archive = AlzArchive::open(path).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "unalz-rs-{}-{}",
        Path::new(path).file_stem().unwrap().to_str().unwrap(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    unalz_rs::extract::extract_all(&mut archive, &dir, password, false, true).unwrap();
    dir
}

macro_rules! extract {
    ($path:expr, $pwd:expr) => {
        extract_to($path, $pwd, concat!(module_path!(), "::", line!()))
    };
}

// --- Store ---

#[test]
fn store_list() {
    let path = skip!("store.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 10);
    for entry in &archive.entries {
        assert_eq!(entry.compression_method, CompressionMethod::Store);
    }
}

#[test]
fn store_extract() {
    let path = skip!("store.alz");
    let dir = extract!(&path, None);
    assert_eq!(
        std::fs::read(dir.join("hello.txt")).unwrap(),
        source("hello.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("binary.bin")).unwrap(),
        source("binary.bin")
    );
    assert_eq!(
        std::fs::read(dir.join("empty.txt")).unwrap(),
        source("empty.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("repeated.txt")).unwrap(),
        source("repeated.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("euckr_content.txt")).unwrap(),
        source("euckr_content.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("한글파일.txt")).unwrap(),
        source("한글파일.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("뷁테스트.txt")).unwrap(),
        source("뷁테스트.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("subdir/inner.txt")).unwrap(),
        source("subdir/inner.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("subdir/nested/deep.txt")).unwrap(),
        source("subdir/nested/deep.txt")
    );
}

// --- Deflate (normal) ---

#[test]
fn deflate_normal_list() {
    let path = skip!("normal.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 10);
    // empty.txt is Store, rest are Deflate
    let deflate_count = archive
        .entries
        .iter()
        .filter(|e| e.compression_method == CompressionMethod::Deflate)
        .count();
    assert!(deflate_count >= 9);
}

#[test]
fn deflate_normal_extract() {
    let path = skip!("normal.alz");
    let dir = extract!(&path, None);
    assert_eq!(
        std::fs::read(dir.join("hello.txt")).unwrap(),
        source("hello.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("binary.bin")).unwrap(),
        source("binary.bin")
    );
    assert_eq!(
        std::fs::read(dir.join("empty.txt")).unwrap(),
        source("empty.txt")
    );
}

// --- Deflate (low) ---

#[test]
fn deflate_low_extract() {
    let path = skip!("low.alz");
    let dir = extract!(&path, None);
    assert_eq!(
        std::fs::read(dir.join("hello.txt")).unwrap(),
        source("hello.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("binary.bin")).unwrap(),
        source("binary.bin")
    );
}

// --- Encrypted (zip2.0) ---

#[test]
fn encrypted_list() {
    let path = skip!("zip20.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert!(archive.is_encrypted);
    let encrypted_count = archive.entries.iter().filter(|e| e.is_encrypted()).count();
    // empty.txt is not encrypted (0 bytes), rest are
    assert!(encrypted_count >= 9);
}

#[test]
fn encrypted_extract() {
    let path = skip!("zip20.alz");
    let dir = extract!(&path, Some("test1234"));
    assert_eq!(
        std::fs::read(dir.join("hello.txt")).unwrap(),
        source("hello.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("binary.bin")).unwrap(),
        source("binary.bin")
    );
    assert_eq!(
        std::fs::read(dir.join("empty.txt")).unwrap(),
        source("empty.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("한글파일.txt")).unwrap(),
        source("한글파일.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("subdir/nested/deep.txt")).unwrap(),
        source("subdir/nested/deep.txt")
    );
}

#[test]
fn encrypted_wrong_password() {
    let path = skip!("zip20.alz");
    let mut archive = AlzArchive::open(&path).unwrap();
    let dir = std::env::temp_dir().join("unalz-rs-wrongpwd");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let result = unalz_rs::extract::extract_all(&mut archive, &dir, Some("wrong"), false, true);
    assert!(result.is_err());
}

// --- Split (multi-volume) ---

#[test]
fn split_list() {
    let path = skip!("split.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 10);
    // large.txt should be 10MB in split archive
    let large = archive
        .entries
        .iter()
        .find(|e| e.file_name == "large.txt")
        .unwrap();
    assert_eq!(large.uncompressed_size, 10485774);
}

#[test]
fn split_extract() {
    let path = skip!("split.alz");
    let dir = extract!(&path, None);
    // split archive has the full 10MB large.txt matching source
    assert_eq!(
        std::fs::read(dir.join("large.txt")).unwrap(),
        source("large.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("hello.txt")).unwrap(),
        source("hello.txt")
    );
    assert_eq!(
        std::fs::read(dir.join("binary.bin")).unwrap(),
        source("binary.bin")
    );
}

// --- Edge cases ---

#[test]
fn empty_file() {
    let path = skip!("store.alz");
    let dir = extract!(&path, None);
    let empty = std::fs::read(dir.join("empty.txt")).unwrap();
    assert!(empty.is_empty());
}

#[test]
fn cp949_extended_filename() {
    let path = skip!("store.alz");
    let archive = AlzArchive::open(&path).unwrap();
    // 뷁 is a CP949-only character not in EUC-KR
    assert!(archive.entries.iter().any(|e| e.file_name.contains("뷁")));
}

#[test]
fn nested_directories() {
    let path = skip!("store.alz");
    let dir = extract!(&path, None);
    assert!(dir.join("subdir/nested/deep.txt").exists());
}
