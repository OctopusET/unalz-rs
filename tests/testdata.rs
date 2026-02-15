//! Tests using local testdata/ files. Skipped if testdata is absent.

use std::path::Path;

use unalz_rs::archive::AlzArchive;

fn testdata(name: &str) -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    path.exists().then(|| path.to_str().unwrap().to_string())
}

macro_rules! skip_if_missing {
    ($path:expr) => {
        match testdata($path) {
            Some(p) => p,
            None => {
                eprintln!("SKIP: testdata/{} not found", $path);
                return;
            }
        }
    };
}

#[test]
fn samples_alz_list() {
    let path = skip_if_missing!("Samples.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 10);
    assert_eq!(archive.entries[0].file_name, "ANSI.txt");
    assert_eq!(archive.entries[0].uncompressed_size, 19);
}

#[test]
fn samples_alz_extract() {
    let path = skip_if_missing!("Samples.alz");
    let mut archive = AlzArchive::open(&path).unwrap();
    let dir = std::env::temp_dir().join("unalz-rs-samples");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    unalz_rs::extract::extract_all(&mut archive, &dir, None, false, true).unwrap();
    assert_eq!(std::fs::read(dir.join("ANSI.txt")).unwrap().len(), 19);
    assert_eq!(std::fs::read(dir.join("EUC-KR.txt")).unwrap().len(), 55);
}

#[test]
fn korean_filenames() {
    let path = skip_if_missing!("2003운영.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 2);
    assert!(archive.entries[0].file_name.contains("운영결과"));
}

#[test]
fn korean_filenames_extract() {
    let path = skip_if_missing!("2003운영.alz");
    let mut archive = AlzArchive::open(&path).unwrap();
    let dir = std::env::temp_dir().join("unalz-rs-korean");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    unalz_rs::extract::extract_all(&mut archive, &dir, None, false, true).unwrap();
}

#[test]
fn multivolume_list() {
    let path = skip_if_missing!("저탄소 중온 .alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 1);
    assert_eq!(archive.entries[0].uncompressed_size, 10860546);
}

#[test]
fn multivolume_extract() {
    let path = skip_if_missing!("저탄소 중온 .alz");
    let mut archive = AlzArchive::open(&path).unwrap();
    let dir = std::env::temp_dir().join("unalz-rs-multivol");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    unalz_rs::extract::extract_all(&mut archive, &dir, None, false, true).unwrap();
}

#[test]
fn corrupted_files_rejected() {
    for name in [
        "1172A80C4A9A7828E6",
        "1307810C4A9A78106D",
        "17744B0C4A9A77C5C2",
    ] {
        if let Some(path) = testdata(name) {
            assert!(AlzArchive::open(&path).is_err(), "should reject {name}");
        }
    }
}
