use std::io::{Read, Write};
use std::path::Path;
use std::process;

use clap::Parser;

use unalz_rs::archive::{ATTR_ARCHIVE, ATTR_DIRECTORY, ATTR_HIDDEN, ATTR_READONLY, AlzArchive};
use unalz_rs::dostime::dos_datetime_to_string;
use unalz_rs::extract;

#[derive(Parser)]
#[command(name = "unalz", about = "ALZ archive extractor", version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// List contents of archive
    #[arg(short = 'l', long = "list")]
    list: bool,

    /// Extract files to pipe (stdout), suppress messages
    #[arg(short = 'p')]
    pipe: bool,

    /// Suppress progress messages
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Set output directory
    #[arg(short = 'd', value_name = "DIR")]
    dest_dir: Option<String>,

    /// Set password
    #[arg(long = "pwd", value_name = "PASSWORD")]
    password: Option<String>,

    /// Archive file (.alz), or "-" for stdin
    archive: String,

    /// Files to extract (if empty, extract all)
    files: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    let quiet = cli.quiet || cli.pipe;

    if !quiet {
        eprintln!("unalz-rs v{}", env!("CARGO_PKG_VERSION"));
    }

    let mut archive = if cli.archive == "-" {
        let mut data = Vec::new();
        if let Err(e) = std::io::stdin().read_to_end(&mut data) {
            eprintln!("err: {e}");
            process::exit(1);
        }
        match AlzArchive::from_bytes(data) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("file open error : stdin");
                eprintln!("err: {e}");
                process::exit(1);
            }
        }
    } else {
        match AlzArchive::open(&cli.archive) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("file open error : {}", cli.archive);
                eprintln!("err: {e}");
                process::exit(1);
            }
        }
    };

    if cli.list {
        list_archive(&archive, &cli.archive);
        return;
    }

    // Handle password.
    let password = if archive.is_encrypted {
        if let Some(ref pwd) = cli.password {
            Some(pwd.clone())
        } else {
            eprint!("Enter Password : ");
            std::io::stderr().flush().ok();
            let mut pwd = String::new();
            std::io::stdin().read_line(&mut pwd).ok();
            let pwd = pwd.trim().to_string();
            Some(pwd)
        }
    } else {
        cli.password.clone()
    };

    let dest_dir = cli.dest_dir.as_deref().unwrap_or(".");
    let dest_path = Path::new(dest_dir);

    if !quiet {
        eprintln!("\nExtract {} to {}", cli.archive, dest_dir);
    }

    let result = if cli.files.is_empty() {
        extract::extract_all(
            &mut archive,
            dest_path,
            password.as_deref(),
            cli.pipe,
            quiet,
        )
    } else {
        extract::extract_files(
            &mut archive,
            dest_path,
            &cli.files,
            password.as_deref(),
            cli.pipe,
            quiet,
        )
    };

    match result {
        Ok(()) => {
            if !quiet {
                eprintln!("\ndone.");
            }
        }
        Err(e) => {
            eprintln!("\nextract failed: {e}");
            process::exit(1);
        }
    }
}

fn list_archive(archive: &AlzArchive, source: &str) {
    println!("\nListing archive: {source}");
    println!();
    println!("Attr  Uncomp Size    Comp Size Method  Date & Time & File Name");
    println!(
        "---- ------------ ------------ ------- ------------------------------------------------"
    );

    let mut total_uncompressed: u64 = 0;
    let mut total_compressed: u64 = 0;
    let mut file_count: u32 = 0;

    for entry in &archive.entries {
        let a = entry.file_attribute;
        let attr = format!(
            "{}{}{}{}",
            if a & ATTR_ARCHIVE != 0 { "A" } else { "_" },
            if a & ATTR_DIRECTORY != 0 { "D" } else { "_" },
            if a & ATTR_READONLY != 0 { "R" } else { "_" },
            if a & ATTR_HIDDEN != 0 { "H" } else { "_" },
        );

        let datetime = dos_datetime_to_string(entry.file_time_date);
        let encrypted = if entry.is_encrypted() { "*" } else { "" };

        println!(
            "{attr} {:>12} {:>12} {:<7} {datetime}  {}{encrypted}",
            entry.uncompressed_size,
            entry.compressed_size,
            entry.compression_method,
            entry.file_name,
        );

        file_count += 1;
        total_uncompressed += entry.uncompressed_size;
        total_compressed += entry.compressed_size;
    }

    println!(
        "---- ------------ ------------ ------- ------------------------------------------------"
    );
    let plural = if file_count <= 1 { "" } else { "s" };
    println!(
        "     {total_uncompressed:>12} {total_compressed:>12}         Total {file_count} file{plural}"
    );
}
