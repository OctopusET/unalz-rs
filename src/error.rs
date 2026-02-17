use std::fmt;

#[derive(Debug)]
pub enum AlzError {
    NotAlzFile,
    CorruptedFile,
    CantOpenFile(std::io::Error),
    CantOpenDestFile(std::io::Error),
    InvalidFilenameLength,
    InflateFailed(String),
    Bzip2Failed(String),
    InvalidFileCrc { expected: u32, got: u32 },
    InvalidSizeFieldWidth(u8),
    UnknownCompressionMethod(u8),
    PasswordNotSet,
    InvalidPassword,
    PathTraversal(String),
    Io(std::io::Error),
}

impl fmt::Display for AlzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAlzFile => write!(f, "not an ALZ file"),
            Self::CorruptedFile => write!(f, "corrupted file"),
            Self::CantOpenFile(e) => write!(f, "can't open archive file: {e}"),
            Self::CantOpenDestFile(e) => write!(f, "can't open dest file: {e}"),
            Self::InvalidFilenameLength => write!(f, "invalid filename length"),
            Self::InflateFailed(s) => write!(f, "inflate failed: {s}"),
            Self::Bzip2Failed(s) => write!(f, "bzip2 decompress failed: {s}"),
            Self::InvalidFileCrc { expected, got } => {
                write!(
                    f,
                    "invalid file CRC: expected {expected:08x}, got {got:08x}"
                )
            }
            Self::InvalidSizeFieldWidth(v) => {
                write!(f, "invalid size field width: 0x{v:02x}")
            }
            Self::UnknownCompressionMethod(m) => write!(f, "unknown compression method: {m}"),
            Self::PasswordNotSet => write!(f, "password was not set"),
            Self::InvalidPassword => write!(f, "invalid password"),
            Self::PathTraversal(p) => write!(f, "path traversal blocked: {p}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AlzError {}

impl From<std::io::Error> for AlzError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type AlzResult<T> = Result<T, AlzError>;
