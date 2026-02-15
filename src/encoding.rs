/// Convert CP949/EUC-KR encoded bytes to a UTF-8 string.
/// ALZ archives store filenames in CP949 (a superset of EUC-KR).
/// We use encoding_rs::EUC_KR which handles CP949 (MS949) as well.
pub fn cp949_to_utf8(bytes: &[u8]) -> String {
    // If it's already valid UTF-8, use it directly.
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }

    let (cow, _encoding_used, _had_errors) = encoding_rs::EUC_KR.decode(bytes);
    cow.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_passthrough() {
        assert_eq!(cp949_to_utf8(b"hello.txt"), "hello.txt");
        assert_eq!(cp949_to_utf8("테스트.txt".as_bytes()), "테스트.txt");
    }

    #[test]
    fn test_cp949_decode() {
        // "운영" in CP949: 0xBF, 0xEE, 0xBF, 0xB5
        let cp949 = b"\xbf\xee\xbf\xb5";
        assert_eq!(cp949_to_utf8(cp949), "운영");
    }

    #[test]
    fn test_empty() {
        assert_eq!(cp949_to_utf8(b""), "");
    }
}
