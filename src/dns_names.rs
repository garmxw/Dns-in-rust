// encode_name: dotted name -> wire bytes.
pub fn encode_name(domain: &str) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();

    if domain.is_empty() || domain == "." {
        out.push(0); // the root name is a lone 00
        return Ok(out);
    }

    for label in domain.trim_end_matches('.').split('.') {
        // Check label length doesn't exceed 63 bytes (DNS spec)
        if label.is_empty() || label.len() > 63 {
            return Err(format!("Invalid label length: {}", label.len()));
        }

        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }

    out.push(0); // 00 terminates every encoded name
    Ok(out)
}

// decode_name: wire bytes -> dotted name.
pub fn decode_name(buf: &[u8]) -> Result<String, String> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos: usize = 0;

    while pos < buf.len() {
        let n = buf[pos] as usize; // length byte for the next label
        pos += 1; // consumed it

        if n == 0 {
            break; // 00 ends the name
        }

        // Check we have enough bytes
        if pos + n > buf.len() {
            return Err("Truncated DNS name: not enough bytes".to_string());
        }

        let label = std::str::from_utf8(&buf[pos..pos + n])
            .map_err(|_| "Invalid UTF-8 in DNS label".to_string())?;

        labels.push(label.to_string());
        pos += n;
    }

    Ok(labels.join("."))
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }

    let cs: Vec<char> = hex.chars().collect();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;

    while i + 1 < cs.len() {
        let hi = cs[i]
            .to_digit(16)
            .ok_or_else(|| format!("Invalid hex character: '{}'", cs[i]))?;
        let lo = cs[i + 1]
            .to_digit(16)
            .ok_or_else(|| format!("Invalid hex character: '{}'", cs[i + 1]))?;

        out.push((hi * 16 + lo) as u8);
        i += 2;
    }

    Ok(out)
}
