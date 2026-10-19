//! Known-answer test: supplied by the algorithm's author, ideally taken from
//! an official or independently generated source (RFC, NIST, upstream test
//! vectors, a script in another language).

/// One vector for a `SealMac`: the inputs of `mac` and the expected tag.
#[derive(Debug, Clone)]
pub struct Kat {
    pub name: String,
    pub key: Vec<u8>,
    pub fragment: Vec<u8>,
    pub state: [u8; 32],
    pub expected: Vec<u8>,
}

impl Kat {
    pub fn new(name: &str, key: Vec<u8>, fragment: Vec<u8>, state: [u8; 32], expected: Vec<u8>) -> Self {
        Kat { name: name.to_string(), key, fragment, state, expected }
    }

    /// Builds a vector from hex strings. `Err` on odd length, non-hex digits
    /// or a state that is not 32 bytes.
    pub fn from_hex(
        name: &str,
        key_hex: &str,
        fragment_hex: &str,
        state_hex: &str,
        expected_hex: &str,
    ) -> Result<Self, String> {
        let state_v = decode_hex(state_hex)?;
        let state: [u8; 32] =
            state_v.try_into().map_err(|_| "state must be exactly 32 bytes".to_string())?;
        Ok(Kat {
            name: name.to_string(),
            key: decode_hex(key_hex)?,
            fragment: decode_hex(fragment_hex)?,
            state,
            expected: decode_hex(expected_hex)?,
        })
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".to_string());
    }
    let digit = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("non-hex digit".to_string()),
        }
    };
    s.as_bytes().chunks(2).map(|p| Ok(digit(p[0])? << 4 | digit(p[1])?)).collect()
}
