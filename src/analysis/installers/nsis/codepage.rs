use std::{borrow::Cow, sync::OnceLock};

use encoding_rs::{Encoding, WINDOWS_1252};
use tracing::warn;

static ANSI: OnceLock<(u16, &'static Encoding)> = OnceLock::new();
static NON_ASCII: OnceLock<()> = OnceLock::new();

pub fn for_id(id: u16) -> Option<&'static Encoding> {
    if !matches!(id, 874 | 932 | 936 | 949 | 950 | 1250..=1258 | 65001) {
        return None;
    }
    codepage::to_encoding(id)
}

/// Returns the ANSI code page of the simulated Windows installation.
pub fn ansi() -> &'static Encoding {
    ANSI.get_or_init(|| {
        if let Some(value) = std::env::var_os("KOMAC_NSIS_ANSI_CODEPAGE") {
            if let Some((id, encoding)) = value
                .to_str()
                .and_then(|value| value.parse::<u16>().ok())
                .and_then(|id| for_id(id).map(|encoding| (id, encoding)))
            {
                return (id, encoding);
            }
            warn!("Invalid KOMAC_NSIS_ANSI_CODEPAGE; using Windows-1252");
        }
        (1252, WINDOWS_1252)
    })
    .1
}

pub fn decode(bytes: &[u8]) -> Cow<'_, str> {
    let encoding = ansi();
    if !bytes.is_ascii() {
        NON_ASCII.get_or_init(|| {
            warn!(encoding = encoding.name(), "ANSI strings depend on the simulated Windows codepage; locale-dependent metadata requires independent validation");
        });
    }
    encoding.decode_without_bom_handling(bytes).0
}

pub fn encode_with(value: &str, encoding: &'static Encoding) -> Vec<u8> {
    let mut bytes = Vec::new();
    for character in value.chars() {
        let text = character.to_string();
        let (encoded, _, lossy) = encoding.encode(&text);
        if lossy {
            bytes.push(b'?');
        } else {
            bytes.extend_from_slice(&encoded);
        }
    }
    bytes
}

pub fn encode(value: &str) -> Vec<u8> {
    encode_with(value, ansi())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_codepages_decode_the_same_installer_bytes_differently() {
        for (id, bytes, expected) in [
            (
                936,
                b"\xb6\xb7\xd3\xe3\xd6\xb1\xb2\xa5".as_slice(),
                "斗鱼直播",
            ),
            (
                949,
                b"\xb9\xf7\xbd\xba \xc7\xc3\xb7\xb9\xc0\xcc\xbe\xee".as_slice(),
                "벅스 플레이어",
            ),
            (1252, b"Link\xf6ping".as_slice(), "Linköping"),
            (65001, b"Link\xc3\xb6ping".as_slice(), "Linköping"),
        ] {
            let encoding = for_id(id).unwrap();
            assert_eq!(encoding.decode_without_bom_handling(bytes).0, expected);
            assert_eq!(encode_with(expected, encoding), bytes);
        }
        assert!(for_id(1200).is_none());
        assert!(for_id(65535).is_none());
    }
}
