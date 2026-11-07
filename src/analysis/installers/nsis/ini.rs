use std::collections::BTreeMap;

use encoding_rs::{UTF_16BE, UTF_16LE};

/// A Windows profile file used by `ReadINIStr` and `WriteINIStr`.
///
/// Section and key names are case insensitive. Surrounding quotes are removed from values.
#[derive(Default)]
pub struct IniFile(BTreeMap<String, BTreeMap<String, String>>);

impl IniFile {
    pub fn parse(bytes: &[u8]) -> Self {
        let text = if let Some(bytes) = bytes.strip_prefix(b"\xff\xfe") {
            UTF_16LE.decode_without_bom_handling(bytes).0
        } else if let Some(bytes) = bytes.strip_prefix(b"\xfe\xff") {
            UTF_16BE.decode_without_bom_handling(bytes).0
        } else {
            super::codepage::decode(bytes)
        };
        let mut result = Self::default();
        let mut section = None;
        for line in text.lines().map(str::trim) {
            if line.starts_with(';') || line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|s| s.split_once(']')) {
                section = Some(name.0.trim().to_lowercase());
            } else if let (Some(section), Some((key, value))) = (&section, line.split_once('=')) {
                result
                    .0
                    .entry(section.clone())
                    .or_default()
                    .entry(key.trim().to_lowercase())
                    .or_insert_with(|| Self::unquote(value.trim()).to_owned());
            }
        }
        result
    }

    fn unquote(value: &str) -> &str {
        value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(value)
    }

    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.0
            .get(&section.to_lowercase())?
            .get(&key.to_lowercase())
            .map(String::as_str)
    }

    pub fn write(&mut self, section: Option<&str>, key: Option<&str>, value: Option<&str>) {
        let Some(section) = section.map(str::to_lowercase) else {
            return;
        };
        let Some(key) = key.map(str::to_lowercase) else {
            self.0.remove(&section);
            return;
        };
        if let Some(value) = value {
            self.0
                .entry(section)
                .or_default()
                .insert(key, Self::unquote(value).to_owned());
        } else if let Some(section) = self.0.get_mut(&section) {
            section.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IniFile;

    #[test]
    fn profile_names_quotes_and_deletions() {
        let mut ini = IniFile::parse(b";comment\r\n[App]\r\nVersion = \"1.2.3\"\r\nempty=\r\n");
        assert_eq!(ini.get("APP", "VERSION"), Some("1.2.3"));
        assert_eq!(ini.get("App", "empty"), Some(""));
        ini.write(Some("app"), Some("Version"), Some("2.0"));
        assert_eq!(ini.get("App", "version"), Some("2.0"));
        ini.write(Some("APP"), Some("VERSION"), None);
        assert_eq!(ini.get("app", "version"), None);
        ini.write(Some("app"), None, None);
        assert_eq!(ini.get("app", "empty"), None);
    }

    #[test]
    fn unicode_profile() {
        let bytes: Vec<_> = "\u{feff}[App]\nPublisher=🚀\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(IniFile::parse(&bytes).get("App", "Publisher"), Some("🚀"));
    }
}
