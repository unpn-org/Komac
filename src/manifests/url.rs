use std::{
    fmt,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, de};
use url::ParseError;
use winget_types::{installer::Architecture, url::DecodedUrl};

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Url {
    inner: DecodedUrl,
    override_architecture: Option<Architecture>,
}

impl Url {
    #[inline]
    pub const fn override_architecture(&self) -> Option<Architecture> {
        self.override_architecture
    }

    #[inline]
    pub const fn inner(&self) -> &DecodedUrl {
        &self.inner
    }

    #[inline]
    pub const fn inner_mut(&mut self) -> &mut DecodedUrl {
        &mut self.inner
    }

    #[inline]
    pub fn into_inner(self) -> DecodedUrl {
        self.inner
    }
}

impl Deref for Url {
    type Target = DecodedUrl;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Url {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl fmt::Display for Url {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner().fmt(f)
    }
}

impl FromStr for Url {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (url, architecture) = s.rsplit_once('|').unwrap_or((s, ""));

        Ok(Self {
            inner: url.parse()?,
            override_architecture: architecture.parse().ok(),
        })
    }
}

impl<'de> Deserialize<'de> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl From<DecodedUrl> for Url {
    fn from(url: DecodedUrl) -> Self {
        Self {
            inner: url,
            override_architecture: None,
        }
    }
}

impl From<url::Url> for Url {
    fn from(url: url::Url) -> Self {
        Self {
            inner: DecodedUrl::from_str(url.as_str()).unwrap(),
            override_architecture: None,
        }
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_original_url_as_fallback() {
        const ENCODED: &str = "https://example.com/OpenSans%5Bwdth%2Cwght%5D.ttf";
        const DECODED: &str = "https://example.com/OpenSans[wdth,wght].ttf";

        let mut url = ENCODED.parse::<Url>().unwrap();

        assert_eq!(url.original_url().as_str(), ENCODED);
        assert_eq!(url.inner().as_str(), DECODED);

        url.use_original_url();

        assert_eq!(url.inner().as_str(), ENCODED);
    }

    #[test]
    fn deserializes_from_string() {
        const URL: &str = "https://example.com/installer.exe|x64";

        let url = serde_json::from_str::<Url>(&format!("\"{URL}\"")).unwrap();

        assert_eq!(
            url.original_url().as_str(),
            "https://example.com/installer.exe"
        );
        assert_eq!(url.override_architecture(), Some(Architecture::X64));
    }
}
