use std::{
    fmt,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use url::ParseError;
use winget_types::{installer::Architecture, url::DecodedUrl};

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Url {
    inner: DecodedUrl,
    original_url: url::Url,
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

    #[inline]
    pub const fn original_url(&self) -> &url::Url {
        &self.original_url
    }

    #[inline]
    pub const fn original_url_mut(&mut self) -> &mut url::Url {
        &mut self.original_url
    }

    pub fn use_original_url(&mut self) {
        *self.inner = self.original_url.clone();
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
            original_url: url.parse()?,
            override_architecture: architecture.parse().ok(),
        })
    }
}

impl From<DecodedUrl> for Url {
    fn from(url: DecodedUrl) -> Self {
        let original_url = (*url).clone();
        Self {
            inner: url,
            original_url,
            override_architecture: None,
        }
    }
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
}
