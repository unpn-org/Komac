pub mod client;
mod error;
pub mod graphql;
#[cfg(feature = "cli")]
mod package;
mod rest;
pub mod utils;

use std::{
    env,
    fmt::{self, Display, Formatter},
    ops::Deref,
    sync::OnceLock,
};

pub use error::GitHubError;

pub struct EnvStr {
    env_var: &'static str,
    default: &'static str,
    value: OnceLock<String>,
}

impl EnvStr {
    pub const fn new(env_var: &'static str, default: &'static str) -> Self {
        Self {
            env_var,
            default,
            value: OnceLock::new(),
        }
    }

    pub fn as_str(&self) -> &str {
        self.value
            .get_or_init(|| {
                env::var(self.env_var)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| self.default.to_owned())
            })
            .as_str()
    }

    pub fn set(&self, value: String) {
        if !value.is_empty() {
            let _ = self.value.set(value);
        }
    }
}

impl AsRef<str> for EnvStr {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for EnvStr {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Display for EnvStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<&EnvStr> for &str {
    fn eq(&self, other: &&EnvStr) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<&str> for &EnvStr {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

pub struct GitHubFullName {
    value: OnceLock<String>,
}

impl GitHubFullName {
    pub const fn new() -> Self {
        Self {
            value: OnceLock::new(),
        }
    }

    pub fn as_str(&self) -> &str {
        self.value
            .get_or_init(|| format!("{}/{}", MICROSOFT.as_str(), WINGET_PKGS.as_str()))
            .as_str()
    }
}

impl AsRef<str> for GitHubFullName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for GitHubFullName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Display for GitHubFullName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<&GitHubFullName> for String {
    fn eq(&self, other: &&GitHubFullName) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<String> for &GitHubFullName {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<&GitHubFullName> for &str {
    fn eq(&self, other: &&GitHubFullName) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<&str> for &GitHubFullName {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

static MICROSOFT_VALUE: EnvStr = EnvStr::new("KOMAC_GITHUB_OWNER", "microsoft");
static WINGET_PKGS_VALUE: EnvStr = EnvStr::new("KOMAC_GITHUB_REPO", "winget-pkgs");
static WINGET_PKGS_FULL_NAME_VALUE: GitHubFullName = GitHubFullName::new();
static GITHUB_HOST_VALUE: EnvStr = EnvStr::new("KOMAC_GITHUB_HOST", "github.com");
static GITHUB_REF_VALUE: EnvStr = EnvStr::new("KOMAC_GITHUB_REF", "HEAD");

pub static MICROSOFT: &EnvStr = &MICROSOFT_VALUE;
pub static WINGET_PKGS: &EnvStr = &WINGET_PKGS_VALUE;
pub static WINGET_PKGS_FULL_NAME: &GitHubFullName = &WINGET_PKGS_FULL_NAME_VALUE;
pub static GITHUB_HOST: &EnvStr = &GITHUB_HOST_VALUE;
pub static GITHUB_REF: &EnvStr = &GITHUB_REF_VALUE;
