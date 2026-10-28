pub mod client;
mod error;
pub mod graphql;
mod local;
#[cfg(feature = "cli")]
pub mod move_package;
#[cfg(feature = "cli")]
mod package;
#[cfg(feature = "cli")]
pub(crate) mod rate_limit;
mod repository;
pub(crate) mod rest;
pub(crate) mod retry;
pub mod utils;

pub use error::GitHubError;
pub use repository::{Repository, set_upstream, upstream};

pub const MICROSOFT: &str = "microsoft";
pub const WINGET_PKGS: &str = "winget-pkgs";
pub const GITHUB_HOST: &str = "github.com";
pub const KOMAC_OWNER: &str = "russellbanks";
pub const KOMAC: &str = "Komac";

use std::{env, sync::OnceLock};

pub(crate) static GITHUB_REF: OnceLock<String> = OnceLock::new();

pub fn github_ref() -> &'static str {
    GITHUB_REF.get_or_init(|| {
        env::var("KOMAC_GITHUB_REF")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "HEAD".to_owned())
    })
}
