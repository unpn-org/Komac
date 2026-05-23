pub mod client;
mod error;
pub mod graphql;
#[cfg(feature = "cli")]
mod package;
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
