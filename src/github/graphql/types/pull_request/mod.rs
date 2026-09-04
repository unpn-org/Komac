mod state;

use jiff::Timestamp;
pub use state::PullRequestState;
use url::Url;

use crate::github::graphql::github_schema as schema;

#[derive(cynic::QueryFragment)]
pub struct PullRequest {
    pub title: String,
    pub url: Url,
    pub state: PullRequestState,
    pub created_at: Timestamp,
    #[allow(dead_code)]
    pub viewer_did_author: bool,
    #[allow(dead_code)]
    pub author: Option<Actor>,
}

#[derive(cynic::QueryFragment)]
pub struct Actor {
    #[allow(dead_code)]
    pub login: String,
}

impl PullRequest {
    #[allow(dead_code)]
    #[inline]
    pub fn author_login(&self) -> Option<&String> {
        self.author.as_ref().map(|author| &author.login)
    }

    /// Returns `true` if the pull request has been closed without being merged.
    #[expect(unused)]
    #[inline]
    pub const fn is_closed(&self) -> bool {
        self.state.is_closed()
    }

    /// Returns `true` if the pull request has been closed by being merged.
    #[expect(unused)]
    #[inline]
    pub const fn is_merged(&self) -> bool {
        self.state.is_merged()
    }

    /// Returns `true` if the pull request is still open.
    #[inline]
    pub const fn is_open(&self) -> bool {
        self.state.is_open()
    }
}
