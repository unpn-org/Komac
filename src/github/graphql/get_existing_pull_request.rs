use cynic::QueryBuilder;
use winget_types::{PackageIdentifier, PackageVersion};

use super::{
    super::{GitHubError, WINGET_PKGS_FULL_NAME, client::GitHub},
    github_schema as schema,
    types::PullRequest,
};

#[derive(cynic::QueryVariables)]
pub struct GetExistingPullRequestVariables<'a> {
    pub query: &'a str,
}

#[derive(cynic::QueryFragment)]
#[cynic(graphql_type = "Query", variables = "GetExistingPullRequestVariables")]
pub struct GetExistingPullRequest {
    #[arguments(first: 100, type: ISSUE, query: $query)]
    pub search: SearchResultItemConnection,
}

impl GetExistingPullRequest {
    pub fn into_pull_requests(self) -> impl Iterator<Item = PullRequest> {
        self.search
            .nodes
            .into_iter()
            .filter_map(SearchResultItem::into_pull_request)
    }
}

#[derive(cynic::QueryFragment)]
pub struct SearchResultItemConnection {
    #[cynic(flatten)]
    pub nodes: Vec<SearchResultItem>,
}

#[derive(cynic::InlineFragments)]
pub enum SearchResultItem {
    PullRequest(PullRequest),
    #[cynic(fallback)]
    Unknown,
}

impl SearchResultItem {
    pub fn into_pull_request(self) -> Option<PullRequest> {
        match self {
            Self::PullRequest(pull_request) => Some(pull_request),
            Self::Unknown => None,
        }
    }
}

impl GitHub {
    pub async fn get_existing_pull_request(
        &self,
        identifier: &PackageIdentifier,
        version: &PackageVersion,
        authenticated_user_only: bool,
    ) -> Result<Option<PullRequest>, GitHubError> {
        let author_filter = if authenticated_user_only {
            " author:@me"
        } else {
            ""
        };
        let query = format!(
            "repo:{WINGET_PKGS_FULL_NAME} is:pull-request in:title {identifier} {version}{author_filter}"
        );

        let response = self
            .run_graphql_with_retry(&GetExistingPullRequest::build(
                GetExistingPullRequestVariables { query: &query },
            ))
            .await?;

        Ok(response.data.and_then(|data| {
            data.into_pull_requests().find(|pull_request| {
                let title = &*pull_request.title;
                // Check that the identifier and version are used in their entirety and not
                // part of another package identifier or version. For example, ensuring we
                // match against "Microsoft.Excel" not "Microsoft.Excel.Beta", or "1.2.3"
                // and not "1.2.3-beta" as `in:title` in the query only does a 'contains'
                // rather than a word boundary match.
                [identifier.as_str(), version.as_str()]
                    .into_iter()
                    .all(|needle| {
                        title.match_indices(needle).any(|(index, matched)| {
                            let before = title[..index].chars().next_back();
                            let after = title[index + matched.len()..].chars().next();
                            // Check whether the characters before and after the identifier
                            // are either None (at the boundary of the title) or whitespace
                            before.is_none_or(char::is_whitespace)
                                && after.is_none_or(char::is_whitespace)
                        })
                    })
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use cynic::QueryBuilder;
    use indoc::indoc;

    use super::{GetExistingPullRequest, GetExistingPullRequestVariables};

    #[test]
    fn get_existing_pull_request_output() {
        const GET_EXISTING_PULL_REQUEST_QUERY: &str = indoc! {r#"
            query GetExistingPullRequest($query: String!) {
              search(first: 100, type: ISSUE, query: $query) {
                nodes {
                  __typename
                  ... on PullRequest {
                    title
                    url
                    state
                    createdAt
                    viewerDidAuthor
                    author {
                      login
                    }
                  }
                }
              }
            }
        "#};

        let operation =
            GetExistingPullRequest::build(GetExistingPullRequestVariables { query: "" });

        assert_eq!(operation.query, GET_EXISTING_PULL_REQUEST_QUERY);
    }
}
