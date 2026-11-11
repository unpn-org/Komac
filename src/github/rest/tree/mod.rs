mod git_file_mode;
mod object;
mod r#type;

use std::collections::BTreeSet;

pub use git_file_mode::GitFileMode;
use itertools::Itertools;
pub use object::TreeObject;
use reqwest::{StatusCode, header::ACCEPT};
use serde::{Deserialize, Serialize};
pub use r#type::TreeType;
use winget_types::{PackageIdentifier, PackageVersion};

use super::{
    super::{
        GITHUB_REF, GitHubError, MICROSOFT, WINGET_PKGS,
        client::GitHub,
        local::{get_versions, local_manifests_enabled},
        utils::PackagePath,
    },
    GITHUB_JSON_MIME, REST_API_URL, REST_API_VERSION, X_GITHUB_API_VERSION,
    error::RestError,
};

/// A Git Tree which represents the hierarchy between files in a Git repository.
#[derive(Serialize, Deserialize)]
pub struct GitTree {
    pub sha: String,
    pub url: String,
    pub truncated: bool,
    pub tree: Vec<TreeObject>,
}

impl GitHub {
    /// Retrieves all available versions for a given package identifier.
    ///
    /// If `font` is `None`, this function first attempts to fetch versions from the manifest path.
    /// If no versions are found there, it tries the font path. Request errors are propagated.
    ///
    /// Returns a tuple containing:
    /// * `BTreeSet<PackageVersion>` - A set of all available package versions
    /// * `bool` - `true` if the package is a font (found in the font path)
    pub async fn get_versions(
        &self,
        package_identifier: &PackageIdentifier,
        font: Option<bool>,
    ) -> Result<(BTreeSet<PackageVersion>, bool), GitHubError> {
        if local_manifests_enabled() {
            return get_versions(package_identifier, font).await;
        }

        let paths: &[bool] = match font {
            Some(true) => &[true],
            Some(false) => &[false],
            None => &[false, true],
        };
        for &font in paths {
            if let Some(versions) = self
                .get_all_versions(
                    MICROSOFT,
                    WINGET_PKGS,
                    PackagePath::new(package_identifier, None, None, font),
                )
                .await?
            {
                return Ok((versions, font));
            }
        }

        Err(GitHubError::PackageNonExistent(package_identifier.clone()))
    }

    /// Returns all valid package versions under a specific repository path
    ///
    /// This function inspects the Git tree at the given path in the target repository, identifies
    /// directories corresponding to version folders, and returns all versions whose entries consist
    /// entirely of file objects (i.e. no subtrees).
    async fn get_all_versions(
        &self,
        owner: &str,
        repo: &str,
        path: PackagePath,
    ) -> Result<Option<BTreeSet<PackageVersion>>, GitHubError> {
        const SEPARATOR: char = '/';

        let endpoint = format!(
            "{REST_API_URL}/repos/{owner}/{repo}/git/trees/{GITHUB_REF}:{path}?recursive={recursive}",
            recursive = true
        );

        let response = self
            .0
            .get(&endpoint)
            .header(ACCEPT, GITHUB_JSON_MIME)
            .header(X_GITHUB_API_VERSION, REST_API_VERSION)
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if let Err(error) = response.error_for_status_ref() {
            // Preserve GitHub's message, or the HTTP error if the body is not JSON.
            return Err(response
                .json::<RestError>()
                .await
                .map(GitHubError::from)
                .unwrap_or_else(|_| error.into()));
        }

        let GitTree { tree, .. } = response.json::<GitTree>().await?;

        let versions = tree
            .iter()
            .filter(|entry| entry.path.matches(SEPARATOR).count() == 1)
            .chunk_by(|entry| {
                entry
                    .path
                    .split_once(SEPARATOR)
                    .map_or(entry.path.as_str(), |(version, _rest)| version)
            })
            .into_iter()
            .filter_map(|(version, mut group)| {
                group
                    .all(|object| !object.is_tree())
                    .then(|| version.parse::<PackageVersion>().ok())?
            })
            .collect::<BTreeSet<_>>();

        Ok((!versions.is_empty()).then_some(versions))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    use reqwest::Client;
    use reqwest_middleware::{ClientBuilder, RequestBuilder};

    use super::*;

    async fn lookup(
        responses: Vec<(u16, &'static str)>,
        font: Option<bool>,
    ) -> Result<(BTreeSet<PackageVersion>, bool), GitHubError> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = [0; 4096];
                stream.read(&mut request).unwrap();
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let github = GitHub(
            ClientBuilder::new(
                Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap(),
            )
            .with_init(move |builder: RequestBuilder| {
                let (client, request) = builder.build_split();
                let mut request = request.unwrap();
                request.url_mut().set_scheme("http").unwrap();
                request.url_mut().set_host(Some("127.0.0.1")).unwrap();
                request.url_mut().set_port(Some(address.port())).unwrap();
                RequestBuilder::from_parts(client, request)
            })
            .build(),
        );
        let result = github
            .get_versions(&"Pulsar-Edit.Pulsar".parse().unwrap(), font)
            .await;
        server.join().unwrap();
        result
    }

    #[tokio::test]
    async fn invalid_token_preserves_github_error() {
        for font in [None, Some(false), Some(true)] {
            let error = lookup(
                vec![(401, r#"{"message":"Bad credentials","status":"401"}"#)],
                font,
            )
            .await
            .unwrap_err();
            assert_eq!(error.to_string(), "Status 401: Bad credentials");
        }
    }

    #[tokio::test]
    async fn font_lookup_preserves_permission_error() {
        let error = lookup(
            vec![
                (404, "{}"),
                (
                    403,
                    r#"{"message":"API rate limit exceeded","status":"403"}"#,
                ),
            ],
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "Status 403: API rate limit exceeded");
    }

    #[tokio::test]
    async fn missing_package_keeps_package_error() {
        for font in [None, Some(false), Some(true)] {
            let count = if font.is_none() { 2 } else { 1 };
            let error = lookup(vec![(404, "{}"); count], font).await.unwrap_err();
            assert!(matches!(error, GitHubError::PackageNonExistent(_)));
        }
    }

    #[tokio::test]
    async fn missing_manifest_path_falls_back_to_fonts() {
        let (versions, font) = lookup(vec![
            (404, "{}"),
            (200, r#"{"sha":"test","url":"test","truncated":false,"tree":[{"path":"1.0/Pulsar-Edit.Pulsar.yaml","mode":"100644","type":"blob","sha":"test","url":"test"}]}"#),
        ], None).await.unwrap();
        assert!(font);
        assert_eq!(
            versions
                .into_iter()
                .map(|version| version.to_string())
                .collect::<Vec<_>>(),
            ["1.0"]
        );
    }

    #[tokio::test]
    async fn non_json_error_preserves_http_status() {
        let error = lookup(vec![(502, "Bad gateway")], None).await.unwrap_err();
        assert!(
            matches!(error, GitHubError::Reqwest(error) if error.status() == Some(StatusCode::BAD_GATEWAY))
        );
    }
}
