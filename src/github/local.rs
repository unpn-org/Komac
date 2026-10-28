use std::{collections::BTreeSet, io, path::Path};

use tokio::fs::{self, DirEntry};
use winget_types::{PackageIdentifier, PackageVersion};

use super::{GITHUB_REF, GitHubError, client::GitHubFile, utils::PackagePath};

// Colons are forbidden in Git refs, so this cannot shadow a branch or tag.
const LOCAL_REF: &str = ":local:";

pub(super) fn local_manifests_enabled() -> bool {
    GITHUB_REF.as_str() == LOCAL_REF
}

fn read_error(path: &Path, source: io::Error) -> GitHubError {
    GitHubError::LocalRead {
        path: path.to_owned(),
        source,
    }
}

pub(super) async fn read_file(path: impl AsRef<Path>) -> Result<String, GitHubError> {
    let path = path.as_ref();
    fs::read_to_string(path)
        .await
        .map_err(|error| read_error(path, error))
}

async fn directory(path: &Path) -> Result<Vec<DirEntry>, GitHubError> {
    let mut reader = fs::read_dir(path)
        .await
        .map_err(|error| read_error(path, error))?;
    let mut entries = Vec::new();
    while let Some(entry) = reader
        .next_entry()
        .await
        .map_err(|error| read_error(path, error))?
    {
        entries.push(entry);
    }
    entries.sort_unstable_by_key(DirEntry::file_name);
    Ok(entries)
}

pub(super) async fn paths(path: impl AsRef<Path>) -> Result<Vec<String>, GitHubError> {
    let mut paths = Vec::new();
    for entry in directory(path.as_ref()).await? {
        let entry_path = entry.path();
        if entry
            .file_type()
            .await
            .map_err(|error| read_error(&entry_path, error))?
            .is_file()
        {
            // GitHub paths use forward slashes on every platform.
            paths.push(entry_path.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(paths)
}

pub(super) async fn files(path: impl AsRef<Path>) -> Result<Vec<GitHubFile>, GitHubError> {
    let mut files = Vec::new();
    for path in paths(path).await? {
        let path = Path::new(&path);
        if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            files.push(GitHubFile::new(
                path.file_name().unwrap().to_string_lossy(),
                read_file(path).await?,
            ));
        }
    }
    Ok(files)
}

async fn versions(path: &PackagePath) -> Result<BTreeSet<PackageVersion>, GitHubError> {
    let mut versions = BTreeSet::new();
    for entry in directory(Path::new(path.as_str())).await? {
        let entry_path = entry.path();
        if !entry
            .file_type()
            .await
            .map_err(|error| read_error(&entry_path, error))?
            .is_dir()
        {
            continue;
        }
        let Ok(version) = entry
            .file_name()
            .to_string_lossy()
            .parse::<PackageVersion>()
        else {
            continue;
        };
        let entries = directory(&entry_path).await?;
        if entries.is_empty() {
            continue;
        }
        let mut only_files = true;
        for entry in entries {
            if !entry
                .file_type()
                .await
                .map_err(|error| read_error(&entry.path(), error))?
                .is_file()
            {
                only_files = false;
                break;
            }
        }
        if only_files {
            versions.insert(version);
        }
    }
    if versions.is_empty() {
        Err(GitHubError::NoValidFiles { path: path.clone() })
    } else {
        Ok(versions)
    }
}

pub(super) async fn get_versions(
    identifier: &PackageIdentifier,
    font: Option<bool>,
) -> Result<(BTreeSet<PackageVersion>, bool), GitHubError> {
    if let Some(font) = font {
        return versions(&PackagePath::new(identifier, None, None, font))
            .await
            .map(|versions| (versions, font));
    }
    match versions(&PackagePath::new(identifier, None, None, false)).await {
        Ok(versions) => Ok((versions, false)),
        Err(GitHubError::NoValidFiles { .. }) => get_font_versions(identifier).await,
        Err(GitHubError::LocalRead { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            get_font_versions(identifier).await
        }
        Err(error) => Err(error),
    }
}

async fn get_font_versions(
    identifier: &PackageIdentifier,
) -> Result<(BTreeSet<PackageVersion>, bool), GitHubError> {
    versions(&PackagePath::new(identifier, None, None, true))
        .await
        .map(|versions| (versions, true))
}

#[cfg(test)]
mod tests {
    use std::{env, fs, process::Command, time::Duration};

    use color_eyre::eyre::Result;
    use reqwest::{Client, Proxy};
    use reqwest_middleware::ClientBuilder;
    use winget_types::{InstallerManifest, LocaleManifest, ManifestTypeWithLocale};

    use super::*;
    use crate::github::client::GitHub;

    fn write_manifests(root: &Path, identifier: &str, version: &str, font: bool) -> Result<()> {
        let path = root.join(
            PackagePath::new(&identifier.parse()?, Some(&version.parse()?), None, font).as_str(),
        );
        fs::create_dir_all(&path)?;
        let header = format!(
            "PackageIdentifier: {identifier}\nPackageVersion: '{version}'\nManifestVersion: 1.12.0\n"
        );
        for (suffix, content) in [
            ("", "DefaultLocale: en-US\nManifestType: version\n".to_owned()),
            (".installer", format!("InstallerType: msi\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://example.com/app.msi\n  InstallerSha256: {}\nManifestType: installer\n", "A".repeat(64))),
            (".locale.en-US", "PackageLocale: en-US\nPublisher: Example\nPackageName: Example App\nLicense: MIT\nShortDescription: Example application\nManifestType: defaultLocale\n".to_owned()),
            (".locale.fr-FR", "PackageLocale: fr-FR\nPackageName: Example App\nManifestType: locale\n".to_owned()),
        ] {
            fs::write(path.join(format!("{identifier}{suffix}.yaml")), format!("{header}{content}"))?;
        }
        Ok(())
    }

    // Run with an isolated environment and working directory: configuration is cached
    // globally, and changing either in-process would race with other tests.
    #[tokio::test]
    async fn reads_manifests_from_working_directory() -> Result<()> {
        if env::var_os("KOMAC_LOCAL_TEST_CHILD").is_none() {
            let root = tempfile::tempdir()?;
            for version in ["1.0", "2.0"] {
                write_manifests(root.path(), "Example.App", version, false)?;
            }
            write_manifests(root.path(), "Example.App", "9.0", true)?;
            write_manifests(root.path(), "Example.Font", "3.0", true)?;
            fs::create_dir_all(root.path().join("manifests/e/Example/App/3.0/nested"))?;
            fs::create_dir_all(root.path().join("manifests/e/Example/App/4.0"))?;
            // Unrelated binary files must not be decoded as manifests.
            fs::write(
                root.path().join("manifests/e/Example/App/2.0/asset.bin"),
                [255],
            )?;
            for reference in [LOCAL_REF, "local", "main"] {
                let output = Command::new(env::current_exe()?)
                    .args([
                        "--exact",
                        "github::local::tests::reads_manifests_from_working_directory",
                        "--nocapture",
                    ])
                    .env("KOMAC_LOCAL_TEST_CHILD", "1")
                    .env("KOMAC_GITHUB_REF", reference)
                    .current_dir(root.path())
                    .output()?;
                assert!(
                    output.status.success(),
                    "{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return Ok(());
        }
        if GITHUB_REF.as_str() != LOCAL_REF {
            assert!(!local_manifests_enabled());
            return Ok(());
        }
        assert!(local_manifests_enabled());
        // Any accidental network request must fail, rather than querying GitHub.
        let github = GitHub(
            ClientBuilder::new(
                Client::builder()
                    .proxy(Proxy::all("http://127.0.0.1:9")?)
                    .timeout(Duration::from_secs(1))
                    .build()?,
            )
            .build(),
        );
        let identifier = "Example.App".parse()?;
        let (versions, font) = github.get_versions(&identifier, None).await?;
        assert!(!font);
        assert_eq!(
            versions.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["1.0", "2.0"]
        );
        let version = versions.last().unwrap();
        let manifests = github.get_manifests(&identifier, version, false).await?;
        assert_eq!(manifests.package_identifier(), &identifier);
        assert_eq!(manifests.package_version(), version);
        assert_eq!(manifests.locales.len(), 1);
        assert_eq!(manifests.locales[0].package_locale.to_string(), "fr-FR");
        let installer = github
            .get_manifest::<InstallerManifest>(
                &identifier,
                version,
                ManifestTypeWithLocale::Installer,
                false,
            )
            .await?;
        assert_eq!(installer.installers.len(), 1);
        let missing_locale = github
            .get_manifest::<LocaleManifest>(
                &identifier,
                version,
                ManifestTypeWithLocale::Locale("de-DE".parse()?),
                false,
            )
            .await;
        assert!(matches!(missing_locale, Err(GitHubError::LocalRead { .. })));
        #[cfg(feature = "cli")]
        {
            use crate::github::{client::RepositoryData, move_package::PackageMove};

            let upstream = RepositoryData {
                id: cynic::Id::new("example"),
                owner: "example".to_owned(),
                full_name: "example/manifests".to_owned(),
                url: "https://example.com/manifests".parse()?,
                default_branch_name: "main".to_owned(),
                default_branch_oid: "example".into(),
            };
            PackageMove::prepare(
                &github,
                &upstream,
                &identifier,
                &"Example.New".parse()?,
                version.clone(),
                false,
                None,
            )
            .await?;
        }
        let path = PackagePath::new(&identifier, Some(version), None, false);
        let paths = github
            .get_directory_content()
            .path(&path)
            .call()
            .await?
            .collect::<Vec<_>>();
        assert!(paths.contains(&format!("{path}/Example.App.installer.yaml")));
        let (font_versions, font) = github.get_versions(&identifier, Some(true)).await?;
        assert!(font);
        assert_eq!(font_versions.last().unwrap().as_str(), "9.0");
        let font_identifier = "Example.Font".parse()?;
        let (font_versions, font) = github.get_versions(&font_identifier, None).await?;
        assert!(font);
        github
            .get_manifests(&font_identifier, font_versions.last().unwrap(), font)
            .await?;
        assert!(matches!(
            github.get_versions(&font_identifier, Some(false)).await,
            Err(GitHubError::LocalRead { .. })
        ));
        assert!(matches!(
            github.get_versions(&"Example.Missing".parse()?, None).await,
            Err(GitHubError::LocalRead { .. })
        ));
        let missing = "9.0".parse()?;
        assert!(matches!(
            github.get_manifests(&identifier, &missing, false).await,
            Err(GitHubError::LocalRead { .. })
        ));
        fs::write(format!("{path}/Example.App.installer.yaml"), "invalid: [")?;
        assert!(matches!(
            github.get_manifests(&identifier, version, false).await,
            Err(GitHubError::YamlError(_))
        ));
        Ok(())
    }
}
