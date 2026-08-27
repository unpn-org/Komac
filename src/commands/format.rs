use std::{
    fmt::Write,
    fs,
    path::{Path, PathBuf},
    thread,
};

use anstream::println;
use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use serde::Serialize;
use walkdir::WalkDir;
use winget_types::{
    Manifest, ManifestType, VersionManifest,
    installer::InstallerManifest,
    locale::{DefaultLocaleManifest, LocaleManifest},
    utils::GenericManifest,
};

use crate::{github::utils::pull_request::convert_to_crlf, manifests::to_yaml_string};

/// Format WinGet manifests using Komac's canonical style
#[derive(Parser)]
#[clap(visible_alias = "fmt")]
pub struct Format {
    /// Repository root, manifest subtree, version directory, or manifest file
    #[arg(default_value = ".", value_hint = clap::ValueHint::AnyPath)]
    path: PathBuf,
}

impl Format {
    pub fn run(self) -> Result<()> {
        let paths = manifest_paths(&self.path)?;
        let total = paths.len();
        let formatted = format_paths(&paths)?;

        println!("Formatted {formatted} of {total} manifests");

        Ok(())
    }
}

fn manifest_paths(path: &Path) -> Result<Vec<PathBuf>> {
    let metadata =
        fs::metadata(path).wrap_err_with(|| format!("Failed to access {}", path.display()))?;

    if metadata.is_file() {
        if is_yaml(path) {
            return Ok(vec![path.to_owned()]);
        }

        bail!("{} is not a YAML manifest", path.display());
    }

    if !metadata.is_dir() {
        bail!("{} is not a file or directory", path.display());
    }

    let manifests = path.join("manifests");
    let fonts = path.join("fonts");
    let roots = [manifests, fonts]
        .into_iter()
        .filter(|root| root.is_dir())
        .collect::<Vec<_>>();
    let roots = if roots.is_empty() {
        vec![path.to_owned()]
    } else {
        roots
    };

    let mut paths = Vec::new();
    for root in roots {
        for entry in WalkDir::new(root) {
            let entry = entry.wrap_err("Failed to traverse manifest tree")?;
            if entry.file_type().is_file() && is_yaml(entry.path()) {
                paths.push(entry.into_path());
            }
        }
    }

    Ok(paths)
}

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("yaml"))
}

fn format_paths(paths: &[PathBuf]) -> Result<usize> {
    if paths.is_empty() {
        return Ok(0);
    }

    let worker_count = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(paths.len());
    let chunk_size = paths.len().div_ceil(worker_count);

    thread::scope(|scope| {
        let workers = paths
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk.iter().try_fold(0, |formatted, path| {
                        format_file(path).map(|changed| formatted + usize::from(changed))
                    })
                })
            })
            .collect::<Vec<_>>();

        workers.into_iter().try_fold(0, |formatted, worker| {
            let worker_formatted = worker
                .join()
                .map_err(|_| eyre!("Manifest formatter worker panicked"))??;
            Ok(formatted + worker_formatted)
        })
    })
}

fn format_file(path: &Path) -> Result<bool> {
    let input =
        fs::read_to_string(path).wrap_err_with(|| format!("Failed to read {}", path.display()))?;
    let created_header = input
        .lines()
        .take_while(|line| line.is_empty() || line.starts_with('#'))
        .find(|line| line.starts_with("# Created "));
    let schema_header = input
        .lines()
        .take_while(|line| line.is_empty() || line.starts_with('#'))
        .find(|line| line.starts_with("# yaml-language-server: $schema="));
    let manifest_type = fast_manifest_type(&input)
        .map(Ok)
        .unwrap_or_else(|| {
            serde_saphyr::from_str::<GenericManifest>(&input).map(|manifest| manifest.r#type)
        })
        .wrap_err_with(|| format!("Failed to read manifest type from {}", path.display()))?;

    let output = match manifest_type {
        ManifestType::Installer => render_manifest(
            &serde_saphyr::from_str::<InstallerManifest>(&input).wrap_err_with(|| {
                format!("Failed to parse installer manifest {}", path.display())
            })?,
            created_header,
            schema_header,
        )?,
        ManifestType::DefaultLocale => render_manifest(
            &serde_saphyr::from_str::<DefaultLocaleManifest>(&input).wrap_err_with(|| {
                format!("Failed to parse default locale manifest {}", path.display())
            })?,
            created_header,
            schema_header,
        )?,
        ManifestType::Locale => render_manifest(
            &serde_saphyr::from_str::<LocaleManifest>(&input)
                .wrap_err_with(|| format!("Failed to parse locale manifest {}", path.display()))?,
            created_header,
            schema_header,
        )?,
        ManifestType::Version => render_manifest(
            &serde_saphyr::from_str::<VersionManifest>(&input)
                .wrap_err_with(|| format!("Failed to parse version manifest {}", path.display()))?,
            created_header,
            schema_header,
        )?,
    };

    if input == output {
        return Ok(false);
    }

    fs::write(path, output).wrap_err_with(|| format!("Failed to write {}", path.display()))?;

    Ok(true)
}

fn fast_manifest_type(input: &str) -> Option<ManifestType> {
    input.lines().rev().find_map(|line| {
        let value = line.strip_prefix("ManifestType:")?.trim();
        match value {
            "installer" => Some(ManifestType::Installer),
            "defaultLocale" => Some(ManifestType::DefaultLocale),
            "locale" => Some(ManifestType::Locale),
            "version" => Some(ManifestType::Version),
            _ => None,
        }
    })
}

fn render_manifest<M>(
    manifest: &M,
    created_header: Option<&str>,
    schema_header: Option<&str>,
) -> Result<String>
where
    M: Manifest + Serialize,
{
    let mut output = String::new();
    if let Some(created_header) = created_header {
        let _ = writeln!(output, "{created_header}");
    }
    if let Some(schema_header) = schema_header {
        let _ = writeln!(output, "{schema_header}");
    } else {
        let _ = writeln!(output, "# yaml-language-server: $schema={}", M::SCHEMA);
    }
    output.push('\n');
    output.push_str(&to_yaml_string(manifest)?);

    Ok(convert_to_crlf(&output).into_owned())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::Path};

    use tempfile::tempdir;
    use winget_types::ManifestType;

    use super::{fast_manifest_type, format_file, format_paths, manifest_paths};

    const UNFORMATTED_VERSION_MANIFEST: &str = r#"# Created by another tool
# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.9.0.schema.json
ManifestVersion: 1.12.0
ManifestType: version
DefaultLocale: en-US
PackageVersion: 1.2.3
PackageIdentifier: Example.Package
"#;

    fn write_manifest(path: &Path) {
        fs::create_dir_all(path.parent().expect("manifest should have a parent")).unwrap();
        fs::write(path, UNFORMATTED_VERSION_MANIFEST).unwrap();
    }

    #[test]
    fn repository_root_discovers_manifests_and_fonts_only() {
        let directory = tempdir().unwrap();
        let manifest = directory
            .path()
            .join("manifests/e/Example/Package/1.2.3/Example.Package.yaml");
        let font = directory
            .path()
            .join("fonts/e/Example/Font/1.2.3/Example.Font.yaml");
        let unrelated = directory.path().join("other/Unrelated.Package.yaml");
        write_manifest(&manifest);
        write_manifest(&font);
        write_manifest(&unrelated);

        let paths = manifest_paths(directory.path())
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>();

        assert_eq!(paths, BTreeSet::from([manifest, font]));
    }

    #[test]
    fn scoped_directory_only_discovers_its_manifest_files() {
        let directory = tempdir().unwrap();
        let selected_version = directory.path().join("manifests/e/Example/Package/1.2.3");
        let selected_manifest = selected_version.join("Example.Package.yaml");
        let other_manifest = directory
            .path()
            .join("manifests/e/Example/Package/2.0.0/Example.Package.yaml");
        write_manifest(&selected_manifest);
        write_manifest(&other_manifest);

        assert_eq!(
            manifest_paths(&selected_version).unwrap(),
            [selected_manifest]
        );
    }

    #[test]
    fn preserves_created_header_and_is_idempotent() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.yaml");
        write_manifest(&path);

        assert!(format_file(&path).unwrap());

        let formatted = fs::read_to_string(&path).unwrap();
        assert!(formatted.starts_with(
            "# Created by another tool\r\n# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.9.0.schema.json\r\n\r\n"
        ));
        assert!(!formatted.contains("winget-manifest.version.1.12.0.schema.json"));
        assert_eq!(formatted.matches("# Created ").count(), 1);
        assert!(!formatted.replace("\r\n", "").contains('\n'));
        assert!(
            formatted.find("PackageIdentifier:").unwrap()
                < formatted.find("PackageVersion:").unwrap()
        );
        assert!(!format_file(&path).unwrap());
    }

    #[test]
    fn does_not_add_created_header() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.yaml");
        fs::write(
            &path,
            UNFORMATTED_VERSION_MANIFEST.replace("# Created by another tool\n", ""),
        )
        .unwrap();

        assert!(format_file(&path).unwrap());

        let formatted = fs::read_to_string(path).unwrap();
        assert!(formatted.starts_with("# yaml-language-server:"));
        assert!(!formatted.contains("# Created "));
    }

    #[test]
    fn formats_multiple_manifests() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("First.Package.yaml");
        let second = directory.path().join("Second.Package.yaml");
        write_manifest(&first);
        write_manifest(&second);

        assert_eq!(format_paths(&[first, second]).unwrap(), 2);
    }

    #[test]
    fn reads_standard_manifest_types_without_parsing_the_document() {
        assert_eq!(
            fast_manifest_type("PackageIdentifier: Example.Package\nManifestType: defaultLocale\n"),
            Some(ManifestType::DefaultLocale)
        );
        assert_eq!(
            fast_manifest_type("ManifestType: locale\r\nManifestVersion: 1.12.0\r\n"),
            Some(ManifestType::Locale)
        );
    }
}
