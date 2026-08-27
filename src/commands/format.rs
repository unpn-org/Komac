use std::{
    fmt::Write,
    fs,
    path::{Path, PathBuf},
    thread,
};

use anstream::println;
use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use serde::{Serialize, de::DeserializeOwned};
use walkdir::WalkDir;
use winget_types::{
    Manifest, ManifestType, VersionManifest,
    installer::InstallerManifest,
    locale::{DefaultLocaleManifest, LocaleManifest},
    utils::GenericManifest,
};

use crate::{github::utils::pull_request::convert_to_crlf, manifests::to_yaml_string};

mod comments;

/// Format WinGet manifests using Komac's canonical style
#[derive(Parser)]
#[clap(visible_alias = "fmt")]
pub struct Format {
    /// Repository root, manifest subtree, version directory, or manifest file
    #[arg(default_value = ".", value_hint = clap::ValueHint::AnyPath)]
    path: PathBuf,

    /// Check formatting without writing files, failing if any manifests need formatting
    #[arg(long)]
    check: bool,
}

impl Format {
    pub fn run(self) -> Result<()> {
        let paths = manifest_paths(&self.path)?;
        let total = paths.len();
        let formatted = format_paths(&paths, self.check)?;

        if self.check {
            if formatted > 0 {
                bail!("{formatted} of {total} manifests need formatting");
            }
            println!("Checked {total} manifests; all are formatted");
        } else {
            println!("Formatted {formatted} of {total} manifests");
        }

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

fn format_paths(paths: &[PathBuf], check: bool) -> Result<usize> {
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
                        format_file(path, check).map(|changed| formatted + usize::from(changed))
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

fn format_file(path: &Path, check: bool) -> Result<bool> {
    let input =
        fs::read_to_string(path).wrap_err_with(|| format!("Failed to read {}", path.display()))?;
    let manifest_type = fast_manifest_type(&input)
        .map(Ok)
        .unwrap_or_else(|| {
            serde_saphyr::from_str::<GenericManifest>(&input).map(|manifest| manifest.r#type)
        })
        .wrap_err_with(|| format!("Failed to read manifest type from {}", path.display()))?;

    let output = match manifest_type {
        ManifestType::Installer => format_manifest::<InstallerManifest>(&input, |manifest| {
            manifest.installers.sort_unstable();
        }),
        ManifestType::DefaultLocale => format_manifest::<DefaultLocaleManifest>(&input, |_| {}),
        ManifestType::Locale => format_manifest::<LocaleManifest>(&input, |_| {}),
        ManifestType::Version => format_manifest::<VersionManifest>(&input, |_| {}),
    }
    .wrap_err_with(|| {
        format!(
            "Failed to format {manifest_type} manifest {}",
            path.display()
        )
    })?;

    if input == output {
        return Ok(false);
    }

    if check {
        println!("Would reformat {}", path.display());
    } else {
        fs::write(path, output).wrap_err_with(|| format!("Failed to write {}", path.display()))?;
    }

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

fn format_manifest<M>(input: &str, normalize: impl FnOnce(&mut M)) -> Result<String>
where
    M: Manifest + Serialize + DeserializeOwned,
{
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut manifest: M = serde_saphyr::from_str(input)?;
    normalize(&mut manifest);

    let mut headers = input
        .lines()
        .take_while(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
        .map(|line| {
            if let Some(text) = line.trim_start().strip_prefix('#') {
                let indent = &line[..line.len() - line.trim_start().len()];
                format!("{indent}{}", comments::normalize(text))
            } else {
                String::new()
            }
        })
        .collect::<Vec<_>>();
    // Comments after the header separator describe the first field. Keeping them in
    // the body avoids absorbing them into the header on the next formatting pass.
    if let Some(separator) = headers.iter().rposition(|line| line.trim().is_empty())
        && !headers[separator + 1..].iter().any(|line| {
            line.trim_start().starts_with("# Created ")
                || line
                    .trim_start()
                    .starts_with("# yaml-language-server: $schema=")
        })
    {
        headers.truncate(separator + 1);
    }
    let mut output = String::new();
    for header in &headers {
        let _ = writeln!(output, "{header}");
    }
    if !headers.iter().any(|line| {
        line.trim_start()
            .starts_with("# yaml-language-server: $schema=")
    }) {
        let _ = writeln!(output, "# yaml-language-server: $schema={}", M::SCHEMA);
    }
    if !output.ends_with("\n\n") {
        output.push('\n');
    }
    output.push_str(&comments::preserve(
        input,
        &to_yaml_string(&manifest)?,
        headers.len(),
    )?);

    Ok(convert_to_crlf(&output).into_owned())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::Path};

    use tempfile::tempdir;
    use winget_types::{
        ManifestType,
        installer::{Architecture, InstallerManifest},
    };

    use super::{Format, fast_manifest_type, format_file, format_paths, manifest_paths};

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

        assert!(format_file(&path, false).unwrap());

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
        assert!(!format_file(&path, false).unwrap());
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

        assert!(format_file(&path, false).unwrap());

        let formatted = fs::read_to_string(path).unwrap();
        assert!(formatted.starts_with("# yaml-language-server:"));
        assert!(!formatted.contains("# Created "));
    }

    #[test]
    fn preserves_header_field_inline_and_trailing_comments() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.yaml");
        let input = "# Maintainer notes\n\n# Created by another tool\n# Keep this manifest\nManifestVersion: 1.12.0 # schema version\n# Manifest kind\nManifestType: version\nDefaultLocale: en-US\nPackageVersion: 1.2.3 # package version\n# Package identity\nPackageIdentifier: Example.Package\n# End of manifest\n# Another final note\n";
        fs::write(&path, input).unwrap();

        assert!(format_file(&path, false).unwrap());

        let formatted = fs::read_to_string(&path).unwrap();
        assert!(formatted.starts_with(
            "# Maintainer notes\r\n\r\n# Created by another tool\r\n# Keep this manifest\r\n# yaml-language-server:"
        ));
        assert!(formatted.contains("# Package identity\r\nPackageIdentifier: Example.Package"));
        assert!(
            formatted.contains("PackageVersion: '1.2.3' # package version\r\n"),
            "{formatted}"
        );
        assert!(formatted.contains("# Manifest kind\r\nManifestType: version\r\n"));
        assert!(formatted.contains("ManifestVersion: '1.12.0' # schema version\r\n"));
        assert!(formatted.ends_with("# End of manifest\r\n# Another final note\r\n"));
        assert!(!format_file(&path, false).unwrap());
    }

    #[test]
    fn preserves_comments_with_bom_and_crlf_in_check_mode() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.yaml");
        let input = format!(
            "\u{feff}# Maintainer notes\r\n{}# Final note\r\n",
            UNFORMATTED_VERSION_MANIFEST.replace('\n', "\r\n"),
        );
        fs::write(&path, &input).unwrap();

        assert!(format_file(&path, true).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), input);
        assert!(format_file(&path, false).unwrap());

        let formatted = fs::read_to_string(&path).unwrap();
        assert!(formatted.starts_with("# Maintainer notes\r\n# Created by another tool\r\n"));
        assert!(formatted.ends_with("# Final note\r\n"));
        assert!(!format_file(&path, true).unwrap());
    }

    #[test]
    fn normalizes_comment_spacing_and_removes_trailing_whitespace() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.yaml");
        let input = "#Created by another tool  \t\n#yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.9.0.schema.json \t\n \t\nManifestVersion: 1.12.0 #schema version \t\n#\tManifest kind  \nManifestType: version \t\nDefaultLocale: en-US  \nPackageVersion: 1.2.3 #   package version  \nPackageIdentifier: Example.Package \t\n#final note \t\n# \t\n";
        fs::write(&path, input).unwrap();

        assert!(format_file(&path, true).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), input);
        assert!(format_file(&path, false).unwrap());

        let formatted = fs::read_to_string(&path).unwrap();
        assert!(formatted.starts_with("# Created by another tool\r\n# yaml-language-server:"));
        assert_eq!(formatted.matches("# yaml-language-server:").count(), 1);
        assert!(formatted.contains("# Manifest kind\r\nManifestType: version\r\n"));
        assert!(formatted.contains("PackageVersion: '1.2.3' # package version\r\n"));
        assert!(formatted.contains("ManifestVersion: '1.12.0' # schema version\r\n"));
        assert!(formatted.ends_with("# final note\r\n#\r\n"));
        assert!(formatted.lines().all(|line| line == line.trim_end()));
        assert!(!format_file(&path, true).unwrap());
    }

    #[test]
    fn formats_multiple_manifests() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("First.Package.yaml");
        let second = directory.path().join("Second.Package.yaml");
        write_manifest(&first);
        write_manifest(&second);

        assert_eq!(format_paths(&[first, second], false).unwrap(), 2);
    }

    #[test]
    fn check_reports_unformatted_manifests_without_writing_files() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("First.Package.yaml");
        let second = directory.path().join("Second.Package.yaml");
        let formatted = directory.path().join("Formatted.Package.yaml");
        write_manifest(&first);
        write_manifest(&second);
        write_manifest(&formatted);
        format_file(&formatted, false).unwrap();
        let formatted_input = fs::read(&formatted).unwrap();

        let error = Format {
            path: directory.path().to_owned(),
            check: true,
        }
        .run()
        .unwrap_err();

        assert_eq!(error.to_string(), "2 of 3 manifests need formatting");
        for path in [&first, &second] {
            assert_eq!(
                fs::read_to_string(path).unwrap(),
                UNFORMATTED_VERSION_MANIFEST
            );
        }
        assert_eq!(fs::read(&formatted).unwrap(), formatted_input);
    }

    #[test]
    fn check_succeeds_for_formatted_manifests() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.yaml");
        write_manifest(&path);
        format_file(&path, false).unwrap();
        let input = fs::read(&path).unwrap();

        Format {
            path: path.clone(),
            check: true,
        }
        .run()
        .unwrap();

        assert_eq!(fs::read(&path).unwrap(), input);
    }

    #[test]
    fn check_succeeds_for_empty_directories() {
        let directory = tempdir().unwrap();

        Format {
            path: directory.path().to_owned(),
            check: true,
        }
        .run()
        .unwrap();
    }

    #[test]
    fn formats_both_locale_types_and_quoted_manifest_types() {
        let directory = tempdir().unwrap();
        for manifest_type in ["locale", "defaultLocale"] {
            let path = directory.path().join(format!("{manifest_type}.yaml"));
            fs::write(&path, format!(
                "ManifestType: '{manifest_type}' # quoted type\nManifestVersion: 1.12.0\nPackageLocale: fr-FR\nShortDescription: Une application\nLicense: MIT\nPackageName: Exemple\nPublisher: Exemple\nPackageVersion: 1.2.3\nPackageIdentifier: Example.Package\n"
            )).unwrap();

            assert!(format_file(&path, false).unwrap());
            let formatted = fs::read_to_string(&path).unwrap();
            assert!(formatted.starts_with(&format!(
                "# yaml-language-server: $schema=https://aka.ms/winget-manifest.{manifest_type}."
            )));
            assert!(formatted.contains("PackageLocale: fr-FR\r\n"));
            assert!(
                formatted.contains(&format!("ManifestType: {manifest_type} # quoted type\r\n"))
            );
            assert!(!format_file(&path, false).unwrap());
        }
    }

    #[test]
    fn leaves_invalid_manifests_unchanged() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Invalid.Package.yaml");
        let input = "ManifestType: version\nPackageIdentifier: Example.Package\n";
        fs::write(&path, input).unwrap();

        for check in [false, true] {
            let error = format_file(&path, check).unwrap_err();
            assert!(error.to_string().contains("Invalid.Package.yaml"));
            assert_eq!(fs::read_to_string(&path).unwrap(), input);
        }
    }

    #[test]
    fn uppercases_hashes_and_sorts_installers() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.installer.yaml");
        fs::write(
            &path,
            r#"PackageIdentifier: Example.Package
PackageVersion: 1.2.3
Installers:
- Architecture: arm64
  InstallerUrl: https://example.com/arm64.exe
  InstallerSha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
- Architecture: x64
  InstallerUrl: https://example.com/x64.exe
  InstallerSha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  SignatureSha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
- Architecture: x86
  InstallerUrl: https://example.com/x86.exe
  InstallerSha256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
ManifestType: installer
ManifestVersion: 1.12.0
"#,
        )
        .unwrap();

        assert!(format_file(&path, false).unwrap());

        let formatted = fs::read_to_string(&path).unwrap();
        let manifest = serde_saphyr::from_str::<InstallerManifest>(&formatted).unwrap();
        assert_eq!(
            manifest
                .installers
                .iter()
                .map(|installer| installer.architecture)
                .collect::<Vec<_>>(),
            [Architecture::X86, Architecture::X64, Architecture::Arm64]
        );
        assert!(formatted.contains(&"A".repeat(64)));
        assert!(formatted.contains(&"B".repeat(64)));
        assert!(formatted.contains(&"C".repeat(64)));
        assert!(formatted.contains(&"D".repeat(64)));
        assert!(!formatted.contains(&"a".repeat(64)));
        assert!(!formatted.contains(&"b".repeat(64)));
        assert!(!formatted.contains(&"c".repeat(64)));
        assert!(!formatted.contains(&"d".repeat(64)));
        assert!(!format_file(&path, false).unwrap());
    }

    #[test]
    fn comments_follow_installers_when_sorted() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.installer.yaml");
        let input = format!(
            "PackageIdentifier: Example.Package\nPackageVersion: 1.2.3\nInstallers: # downloads\n# ARM installer\n- Architecture: arm64 # ARM architecture\n  InstallerUrl: https://example.com/arm64.exe # ARM download\n  InstallerSha256: {} # ARM hash\n# x86 installer\n- Architecture: x86 # x86 architecture\n  InstallerUrl: https://example.com/x86.exe # x86 download\n  InstallerSha256: {} # x86 hash\nManifestType: installer\nManifestVersion: 1.12.0\n",
            "a".repeat(64),
            "b".repeat(64),
        );
        fs::write(&path, input).unwrap();

        assert!(format_file(&path, false).unwrap());

        let formatted = fs::read_to_string(&path).unwrap();
        assert!(formatted.contains("Installers: # downloads\r\n"));
        for (architecture, description, hash) in [("arm64", "ARM", 'A'), ("x86", "x86", 'B')] {
            assert!(formatted.contains(&format!(
                "# {description} installer\r\n- Architecture: {architecture} # {description} architecture\r\n  InstallerUrl: https://example.com/{architecture}.exe # {description} download\r\n  InstallerSha256: {} # {description} hash\r\n",
                hash.to_string().repeat(64),
            )));
        }
        assert!(
            formatted.find("# x86 installer").unwrap() < formatted.find("# ARM installer").unwrap()
        );
        assert!(!format_file(&path, false).unwrap());
    }

    #[test]
    fn normalizes_manifest_paths_to_windows_separators() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.Package.installer.yaml");
        fs::write(
            &path,
            r#"PackageIdentifier: Example.Package
PackageVersion: 1.2.3
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
- RelativeFilePath: bin/app.exe
InstallationMetadata:
  DefaultInstallLocation: '%ProgramFiles%/Example'
  Files:
  - RelativeFilePath: bin/app.exe
InstallerSwitches:
  Silent: /S
Installers:
- Architecture: x64
  InstallerUrl: https://example.com/app.zip
  InstallerSha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ManifestType: installer
ManifestVersion: 1.12.0
"#,
        )
        .unwrap();

        assert!(format_file(&path, false).unwrap());

        let formatted = fs::read_to_string(&path).unwrap();
        assert_eq!(
            formatted.matches(r"RelativeFilePath: bin\app.exe").count(),
            2
        );
        assert!(formatted.contains(r"%ProgramFiles%\Example"));
        assert!(formatted.contains("Silent: /S"));
        assert!(formatted.contains("InstallerUrl: https://example.com/app.zip"));
        assert!(!format_file(&path, false).unwrap());
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
