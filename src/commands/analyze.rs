use std::{
    fs::File,
    io,
    io::{Read, Seek, SeekFrom},
};

use anstream::stdout;
use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use color_eyre::{Result, eyre::ensure};
use serde::Serialize;
use sha2::{Digest, Sha256, digest::Output};
use winget_types::{Sha256String, installer::Installer};

use crate::{
    analysis::{Analyzer, FontInfo, PeInfo, installers::font::FontAnalysis},
    manifests::{print_manifest, to_yaml_string},
};

/// Analyzes a file and outputs information about it
#[derive(Parser)]
#[clap(visible_alias = "analyse")]
pub struct Analyze {
    #[arg(value_parser = is_valid_file, value_hint = clap::ValueHint::FilePath)]
    file_path: Utf8PathBuf,

    #[cfg(not(debug_assertions))]
    /// Hash the file and include it in the `InstallerSha256` field
    #[arg(long = "hash", alias = "sha256", overrides_with = "hash")]
    _no_hash: bool,

    #[cfg(not(debug_assertions))]
    /// Skip hashing the file
    #[arg(long = "no-hash", alias = "no-sha256", action = clap::ArgAction::SetFalse)]
    hash: bool,

    #[cfg(debug_assertions)]
    /// Hash the file and include it in the `InstallerSha256` field
    #[arg(long, alias = "sha256", overrides_with = "_no_hash")]
    hash: bool,

    #[cfg(debug_assertions)]
    /// Skip hashing the file
    #[arg(long = "no-hash", alias = "no-sha256")]
    _no_hash: bool,
}

impl Analyze {
    pub fn run(self) -> Result<()> {
        let mut file = File::open(&self.file_path)?;
        let file_name = self
            .file_path
            .file_name()
            .unwrap_or_else(|| self.file_path.as_str());
        let sha_256 = self
            .hash
            .then(|| {
                let sha_256 = Sha256String::from_digest(&sha256_digest(&mut file)?);
                file.seek(SeekFrom::Start(0))?;
                Ok::<_, io::Error>(sha_256)
            })
            .transpose()?;

        let mut analyzer = Analyzer::new(&mut file, file_name, FontAnalysis::Full)?;
        if let Some(sha_256) = sha_256 {
            for installer in &mut analyzer.installers {
                installer.sha_256 = sha_256.clone();
            }
        }
        let yaml = match (
            analyzer.pe_info.as_ref(),
            analyzer.font_info.as_ref(),
            analyzer.installers.as_slice(),
        ) {
            (Some(pe_info), None, [installer]) => {
                to_yaml_string(&AnalyzeSingleOutput { pe_info, installer })?
            }
            (Some(pe_info), None, installers) => to_yaml_string(&AnalyzeMultiOutput {
                pe_info,
                installers,
            })?,
            (None, Some(font_info), [installer]) => to_yaml_string(&AnalyzeFontOutput {
                font_info,
                installer,
            })?,
            (None, Some(_), _) => unreachable!("font analysis always produces one installer"),
            (None, None, [installer]) => to_yaml_string(installer)?,
            (None, None, installers) => to_yaml_string(&installers)?,
            (Some(_), Some(_), _) => unreachable!("a file cannot be both a PE and a font"),
        };
        let mut lock = stdout().lock();
        print_manifest(&mut lock, &yaml);
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AnalyzeSingleOutput<'a> {
    #[serde(rename = "PEInfo")]
    pe_info: &'a PeInfo,
    installer: &'a Installer,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AnalyzeMultiOutput<'a> {
    #[serde(rename = "PEInfo")]
    pe_info: &'a PeInfo,
    installers: &'a [Installer],
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AnalyzeFontOutput<'a> {
    font_info: &'a FontInfo,
    installer: &'a Installer,
}

fn sha256_digest<R: Read>(mut reader: R) -> io::Result<Output<Sha256>> {
    let mut digest = Sha256::new();
    let mut buffer = [0; 1 << 13];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }

    Ok(digest.finalize())
}

fn is_valid_file(path: &str) -> Result<Utf8PathBuf> {
    let path = Utf8Path::new(path);
    ensure!(path.exists(), "{path} does not exist");
    ensure!(path.is_file(), "{path} is not a file");
    Ok(path.to_path_buf())
}
