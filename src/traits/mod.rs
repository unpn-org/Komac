mod ascii_ext;
#[cfg(feature = "cli")]
pub mod name;
pub mod path;

use std::{cell::Cell, mem, sync::LazyLock};

pub use ascii_ext::AsciiExt;
use html2text::render::{TaggedLine, TextDecorator};
#[cfg(feature = "cli")]
pub use name::Name;
use regex::Regex;
use winget_types::{
    Manifest, PackageVersion,
    installer::Architecture,
    locale::{DefaultLocaleManifest, LocaleManifest, ReleaseNotes},
    url::ReleaseNotesUrl,
};

use super::{
    analysis::installers::pe::{
        IMAGE_FILE_MACHINE_AM33, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM,
        IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARM64EC, IMAGE_FILE_MACHINE_ARM64X,
        IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64,
        IMAGE_FILE_MACHINE_M32R, IMAGE_FILE_MACHINE_POWERPC, IMAGE_FILE_MACHINE_POWERPCFP,
        IMAGE_FILE_MACHINE_R4000, IMAGE_FILE_MACHINE_SH3, IMAGE_FILE_MACHINE_SH3DSP,
        IMAGE_FILE_MACHINE_SH4, IMAGE_FILE_MACHINE_SH5, IMAGE_FILE_MACHINE_THUMB,
        IMAGE_FILE_MACHINE_UNKNOWN,
    },
    github::{client::GitHubValues, graphql::types::Html},
};
use crate::analysis::installers::pe::PE;

pub trait FromMachine {
    fn from_machine(machine: u16) -> Self;
}

impl FromMachine for Architecture {
    fn from_machine(machine: u16) -> Self {
        match machine {
            IMAGE_FILE_MACHINE_AMD64
            | IMAGE_FILE_MACHINE_IA64
            | IMAGE_FILE_MACHINE_POWERPC
            | IMAGE_FILE_MACHINE_POWERPCFP
            | IMAGE_FILE_MACHINE_R4000
            | IMAGE_FILE_MACHINE_SH5 => Self::X64,
            IMAGE_FILE_MACHINE_AM33
            | IMAGE_FILE_MACHINE_I386
            | IMAGE_FILE_MACHINE_M32R
            | IMAGE_FILE_MACHINE_SH3
            | IMAGE_FILE_MACHINE_SH3DSP
            | IMAGE_FILE_MACHINE_SH4 => Self::X86,
            IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC | IMAGE_FILE_MACHINE_ARM64X => {
                Self::Arm64
            }
            IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_ARMNT | IMAGE_FILE_MACHINE_THUMB => {
                Self::Arm
            }
            IMAGE_FILE_MACHINE_UNKNOWN => Self::Neutral,
            _ => panic!("Unexpected architecture: {machine:?}"),
        }
    }
}

pub trait IntoWingetArchitecture {
    fn winget_architecture(&self) -> Architecture;
}

impl IntoWingetArchitecture for PE {
    fn winget_architecture(&self) -> Architecture {
        Architecture::from_machine(self.machine())
    }
}

#[derive(Default)]
struct GitHubHtmlDecorator {
    seen_header: Cell<bool>,
}

const HEADER_MARKER: &str = "__KOMAC_HEADER__ ";

impl TextDecorator for GitHubHtmlDecorator {
    type Annotation = ();

    fn decorate_link_start(&mut self, _url: &str) -> (String, Self::Annotation) {
        (String::new(), ())
    }

    fn decorate_link_end(&mut self) -> String {
        String::new()
    }

    fn decorate_em_start(&self) -> (String, Self::Annotation) {
        (String::new(), ())
    }

    fn decorate_em_end(&self) -> String {
        String::new()
    }

    fn decorate_strong_start(&self) -> (String, Self::Annotation) {
        (String::new(), ())
    }

    fn decorate_strong_end(&self) -> String {
        String::new()
    }

    fn decorate_strikeout_start(&self) -> (String, Self::Annotation) {
        (String::new(), ())
    }

    fn decorate_strikeout_end(&self) -> String {
        String::new()
    }

    fn decorate_code_start(&self) -> (String, Self::Annotation) {
        (String::new(), ())
    }

    fn decorate_code_end(&self) -> String {
        String::new()
    }

    fn decorate_preformat_first(&self) -> Self::Annotation {}

    fn decorate_preformat_cont(&self) -> Self::Annotation {}

    fn decorate_image(&mut self, _src: &str, _title: &str) -> (String, Self::Annotation) {
        (String::new(), ())
    }

    fn header_prefix(&self, _level: usize) -> String {
        self.seen_header.set(true);
        String::from(HEADER_MARKER)
    }

    fn quote_prefix(&self) -> String {
        String::from("> ")
    }

    fn unordered_item_prefix(&self) -> String {
        String::from("- ")
    }

    fn ordered_item_prefix(&self, i: i64) -> String {
        format!("{i}. ")
    }

    fn make_subblock_decorator(&self) -> Self {
        Self::default()
    }

    fn finalise(&mut self, _links: Vec<String>) -> Vec<TaggedLine<()>> {
        Vec::new()
    }
}

pub trait FromHtml {
    fn from_html(html: &Html) -> Option<Self>
    where
        Self: Sized;
}

fn add_section_spacing(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 32);
    let mut seen_header = false;
    let mut previous_line_blank = true;

    for line in text.lines() {
        let is_blank = line.trim().is_empty();
        if let Some(header) = line.strip_prefix(HEADER_MARKER) {
            if seen_header && !previous_line_blank {
                output.push('\n');
            }
            output.push_str(header);
            output.push('\n');
            seen_header = true;
            previous_line_blank = false;
            continue;
        }

        output.push_str(line);
        output.push('\n');
        previous_line_blank = is_blank;
    }

    output
}

impl FromHtml for ReleaseNotes {
    fn from_html(html: &Html) -> Option<Self> {
        // Strings that have whitespace before newlines get escaped and treated as literal strings
        // in YAML so this regex identifies any amount of whitespace and duplicate newlines
        static NEWLINE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+\n").unwrap());
        // GitHub release notes often end with compare lines such as:
        // "Full Changelog: v2.14.0...v2.15.0" or "Full Changelog: 2.14.0...2.15.0".
        // Remove any line containing a tag/version compare range.
        static COMPARE_RANGE_LINE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"(?im)^[^\n]*\b[0-9A-Za-z][0-9A-Za-z._+-]*\.\.\.[0-9A-Za-z][0-9A-Za-z._+-]*[^\n]*\n?")
                    .unwrap()
        });

        html2text::from_read_with_decorator(
            html.as_bytes(),
            usize::MAX,
            GitHubHtmlDecorator::default(),
        )
        .ok()
        .and_then(|text| {
            let normalized_text = COMPARE_RANGE_LINE_REGEX.replace_all(&text, "");
            let normalized_text = NEWLINE_REGEX.replace_all(&normalized_text, "\n");
            let normalized_text = add_section_spacing(&normalized_text);
            Self::new(normalized_text.trim()).ok()
        })
    }
}

pub trait LocaleExt {
    fn update(
        &mut self,
        package_version: &PackageVersion,
        github_values: &mut Option<GitHubValues>,
        release_notes_url: Option<&ReleaseNotesUrl>,
    );
}

impl LocaleExt for LocaleManifest {
    fn update(
        &mut self,
        package_version: &PackageVersion,
        github_values: &mut Option<GitHubValues>,
        release_notes_url: Option<&ReleaseNotesUrl>,
    ) {
        self.package_version.clone_from(package_version);
        self.release_notes_url = release_notes_url.cloned().or_else(|| {
            github_values.as_ref().and_then(|values| {
                if values.release_notes.is_some() {
                    values.release_notes_url.clone()
                } else {
                    None
                }
            })
        });
        self.manifest_type = Self::TYPE;
        self.update_manifest_version();
    }
}

impl LocaleExt for DefaultLocaleManifest {
    fn update(
        &mut self,
        package_version: &PackageVersion,
        github_values: &mut Option<GitHubValues>,
        release_notes_url: Option<&ReleaseNotesUrl>,
    ) {
        self.package_version.clone_from(package_version);
        if self.publisher_url.is_none() {
            self.publisher_url = github_values
                .as_mut()
                .map(|values| mem::take(&mut values.publisher_url));
        }
        if self.publisher_support_url.is_none() {
            self.publisher_support_url = github_values
                .as_mut()
                .and_then(|values| values.issues_url.take());
        }
        if self.package_url.is_none() {
            self.package_url = github_values
                .as_ref()
                .map(|values| values.package_url.clone());
        }
        if self.license_url.is_none() {
            self.license_url = github_values
                .as_mut()
                .and_then(|values| values.license_url.take());
        }
        if self.tags.is_empty() {
            self.tags = github_values
                .as_mut()
                .map(|values| mem::take(&mut values.topics))
                .unwrap_or_default();
        }
        self.release_notes = github_values
            .as_mut()
            .and_then(|values| values.release_notes.take());
        self.release_notes_url = release_notes_url.cloned().or_else(|| {
            github_values.as_mut().and_then(|values| {
                if self.release_notes.is_some() {
                    values.release_notes_url.take()
                } else {
                    None
                }
            })
        });
        self.manifest_type = Self::TYPE;
        self.update_manifest_version();
    }
}
