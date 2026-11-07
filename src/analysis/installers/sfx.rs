use std::{
    collections::BTreeSet,
    io::{self, Read, Seek, SeekFrom},
};

use sevenz_rust2::{Archive, BlockDecoder, Password};
use winget_types::installer::Architecture;

use super::pe::{PE, resource::SectionReader, utils::machine_from_exe_reader};
use crate::traits::FromMachine;

const SIGNATURE: &[u8] = b"7z\xBC\xAF\x27\x1C";
const MAX_SETUP: u64 = 256 * 1024 * 1024;

pub struct WrappedSetup {
    pub data: Vec<u8>,
    pub architecture: Option<Architecture>,
}

/// Extracts the `setup.exe` selected by a 7-Zip SFX configuration.
fn setup_config(prefix: &[u8]) -> Option<usize> {
    let archive = memchr::memmem::find(prefix, SIGNATURE)?;
    let start = memchr::memmem::find(&prefix[..archive], b";!@Install@!UTF-8!")?;
    let config = std::str::from_utf8(&prefix[start..archive]).ok()?;
    let end = config.find(";!@InstallEnd@!")?;
    let start = 0;
    let launches_setup = config[start..end].lines().any(|line| {
        let Some((key, value)) = line.trim().split_once('=') else {
            return false;
        };
        key.trim().eq_ignore_ascii_case("RunProgram")
            && value
                .trim()
                .trim_start_matches('"')
                .split_whitespace()
                .next()
                .is_some_and(|value| {
                    value
                        .trim_end_matches('"')
                        .eq_ignore_ascii_case("setup.exe")
                })
    });
    launches_setup.then_some(archive)
}

pub fn read_setup<R: Read + Seek>(
    reader: &mut R,
    pe: &PE,
    product: Option<&str>,
) -> io::Result<Option<WrappedSetup>> {
    let Some(overlay) = pe.overlay_offset() else {
        return Ok(None);
    };
    reader.seek(SeekFrom::Start(overlay))?;
    let mut prefix = Vec::new();
    reader.by_ref().take(65536).read_to_end(&mut prefix)?;
    let Some(offset) = setup_config(&prefix) else {
        return Ok(None);
    };
    let source = SectionReader::from_offset(reader, overlay + offset as u64)?;
    read_archive(source, product).map(Some)
}

fn read_archive<R: Read + Seek>(mut source: R, product: Option<&str>) -> io::Result<WrappedSetup> {
    let password = Password::empty();
    let archive = Archive::read(&mut source, &password).map_err(io::Error::other)?;
    let setup = archive
        .files
        .iter()
        .position(|file| file.name().eq_ignore_ascii_case("setup.exe") && !file.is_directory)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SFX setup.exe is missing"))?;
    if archive.files[setup].size() > MAX_SETUP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SFX setup.exe exceeds the analysis resource limit",
        ));
    }
    let product = product
        .unwrap_or_default()
        .split_whitespace()
        .last()
        .unwrap_or_default();
    let candidates: Vec<_> = archive
        .files
        .iter()
        .enumerate()
        .filter(|(_, file)| {
            let name = file.name().replace('\\', "/").to_ascii_lowercase();
            let Some(name) = name.strip_prefix("core/") else {
                return false;
            };
            let Some(stem) = name.strip_suffix(".exe") else {
                return false;
            };
            !file.is_directory
                && (stem.eq_ignore_ascii_case("firefox")
                    || stem.eq_ignore_ascii_case("thunderbird")
                    || (!product.is_empty() && stem.eq_ignore_ascii_case(product)))
        })
        .map(|(index, _)| index)
        .collect();
    let application = if candidates.len() == 1 {
        candidates.first().copied()
    } else {
        None
    };
    let blocks: BTreeSet<_> = std::iter::once(setup)
        .chain(application)
        .filter_map(|index| archive.stream_map.file_block_index[index])
        .collect();
    let mut data = None;
    let mut architecture = None;
    let mut application_read = false;
    for block in blocks {
        BlockDecoder::new(2, block, &archive, &password, &mut source)
            .for_each_entries(&mut |entry, reader| {
                if entry.name() == archive.files[setup].name() {
                    let mut bytes = Vec::new();
                    reader.take(MAX_SETUP + 1).read_to_end(&mut bytes)?;
                    if bytes.len() as u64 > MAX_SETUP {
                        return Err(io::Error::other(
                            "SFX setup exceeds the analysis resource limit",
                        )
                        .into());
                    }
                    data = Some(bytes);
                } else if application
                    .is_some_and(|index| entry.name() == archive.files[index].name())
                {
                    application_read = true;
                    architecture = machine_from_exe_reader(reader)
                        .ok()
                        .and_then(Architecture::try_from_machine);
                }
                Ok(data.is_none() || (application.is_some() && !application_read))
            })
            .map_err(io::Error::other)?;
    }
    let data =
        data.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SFX setup has no data"))?;
    Ok(WrappedSetup { data, architecture })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_application_architecture_instead_of_wrapper_architecture() {
        let bytes = include_bytes!("../../../tests/fixtures/nsis/setup-arm64.7z");
        let setup = read_archive(std::io::Cursor::new(bytes), Some("Mozilla Firefox")).unwrap();
        assert_eq!(setup.data, b"compiled setup fixture");
        assert_eq!(setup.architecture, Some(Architecture::Arm64));
    }

    #[test]
    fn reads_case_insensitive_setup_entry() {
        let bytes = include_bytes!("../../../tests/fixtures/nsis/setup.7z");
        let setup = read_archive(std::io::Cursor::new(bytes), None).unwrap();
        assert_eq!(setup.data, b"compiled setup fixture");
        assert_eq!(setup.architecture, None);
    }

    #[test]
    fn requires_an_explicit_setup_launch() {
        let mut prefix =
            b";!@Install@!UTF-8!\nRunProgram=\"setup.exe\"\n;!@InstallEnd@!\n".to_vec();
        let offset = prefix.len();
        prefix.extend(SIGNATURE);
        assert_eq!(setup_config(&prefix), Some(offset));
        let mut padded = vec![0xff, 0xfe];
        padded.extend(&prefix);
        assert_eq!(setup_config(&padded), Some(offset + 2));
        let unrelated =
            b";!@Install@!UTF-8!\nRunProgram=\"viewer.exe\"\n;!@InstallEnd@!\n7z\xBC\xAF\x27\x1C";
        assert_eq!(setup_config(unrelated), None);
        assert_eq!(setup_config(SIGNATURE), None);
    }
}
