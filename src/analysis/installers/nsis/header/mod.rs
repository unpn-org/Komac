pub mod block;
mod compression;
mod decoder;
pub mod flags;
pub(super) mod indexed;
pub(super) mod lzma2;
pub(super) mod nsis_bzip2;
pub(super) mod nsis_deflate;
pub(super) mod threaded_lzma;

use std::{
    fmt, io,
    io::{Error, ErrorKind, Read, Seek},
};

pub use compression::Compression;
pub use decoder::Decoder;
use tracing::debug;
use zerocopy::{FromBytes, I32, LE};

use super::{FirstHeader, NsisError};
use crate::{
    analysis::installers::{
        nsis::header::{
            block::{BlockHeaders, BlockType},
            flags::CommonHeaderFlags,
        },
        utils::LzmaStreamHeader,
    },
    read::ReadBytesExt,
};

const NSIS_MAX_INST_TYPES: u8 = 32;

/// <https://github.com/NSIS-Dev/nsis/blob/v311/Source/exehead/fileform.h#L295>
#[derive(Clone)]
#[repr(C)]
pub struct Header {
    indexed_files: Option<Vec<indexed::FileRecord>>,
    common_header_flags: CommonHeaderFlags,
    blocks: BlockHeaders,

    #[doc(alias = "install_reg_rootkey")]
    install_registry_root_key: I32<LE>,

    #[doc(alias = "install_reg_key_ptr")]
    install_registry_key_ptr: I32<LE>,

    #[doc(alias = "install_reg_value_ptr")]
    install_registry_value_ptr: I32<LE>,

    #[doc(alias = "bg_color1")]
    background_color_1: I32<LE>,

    #[doc(alias = "bg_color2")]
    background_color_2: I32<LE>,

    #[doc(alias = "bg_textcolor")]
    background_text_color: I32<LE>,

    #[doc(alias = "lb_bg")]
    log_window_background_color: I32<LE>,

    #[doc(alias = "lb_fg")]
    log_window_foreground_color: I32<LE>,

    #[doc(alias = "langtable_size")]
    language_table_size: I32<LE>,

    #[doc(alias = "license_bg")]
    license_background_color: I32<LE>,

    #[doc(alias = "code_onInit")]
    code_on_init: I32<LE>,

    #[doc(alias = "code_onInstSuccess")]
    code_on_inst_success: I32<LE>,

    #[doc(alias = "code_onInstFailed")]
    code_on_inst_failed: I32<LE>,

    #[doc(alias = "code_onUserAbort")]
    code_on_user_abort: I32<LE>,

    #[doc(alias = "code_onGUIInit")]
    code_on_gui_init: I32<LE>,

    #[doc(alias = "code_onGUIEnd")]
    code_on_gui_end: I32<LE>,

    #[doc(alias = "code_onMouseOverSection")]
    code_on_mouse_over_section: I32<LE>,

    #[doc(alias = "code_onVerifyInstDir")]
    code_on_verify_install_dir: I32<LE>,

    #[doc(alias = "code_onSelChange")]
    code_on_sel_change: I32<LE>,

    #[doc(alias = "code_onRebootFailed")]
    code_on_reboot_failed: I32<LE>,

    install_types: [I32<LE>; NSIS_MAX_INST_TYPES as usize + 1],

    install_directory_ptr: I32<LE>,

    install_directory_auto_append: I32<LE>,

    str_uninstall_child: I32<LE>,

    str_uninstall_command: I32<LE>,

    /// Points to the path of `wininit.ini`.
    str_win_init: I32<LE>,
}

pub struct Decompressed<R: Read + Seek> {
    pub data: Vec<u8>,
    pub is_solid: bool,
    pub non_solid_start_offset: u64,
    pub record_width: usize,
    pub compression: Compression,
    pub decoder: Decoder<R>,
}

fn is_lzma(data: &[u8]) -> Option<Compression> {
    fn is_lzma_header(data: &[u8]) -> bool {
        data.get(0..3) == Some([0x5D, 0, 0].as_slice())
            && data.get(5) == Some(&0)
            && data.get(6).is_some_and(|byte| byte & (1 << 7) == 0)
    }

    if is_lzma_header(data) {
        Some(Compression::Lzma(false))
    } else if data.first() <= Some(&1) && is_lzma_header(&data[1..]) {
        Some(Compression::Lzma(true))
    } else {
        None
    }
}

fn is_bzip2(data: &[u8]) -> bool {
    const BZIP2_MAGIC: u8 = 0x31;

    data.first() == Some(&BZIP2_MAGIC) && data.get(1) < Some(&14)
}

const HEADER_SIGNATURE_SIZE: usize = 16;

impl Header {
    pub fn read_from(data: &[u8], is_64_bit: bool) -> Result<Self, NsisError> {
        Self::read_layout(data, is_64_bit, false)
    }

    pub fn read_indexed(data: &[u8]) -> Result<Self, NsisError> {
        let header = Self::read_layout(data, false, true)?;
        if header.blocks[BlockType::Pages].offset() != 308 {
            return Err(io::Error::from(io::ErrorKind::InvalidData).into());
        }
        header.blocks.indexed_entries(data)?;
        Ok(header)
    }

    fn read_layout(data: &[u8], is_64_bit: bool, indexed: bool) -> Result<Self, NsisError> {
        let (common_header_flags, rest) = CommonHeaderFlags::read_from_prefix(data)?;

        let (blocks, mut rest) = BlockHeaders::read_dynamic_from_prefix(rest, is_64_bit)?;
        let indexed_files = if indexed {
            let offset = rest.read_t::<zerocopy::U32<LE>>()?.get();
            let count = rest.read_t::<zerocopy::U32<LE>>()?.get();
            Some(indexed::file_records(data, offset, count)?)
        } else {
            None
        };

        Ok(Self {
            indexed_files,
            common_header_flags,
            blocks,
            install_registry_root_key: rest.read_t()?,
            install_registry_key_ptr: rest.read_t()?,
            install_registry_value_ptr: rest.read_t()?,
            background_color_1: rest.read_t()?,
            background_color_2: rest.read_t()?,
            background_text_color: rest.read_t()?,
            log_window_background_color: rest.read_t()?,
            log_window_foreground_color: rest.read_t()?,
            language_table_size: rest.read_t()?,
            license_background_color: rest.read_t()?,
            code_on_init: rest.read_t()?,
            code_on_inst_success: rest.read_t()?,
            code_on_inst_failed: rest.read_t()?,
            code_on_user_abort: rest.read_t()?,
            code_on_gui_init: rest.read_t()?,
            code_on_gui_end: rest.read_t()?,
            code_on_mouse_over_section: rest.read_t()?,
            code_on_verify_install_dir: rest.read_t()?,
            code_on_sel_change: rest.read_t()?,
            code_on_reboot_failed: if blocks[BlockType::Pages].offset() == 276 {
                // NSIS v2 does not have `code_on_reboot_failed`
                I32::ZERO
            } else {
                rest.read_t()?
            },
            install_types: rest.read_t()?,
            install_directory_ptr: rest.read_t()?,
            install_directory_auto_append: rest.read_t()?,
            str_uninstall_child: rest.read_t()?,
            str_uninstall_command: rest.read_t()?,
            str_win_init: rest.read_t()?,
        })
    }

    /// <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L5753>
    pub fn decompress<R: Read + Seek>(
        mut reader: R,
        first_header: &FirstHeader,
    ) -> io::Result<Decompressed<R>> {
        /*
          XX XX XX XX             XX XX XX XX == FirstHeader.HeaderSize, nonsolid, uncompressed
          5D 00 00 dd dd 00       solid LZMA
          00 5D 00 00 dd dd 00    solid LZMA, empty filter (there are no such archives)
          01 5D 00 00 dd dd 00    solid LZMA, BCJ filter   (only 7-Zip installer used that format)

          SS SS SS 80 00 5D 00 00 dd dd 00     non-solid LZMA, empty filter
          SS SS SS 80 01 5D 00 00 dd dd 00     non-solid LZMA, BCJ filter
          SS SS SS 80 01 tt         non-solid BZip (tt < 14)
          SS SS SS 80               non-solid Deflate

          01 tt         solid BZip (tt < 14)
          other         solid Deflate
        */

        // Read the signature
        let mut signature = [0; HEADER_SIGNATURE_SIZE];
        reader.read_exact(&mut signature)?;

        // Older BI installers use four-byte record sizes, newer BI installers eight.
        let mut record_width = if first_header.is_nsisbi() { 8 } else { 4 };
        if signature[3] == 0x80 {
            record_width = 4;
        }
        let prefix = |width: usize| {
            if width == 8 {
                u64::from_le_bytes(signature[..8].try_into().unwrap())
            } else {
                u64::from(u32::from_le_bytes(signature[..4].try_into().unwrap()))
            }
        };
        if prefix(4) == u64::from(first_header.length_of_header()) && prefix(8) != prefix(4) {
            record_width = 4;
        }
        let mut compressed_header_size = prefix(record_width);
        let mask = 1u64 << (record_width * 8 - 1);
        let mut is_solid = true;
        let detect = |bytes: &[u8]| {
            if first_header.is_nsisbi() && bytes.get(3) == Some(&0x5d) {
                Some(Compression::ThreadedLzma)
            } else {
                is_lzma(bytes).or_else(|| is_bzip2(bytes).then_some(Compression::BZip2))
            }
        };
        let mut compression =
            if compressed_header_size == u64::from(first_header.length_of_header()) {
                is_solid = false;
                Compression::None
            } else if let Some(compression) = detect(&signature) {
                compression
            } else if signature[record_width - 1] == 0x80 {
                is_solid = false;
                detect(&signature[record_width..]).unwrap_or(Compression::Zlib)
            } else {
                Compression::Zlib
            };
        let rewind = if is_solid {
            HEADER_SIGNATURE_SIZE
        } else {
            HEADER_SIGNATURE_SIZE - record_width
        };
        reader.seek_relative(-(rewind as i64))?;
        if !is_solid {
            compressed_header_size &= !mask;
            if compression == Compression::Zlib
                && lzma2::probe(
                    &mut reader,
                    compressed_header_size,
                    u64::from(first_header.length_of_header()),
                )?
            {
                compression = Compression::Lzma2;
            }
        }

        debug!(?compression, is_solid, compressed_header_size);

        let expected_size = first_header.length_of_header() as usize;
        let mut decoder = match compression {
            Compression::Lzma(filter_flag) => {
                if filter_flag {
                    reader.seek_relative(1)?;
                }
                let header = reader.read_t::<LzmaStreamHeader>()?;
                Decoder::new_lzma1(reader, header)?
            }
            Compression::ThreadedLzma => Decoder::ThreadedLzma(threaded_lzma::Decoder::new(reader)),
            Compression::Lzma2 => Decoder::new_lzma2(reader)?,
            Compression::BZip2 => Decoder::NsisBZip2(nsis_bzip2::Decoder::new(
                reader,
                (!is_solid).then_some(compressed_header_size as usize),
                expected_size + if is_solid { record_width } else { 0 },
            )?),
            Compression::Zlib => Decoder::Zlib(nsis_deflate::Decoder::new(reader)),
            Compression::None => Decoder::None(reader),
        };

        if is_solid {
            let decompressed_header_size = if record_width == 8 {
                decoder.read_t::<zerocopy::U64<LE>>()?.get()
            } else {
                u64::from(decoder.read_u32::<LE>()?)
            };
            let expected_size = u64::from(first_header.length_of_header());
            if decompressed_header_size != expected_size {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Decompressed header size ({decompressed_header_size}) did not equal size defined in first header ({expected_size})",
                    ),
                ));
            }
        }

        let mut decompressed_data = vec![0; first_header.length_of_header() as usize];
        decoder.read_exact(&mut decompressed_data)?;

        Ok(Decompressed {
            data: decompressed_data,
            is_solid,
            non_solid_start_offset: compressed_header_size,
            record_width,
            compression,
            decoder,
        })
    }

    pub const fn blocks(&self) -> &BlockHeaders {
        &self.blocks
    }

    pub fn indexed_files(&self) -> Option<&[indexed::FileRecord]> {
        self.indexed_files.as_deref()
    }

    #[inline]
    pub const fn install_registry_root_key(&self) -> i32 {
        self.install_registry_root_key.get()
    }

    /// Returns the language table's size, or `None` if the size was negative.
    ///
    /// In NSIS v2, if a language table was not set, the default one is generated, but its defined
    /// length will be `-1`. In this case, this function returns `None`. The caller should fall back
    /// to the actual length of the language table data block.
    pub fn language_table_size(&self) -> Option<usize> {
        if self.language_table_size == I32::ZERO {
            None
        } else {
            usize::try_from(self.language_table_size.get()).ok()
        }
    }

    #[inline]
    pub fn install_directory(&self) -> Option<i32> {
        if self.install_directory_ptr == I32::ZERO {
            None
        } else {
            Some(self.install_directory_ptr.get())
        }
    }

    #[inline]
    pub const fn code_on_init(&self) -> i32 {
        self.code_on_init.get()
    }

    #[inline]
    pub const fn code_on_inst_success(&self) -> i32 {
        self.code_on_inst_success.get()
    }

    #[inline]
    pub const fn code_on_inst_failed(&self) -> i32 {
        self.code_on_inst_failed.get()
    }

    #[inline]
    pub const fn code_on_user_abort(&self) -> i32 {
        self.code_on_user_abort.get()
    }
}

#[expect(
    clippy::missing_fields_in_debug,
    reason = "Fields are used through function calls"
)]
impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("flags", &self.common_header_flags)
            .field("blocks", &self.blocks())
            .field("install_reg_rootkey", &self.install_registry_root_key())
            .field("install_reg_key_ptr", &self.install_registry_key_ptr.get())
            .field(
                "install_reg_value_ptr",
                &self.install_registry_value_ptr.get(),
            )
            .field("bg_color1", &self.background_color_1.get())
            .field("bg_color2", &self.background_color_2.get())
            .field("bg_textcolor1", &self.background_text_color.get())
            .field("lb_bg", &self.log_window_background_color.get())
            .field("lb_fg", &self.log_window_foreground_color.get())
            .field("langtable_size", &self.language_table_size.get())
            .field("license_bg", &self.license_background_color.get())
            .field("code_onInit", &self.code_on_init())
            .field("code_onInstSuccess", &self.code_on_inst_success())
            .field("code_onInstFailed", &self.code_on_inst_failed())
            .field("code_onUserAbort", &self.code_on_user_abort())
            .field("code_onGUIInit", &self.code_on_gui_init.get())
            .field("code_onGUIEnd", &self.code_on_gui_end.get())
            .field(
                "code_onMouseOverSection",
                &self.code_on_mouse_over_section.get(),
            )
            .field(
                "code_onVerifyInstDir",
                &self.code_on_verify_install_dir.get(),
            )
            .field("code_onSelChange", &self.code_on_sel_change.get())
            .field("code_onRebootFailed", &self.code_on_reboot_failed.get())
            .field("install_types", &self.install_types.map(I32::get))
            .field("install_directory_ptr", &self.install_directory_ptr.get())
            .field(
                "install_directory_auto_append",
                &self.install_directory_auto_append.get(),
            )
            .field("str_uninstchild", &self.str_uninstall_child.get())
            .field("str_uninstcmd", &self.str_uninstall_command.get())
            .field("str_wininit", &self.str_win_init.get())
            .finish()
    }
}
