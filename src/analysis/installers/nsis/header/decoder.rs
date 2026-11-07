use std::io::{Read, Result, Seek};

use lzma_rust2::{Lzma2Reader, LzmaReader};

use super::{LzmaStreamHeader, nsis_bzip2, nsis_deflate, threaded_lzma};

pub enum Decoder<R: Read + Seek> {
    Lzma(Box<LzmaReader<R>>),
    Lzma2(Box<Lzma2Reader<R>>),
    ThreadedLzma(threaded_lzma::Decoder<R>),
    NsisBZip2(nsis_bzip2::Decoder<R>),
    Zlib(nsis_deflate::Decoder<R>),
    None(R),
}

impl<R: Read + Seek> Decoder<R> {
    pub fn new_lzma2(mut reader: R) -> lzma_rust2::Result<Self> {
        let mut property = [0];
        reader.read_exact(&mut property)?;
        let dictionary = super::lzma2::dictionary_size(property[0])?;
        Lzma2Reader::new_mem_limit(reader, dictionary, 512 * 1024, None)
            .map(|decoder| Self::Lzma2(Box::new(decoder)))
    }

    /// Creates a new LZMA1 decoder from a reader and an [`LzmaStreamHeader`].
    pub fn new_lzma1(reader: R, header: LzmaStreamHeader) -> lzma_rust2::Result<Self> {
        LzmaReader::new_with_props(
            reader,
            u64::MAX,
            header.props(),
            header.dictionary_size(),
            None,
        )
        .map(|reader| Self::Lzma(Box::new(reader)))
    }
}

impl<R: Read + Seek> Decoder<R> {
    pub fn into_inner(self) -> R {
        match self {
            Self::Lzma(reader) => reader.into_inner(),
            Self::Lzma2(reader) => reader.into_inner(),
            Self::ThreadedLzma(reader) => reader.into_inner(),
            Self::NsisBZip2(reader) => reader.into_inner(),
            Self::Zlib(reader) => reader.into_inner(),
            Self::None(reader) => reader,
        }
    }
}

impl<R: Read + Seek> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Lzma(reader) => reader.read(buf),
            Self::Lzma2(reader) => reader.read(buf),
            Self::ThreadedLzma(reader) => reader.read(buf),
            Self::NsisBZip2(reader) => reader.read(buf),
            Self::Zlib(reader) => reader.read(buf),
            Self::None(reader) => reader.read(buf),
        }
    }
}
