#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Compression {
    Lzma(bool),
    Lzma2,
    BZip2,
    ThreadedLzma,
    Zlib,
    None,
}
