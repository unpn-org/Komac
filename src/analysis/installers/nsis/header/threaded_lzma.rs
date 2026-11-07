//! The NSISBI wrapper for multithreaded LZMA streams.
//!
//! Each record contains a 24-bit length followed by an independent raw LZMA stream with its
//! own properties and dictionary header.

use std::io::{self, Cursor, Read};

use lzma_rust2::LzmaReader;

pub struct Decoder<R> {
    inner: R,
    block: Cursor<Vec<u8>>,
    ended: bool,
}

impl<R: Read> Decoder<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            block: Cursor::new(Vec::new()),
            ended: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let count = self.block.read(buf)?;
            if count != 0 || self.ended {
                return Ok(count);
            }
            let mut length = [0; 3];
            if self.inner.read(&mut length[..1])? == 0 {
                self.ended = true;
                return Ok(0);
            }
            self.inner.read_exact(&mut length[1..])?;
            let length = u32::from_le_bytes([length[0], length[1], length[2], 0]) as usize;
            if length == 0 {
                self.ended = true;
                return Ok(0);
            }
            if length < 5 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut compressed = vec![0; length];
            self.inner.read_exact(&mut compressed)?;
            let dictionary = u32::from_le_bytes(compressed[1..5].try_into().unwrap());
            if dictionary > 64 * 1024 * 1024 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut decoder = LzmaReader::new_with_props(
                &compressed[5..],
                u64::MAX,
                compressed[0],
                dictionary,
                None,
            )?
            .take(64 * 1024 * 1024 + 1);
            let mut output = Vec::new();
            decoder.read_to_end(&mut output)?;
            if output.len() > 64 * 1024 * 1024 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.block = Cursor::new(output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_independent_lzma_blocks() {
        let compressed = [
            93, 0, 0, 16, 0, 0, 51, 26, 74, 172, 12, 121, 176, 51, 254, 255, 252, 102, 64, 0,
        ];
        let mut stream = Vec::new();
        for _ in 0..2 {
            stream.extend([compressed.len() as u8, 0, 0]);
            stream.extend(compressed);
        }
        stream.extend([0, 0, 0]);
        let mut out = Vec::new();
        Decoder::new(stream.as_slice())
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"firstfirst");
    }

    #[test]
    fn rejects_truncated_blocks() {
        assert!(
            Decoder::new(&b"\x0a\0\0short"[..])
                .read_to_end(&mut Vec::new())
                .is_err()
        );
        assert!(
            Decoder::new(&b"\x02\0\0xx"[..])
                .read_to_end(&mut Vec::new())
                .is_err()
        );
    }
}
