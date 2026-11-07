//! Raw DEFLATE streams used by NSIS.
//!
//! NSIS omits the one's-complement length field from stored blocks.

use std::io::{self, BufReader, Read};

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid NSIS DEFLATE stream")
}

struct Huffman {
    counts: [usize; 16],
    symbols: Vec<usize>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> io::Result<Self> {
        let mut counts = [0; 16];
        for &length in lengths {
            *counts.get_mut(usize::from(length)).ok_or_else(invalid)? += 1;
        }
        let mut left = 1isize;
        for &count in &counts[1..] {
            left = left * 2 - count as isize;
            if left < 0 {
                return Err(invalid());
            }
        }
        let mut symbols = Vec::new();
        for length in 1..16 {
            symbols.extend(
                lengths
                    .iter()
                    .enumerate()
                    .filter_map(|(symbol, &len)| (usize::from(len) == length).then_some(symbol)),
            );
        }
        Ok(Self { counts, symbols })
    }

    fn decode<R: Read>(&self, input: &mut Bits<R>) -> io::Result<usize> {
        let (mut code, mut first, mut index) = (0, 0, 0);
        for length in 1..16 {
            code = code * 2 + input.read(1)? as usize;
            let count = self.counts[length];
            if code >= first && code - first < count {
                return self
                    .symbols
                    .get(index + code - first)
                    .copied()
                    .ok_or_else(invalid);
            }
            index += count;
            first = (first + count) * 2;
        }
        Err(invalid())
    }
}

struct Bits<R> {
    inner: R,
    bits: u32,
    count: u32,
}

impl<R: Read> Bits<R> {
    fn read(&mut self, count: u32) -> io::Result<u32> {
        while self.count < count {
            let mut byte = [0];
            self.inner.read_exact(&mut byte)?;
            self.bits |= u32::from(byte[0]) << self.count;
            self.count += 8;
        }
        let result = self.bits & ((1 << count) - 1);
        self.bits >>= count;
        self.count -= count;
        Ok(result)
    }
}

enum Block {
    Header,
    Stored(usize),
    Codes(Huffman, Huffman),
    End,
}

pub struct Decoder<R> {
    input: Bits<BufReader<R>>,
    block: Block,
    final_block: bool,
    history: Box<[u8; 32768]>,
    produced: usize,
    copy: (usize, usize),
}

impl<R: Read> Decoder<R> {
    pub fn new(inner: R) -> Self {
        Self {
            input: Bits {
                inner: BufReader::new(inner),
                bits: 0,
                count: 0,
            },
            block: Block::Header,
            final_block: false,
            history: Box::new([0; 32768]),
            produced: 0,
            copy: (0, 0),
        }
    }

    pub fn into_inner(self) -> R {
        self.input.inner.into_inner()
    }

    fn tables(&mut self) -> io::Result<(Huffman, Huffman)> {
        let literals = self.input.read(5)? as usize + 257;
        let distances = self.input.read(5)? as usize + 1;
        let codes = self.input.read(4)? as usize + 4;
        if literals > 286 {
            return Err(invalid());
        }
        let order = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        let mut lengths = [0; 19];
        for &index in &order[..codes] {
            lengths[index] = self.input.read(3)? as u8;
        }
        let tree = Huffman::new(&lengths)?;
        let mut lengths = Vec::new();
        while lengths.len() < literals + distances {
            let symbol = tree.decode(&mut self.input)?;
            let (value, count) = match symbol {
                0..=15 => (symbol as u8, 1),
                16 => (
                    *lengths.last().ok_or_else(invalid)?,
                    self.input.read(2)? as usize + 3,
                ),
                17 => (0, self.input.read(3)? as usize + 3),
                18 => (0, self.input.read(7)? as usize + 11),
                _ => return Err(invalid()),
            };
            if lengths.len() + count > literals + distances {
                return Err(invalid());
            }
            lengths.resize(lengths.len() + count, value);
        }
        if lengths[256] == 0 {
            return Err(invalid());
        }
        Ok((
            Huffman::new(&lengths[..literals])?,
            Huffman::new(&lengths[literals..])?,
        ))
    }

    fn byte(&mut self) -> io::Result<Option<u8>> {
        const LENGTH: [usize; 29] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
            115, 131, 163, 195, 227, 258,
        ];
        const LENGTH_BITS: [u32; 29] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
        ];
        const DISTANCE: [usize; 30] = [
            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
            1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
        ];
        loop {
            if self.copy.0 != 0 {
                self.copy.0 -= 1;
                return Ok(Some(self.history[(self.produced - self.copy.1) % 32768]));
            }
            match &mut self.block {
                Block::End => return Ok(None),
                Block::Header => {
                    self.final_block = self.input.read(1)? != 0;
                    self.block = match self.input.read(2)? {
                        0 => {
                            self.input.bits = 0;
                            self.input.count = 0;
                            Block::Stored(self.input.read(16)? as usize)
                        }
                        1 => {
                            let mut lengths = [8; 288];
                            lengths[144..256].fill(9);
                            lengths[256..280].fill(7);
                            Block::Codes(Huffman::new(&lengths)?, Huffman::new(&[5; 32])?)
                        }
                        2 => {
                            let (lit, dist) = self.tables()?;
                            Block::Codes(lit, dist)
                        }
                        _ => return Err(invalid()),
                    };
                }
                Block::Stored(remaining) if *remaining != 0 => {
                    *remaining -= 1;
                    return Ok(Some(self.input.read(8)? as u8));
                }
                Block::Stored(_) => {
                    self.block = if self.final_block {
                        Block::End
                    } else {
                        Block::Header
                    }
                }
                Block::Codes(literals, distances) => match literals.decode(&mut self.input)? {
                    literal @ 0..=255 => return Ok(Some(literal as u8)),
                    256 => {
                        self.block = if self.final_block {
                            Block::End
                        } else {
                            Block::Header
                        }
                    }
                    symbol @ 257..=285 => {
                        let index = symbol - 257;
                        let length = LENGTH[index] + self.input.read(LENGTH_BITS[index])? as usize;
                        let distance = distances.decode(&mut self.input)?;
                        if distance >= DISTANCE.len() {
                            return Err(invalid());
                        }
                        let extra = if distance < 4 {
                            0
                        } else {
                            (distance as u32 / 2) - 1
                        };
                        let distance = DISTANCE[distance] + self.input.read(extra)? as usize;
                        if distance > self.produced || distance > 32768 {
                            return Err(invalid());
                        }
                        self.copy = (length, distance);
                    }
                    _ => return Err(invalid()),
                },
            }
        }
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut count = 0;
        while count < buf.len() {
            let Some(byte) = self.byte()? else {
                break;
            };
            self.history[self.produced % 32768] = byte;
            self.produced += 1;
            buf[count] = byte;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn nsis_stored_blocks_omit_complement_length() {
        let mut output = Vec::new();
        Decoder::new(&b"\x01\x05\x00hello"[..])
            .read_to_end(&mut output)
            .unwrap();
        assert_eq!(output, b"hello");
    }

    #[test]
    fn fixed_and_dynamic_huffman_blocks() {
        for input in [
            b"hello hello hello".to_vec(),
            (0..100000).map(|i| (i % 251) as u8).collect(),
        ] {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(&input).unwrap();
            let compressed = encoder.finish().unwrap();
            let mut output = Vec::new();
            Decoder::new(compressed.as_slice())
                .read_to_end(&mut output)
                .unwrap();
            assert_eq!(output, input);
        }
    }
}
