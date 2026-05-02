/*
 * Adapted from https://github.com/BinFlip/nsis-rs/blob/main/src/decompress/bzip2.rs
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *      Copyright 2025 Johann Kempter
 *
 *      Licensed under the Apache License, Version 2.0 (the "License");
 *      you may not use this file except in compliance with the License.
 *      You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the License is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the License for the specific language governing permissions and
 *      limitations under the License.
 */

use std::io::{Cursor, Error, ErrorKind, Read, Result};

const BZ_MAX_ALPHA_SIZE: usize = 258;
const BZ_MAX_ALPHA_SIZE_I32: i32 = 258;
const BZ_MAX_CODE_LEN: usize = 23;
const BZ_N_GROUPS: usize = 6;
const BZ_G_SIZE_I32: i32 = 50;
const BZ_MAX_SELECTORS_I32: i32 = 18_002;
const MTFA_SIZE: usize = 4096;
const MTFL_SIZE: usize = 16;
const BLOCK_SIZE: usize = 900_000;
const BLOCK_SIZE_I32: i32 = 900_000;
const BZ_RUNA: i32 = 0;
const BZ_RUNB: i32 = 1;

pub struct Decoder<R> {
    inner: R,
    decompressed: Cursor<Vec<u8>>,
}

impl<R: Read> Decoder<R> {
    pub fn new(mut reader: R, compressed_size: Option<usize>, max_output: usize) -> Result<Self> {
        let compressed = if let Some(compressed_size) = compressed_size {
            let mut compressed = vec![0; compressed_size];
            reader.read_exact(&mut compressed)?;
            compressed
        } else {
            let mut compressed = Vec::new();
            reader.read_to_end(&mut compressed)?;
            compressed
        };

        Ok(Self {
            inner: reader,
            decompressed: Cursor::new(decompress(&compressed, max_output)?),
        })
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.decompressed.read(buf)
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    position: usize,
    buffer: u32,
    live: i32,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            buffer: 0,
            live: 0,
        }
    }

    fn get_bits(&mut self, count: i32) -> Result<i32> {
        loop {
            if self.live >= count {
                let value = (self.buffer >> (self.live - count)) & ((1 << count) - 1);
                self.live -= count;
                return i32::try_from(value)
                    .map_err(|_| invalid_data("NSIS bzip2 bit value out of range"));
            }

            let byte = self
                .data
                .get(self.position)
                .ok_or_else(|| invalid_data("Unexpected end of NSIS bzip2 input"))?;
            self.buffer = (self.buffer << 8) | u32::from(*byte);
            self.live += 8;
            self.position += 1;
        }
    }

    #[inline]
    fn get_bit(&mut self) -> Result<i32> {
        self.get_bits(1)
    }

    #[inline]
    fn get_u8(&mut self) -> Result<i32> {
        self.get_bits(8)
    }
}

struct HuffmanTables {
    selector: Vec<u8>,
    min_lens: [i32; BZ_N_GROUPS],
    limit: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    perm: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    base: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    n_selectors: i32,
    group_no: i32,
    group_pos: i32,
}

pub fn decompress(compressed: &[u8], max_output: usize) -> Result<Vec<u8>> {
    if compressed.is_empty() {
        return Err(invalid_data("Empty NSIS bzip2 input"));
    }

    let mut reader = BitReader::new(compressed);
    let mut output = Vec::with_capacity(max_output.min(BLOCK_SIZE));

    loop {
        match reader.get_u8()? {
            0x17 => break,
            0x31 => decompress_block(&mut reader, &mut output, max_output)?,
            header => {
                return Err(invalid_data(format!(
                    "Invalid NSIS bzip2 block header 0x{header:02X}",
                )));
            }
        }

        if output.len() >= max_output {
            output.truncate(max_output);
            break;
        }
    }

    Ok(output)
}

#[allow(clippy::too_many_lines)]
fn decompress_block(
    reader: &mut BitReader<'_>,
    output: &mut Vec<u8>,
    max_output: usize,
) -> Result<()> {
    let b0 = reader.get_u8()?;
    let b1 = reader.get_u8()?;
    let b2 = reader.get_u8()?;
    let orig_ptr = (b0 << 16) | (b1 << 8) | b2;

    if !(0..=10 + BLOCK_SIZE_I32).contains(&orig_ptr) {
        return Err(invalid_data(format!(
            "NSIS bzip2 origPtr out of range: {orig_ptr}",
        )));
    }

    let mut in_use16 = [false; 16];
    for item in &mut in_use16 {
        *item = reader.get_bit()? == 1;
    }

    let mut in_use = [false; 256];
    for (i, group_used) in in_use16.into_iter().enumerate() {
        if group_used {
            for j in 0..16 {
                in_use[i * 16 + j] = reader.get_bit()? == 1;
            }
        }
    }
    let mut seq_to_unseq = [0; 256];
    let mut n_in_use = 0;
    for (symbol, used) in in_use.into_iter().enumerate() {
        if used {
            seq_to_unseq[n_in_use] =
                u8::try_from(symbol).map_err(|_| invalid_data("NSIS bzip2 symbol out of range"))?;
            n_in_use += 1;
        }
    }
    if n_in_use == 0 {
        return Err(invalid_data("NSIS bzip2 block has no symbols in use"));
    }

    let alpha_size = n_in_use + 2;
    let n_groups = reader.get_bits(3)?;
    if !(2..=6).contains(&n_groups) {
        return Err(invalid_data(format!(
            "NSIS bzip2 nGroups out of range: {n_groups}",
        )));
    }
    let n_groups =
        usize::try_from(n_groups).map_err(|_| invalid_data("NSIS bzip2 nGroups out of range"))?;

    let n_selectors = reader.get_bits(15)?;
    if !(1..=BZ_MAX_SELECTORS_I32).contains(&n_selectors) {
        return Err(invalid_data(format!(
            "NSIS bzip2 nSelectors out of range: {n_selectors}",
        )));
    }
    let n_selectors = usize::try_from(n_selectors)
        .map_err(|_| invalid_data("NSIS bzip2 nSelectors out of range"))?;

    let mut selector_mtf = vec![0; n_selectors];
    for selector in &mut selector_mtf {
        let mut value = 0;
        loop {
            if reader.get_bit()? == 0 {
                break;
            }
            value += 1;
            if value >= n_groups {
                return Err(invalid_data("NSIS bzip2 selector MTF value out of range"));
            }
        }
        *selector =
            u8::try_from(value).map_err(|_| invalid_data("NSIS bzip2 selector out of range"))?;
    }

    let mut selector = vec![0; n_selectors];
    let mut positions = [0; BZ_N_GROUPS];
    for (value, position) in positions.iter_mut().enumerate().take(n_groups) {
        *position = u8::try_from(value)
            .map_err(|_| invalid_data("NSIS bzip2 selector position out of range"))?;
    }
    for (i, selector_mtf) in selector_mtf.into_iter().enumerate() {
        let value = selector_mtf as usize;
        let selected = positions[value];
        for index in (1..=value).rev() {
            positions[index] = positions[index - 1];
        }
        positions[0] = selected;
        selector[i] = selected;
    }

    let mut lengths = [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS];
    for table in lengths.iter_mut().take(n_groups) {
        let mut current = reader.get_bits(5)?;
        for slot in table.iter_mut().take(alpha_size) {
            loop {
                if !(1..=20).contains(&current) {
                    return Err(invalid_data(format!(
                        "NSIS bzip2 code length out of range: {current}",
                    )));
                }
                if reader.get_bit()? == 0 {
                    break;
                }
                if reader.get_bit()? == 0 {
                    current += 1;
                } else {
                    current -= 1;
                }
            }
            *slot = u8::try_from(current)
                .map_err(|_| invalid_data("NSIS bzip2 code length out of range"))?;
        }
    }

    let mut huffman = HuffmanTables {
        selector,
        min_lens: [0; BZ_N_GROUPS],
        limit: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
        perm: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
        base: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
        n_selectors: i32::try_from(n_selectors)
            .map_err(|_| invalid_data("NSIS bzip2 nSelectors out of range"))?,
        group_no: -1,
        group_pos: 0,
    };

    for (table_index, table_lengths) in lengths.iter().enumerate().take(n_groups) {
        let mut min_len = 32;
        let mut max_len = 0;
        for &length in table_lengths.iter().take(alpha_size) {
            let length = i32::from(length);
            min_len = min_len.min(length);
            max_len = max_len.max(length);
        }
        create_decode_tables(
            &mut huffman.limit[table_index],
            &mut huffman.base[table_index],
            &mut huffman.perm[table_index],
            table_lengths,
            min_len,
            max_len,
            alpha_size,
        );
        huffman.min_lens[table_index] = min_len;
    }

    let eob = i32::try_from(n_in_use + 1)
        .map_err(|_| invalid_data("NSIS bzip2 EOB symbol out of range"))?;
    let mut unzftab = [0; 256];
    let mut mtfa = [0; MTFA_SIZE];
    let mut mtfbase = [0; 256 / MTFL_SIZE];

    let mut kk = MTFA_SIZE - 1;
    for ii in (0..(256 / MTFL_SIZE)).rev() {
        for jj in (0..MTFL_SIZE).rev() {
            mtfa[kk] = u8::try_from(ii * MTFL_SIZE + jj)
                .map_err(|_| invalid_data("NSIS bzip2 MTF value out of range"))?;
            kk = kk.wrapping_sub(1);
        }
        mtfbase[ii] = kk.wrapping_add(1);
    }

    let mut tt = vec![0; BLOCK_SIZE];
    let mut nblock = 0;
    let mut next_sym = get_mtf_val(reader, &mut huffman)?;

    loop {
        if next_sym == eob {
            break;
        }

        if next_sym == BZ_RUNA || next_sym == BZ_RUNB {
            let mut es = -1;
            let mut power = 1;
            while next_sym == BZ_RUNA || next_sym == BZ_RUNB {
                if next_sym == BZ_RUNA {
                    es += power;
                }
                power <<= 1;
                if next_sym == BZ_RUNB {
                    es += power;
                }
                next_sym = get_mtf_val(reader, &mut huffman)?;
            }

            es += 1;
            let symbol = seq_to_unseq[mtfa[mtfbase[0]] as usize];
            unzftab[symbol as usize] += es;

            let es = usize::try_from(es)
                .map_err(|_| invalid_data("NSIS bzip2 run length out of range"))?;
            if nblock + es > BLOCK_SIZE {
                return Err(invalid_data("NSIS bzip2 block overflow during RLE"));
            }
            for _ in 0..es {
                tt[nblock] = u32::from(symbol);
                nblock += 1;
            }
            continue;
        }

        if nblock >= BLOCK_SIZE {
            return Err(invalid_data("NSIS bzip2 block overflow"));
        }

        let symbol = mtf_decode(next_sym, &mut mtfa, &mut mtfbase);
        let unseq = seq_to_unseq[symbol as usize];
        unzftab[unseq as usize] += 1;
        tt[nblock] = u32::from(unseq);
        nblock += 1;
        next_sym = get_mtf_val(reader, &mut huffman)?;
    }

    let orig_ptr =
        usize::try_from(orig_ptr).map_err(|_| invalid_data("NSIS bzip2 origPtr out of range"))?;
    if orig_ptr >= nblock {
        return Err(invalid_data(format!(
            "NSIS bzip2 origPtr {orig_ptr} out of range for nblock {nblock}",
        )));
    }

    let mut cftab = [0; 257];
    for i in 1..=256 {
        cftab[i] = unzftab[i - 1] + cftab[i - 1];
    }
    if cftab[256]
        != i32::try_from(nblock).map_err(|_| invalid_data("NSIS bzip2 block is too large"))?
    {
        return Err(invalid_data("NSIS bzip2 cftab consistency check failed"));
    }

    for i in 0..nblock {
        let symbol = (tt[i] & 0xff) as usize;
        let destination = usize::try_from(cftab[symbol])
            .map_err(|_| invalid_data("NSIS bzip2 cftab index out of range"))?;
        tt[destination] |=
            u32::try_from(i).map_err(|_| invalid_data("NSIS bzip2 block index out of range"))? << 8;
        cftab[symbol] += 1;
    }

    decode_bwt_output(&tt, orig_ptr, nblock, output, max_output)
}

fn create_decode_tables(
    limit: &mut [i32],
    base: &mut [i32],
    perm: &mut [i32],
    length: &[u8],
    min_len: i32,
    max_len: i32,
    alpha_size: usize,
) {
    let mut pp = 0;
    for i in min_len..=max_len {
        for (j, &len_j) in length.iter().enumerate().take(alpha_size) {
            if i32::from(len_j) == i {
                perm[pp] = i32::try_from(j).expect("NSIS bzip2 alpha size fits in i32");
                pp += 1;
            }
        }
    }

    base.iter_mut()
        .take(BZ_MAX_CODE_LEN)
        .for_each(|item| *item = 0);
    for &len_j in length.iter().take(alpha_size) {
        let index = len_j as usize + 1;
        if index < BZ_MAX_CODE_LEN {
            base[index] += 1;
        }
    }
    for i in 1..BZ_MAX_CODE_LEN {
        base[i] += base[i - 1];
    }

    limit
        .iter_mut()
        .take(BZ_MAX_CODE_LEN)
        .for_each(|item| *item = 0);
    let mut value = 0;
    for i in min_len..=max_len {
        let index = usize::try_from(i).expect("NSIS bzip2 code length is positive");
        value += base[index + 1] - base[index];
        limit[index] = value - 1;
        value <<= 1;
    }
    for i in (min_len + 1)..=max_len {
        let index = usize::try_from(i).expect("NSIS bzip2 code length is positive");
        base[index] = ((limit[index - 1] + 1) << 1) - base[index];
    }
}

fn get_mtf_val(reader: &mut BitReader<'_>, huffman: &mut HuffmanTables) -> Result<i32> {
    if huffman.group_pos == 0 {
        huffman.group_no += 1;
        if huffman.group_no >= huffman.n_selectors {
            return Err(invalid_data("NSIS bzip2 ran out of selectors"));
        }
        huffman.group_pos = BZ_G_SIZE_I32;
    }
    huffman.group_pos -= 1;

    let group_no = usize::try_from(huffman.group_no)
        .map_err(|_| invalid_data("NSIS bzip2 group index out of range"))?;
    let selected = usize::from(huffman.selector[group_no]);
    let mut zn = huffman.min_lens[selected];
    let mut zvec = reader.get_bits(zn)?;

    loop {
        if zn > 20 {
            return Err(invalid_data("NSIS bzip2 Huffman code length exceeds 20"));
        }
        let zn_index =
            usize::try_from(zn).map_err(|_| invalid_data("NSIS bzip2 code length out of range"))?;
        if zvec <= huffman.limit[selected][zn_index] {
            break;
        }
        zn += 1;
        zvec = (zvec << 1) | reader.get_bit()?;
    }

    let zn_index =
        usize::try_from(zn).map_err(|_| invalid_data("NSIS bzip2 code length out of range"))?;
    let index = zvec - huffman.base[selected][zn_index];
    if !(0..BZ_MAX_ALPHA_SIZE_I32).contains(&index) {
        return Err(invalid_data("NSIS bzip2 Huffman index out of range"));
    }
    Ok(huffman.perm[selected][usize::try_from(index)
        .map_err(|_| invalid_data("NSIS bzip2 Huffman index out of range"))?])
}

fn mtf_decode(
    next_sym: i32,
    mtfa: &mut [u8; MTFA_SIZE],
    mtfbase: &mut [usize; 256 / MTFL_SIZE],
) -> u8 {
    let nn = usize::try_from(next_sym - 1).expect("NSIS bzip2 MTF symbol is positive");

    if nn < MTFL_SIZE {
        let position = mtfbase[0];
        let symbol = mtfa[position + nn];
        for index in (1..=nn).rev() {
            mtfa[position + index] = mtfa[position + index - 1];
        }
        mtfa[position] = symbol;
        return symbol;
    }

    let list = nn / MTFL_SIZE;
    let offset = nn % MTFL_SIZE;
    let mut position = mtfbase[list] + offset;
    let symbol = mtfa[position];

    while position > mtfbase[list] {
        mtfa[position] = mtfa[position - 1];
        position -= 1;
    }
    mtfbase[list] += 1;

    for current_list in (1..=list).rev() {
        mtfbase[current_list] -= 1;
        mtfa[mtfbase[current_list]] = mtfa[mtfbase[current_list - 1] + MTFL_SIZE - 1];
    }
    mtfbase[0] -= 1;
    mtfa[mtfbase[0]] = symbol;

    if mtfbase[0] == 0 {
        let mut kk = MTFA_SIZE - 1;
        for ii in (0..(256 / MTFL_SIZE)).rev() {
            for jj in (0..MTFL_SIZE).rev() {
                mtfa[kk] = mtfa[mtfbase[ii] + jj];
                kk = kk.wrapping_sub(1);
            }
            mtfbase[ii] = kk.wrapping_add(1);
        }
    }

    symbol
}

fn decode_bwt_output(
    tt: &[u32],
    orig_ptr: usize,
    nblock: usize,
    output: &mut Vec<u8>,
    max_output: usize,
) -> Result<()> {
    let mut t_pos = tt[orig_ptr] >> 8;
    let mut nblock_used = 0;
    let mut k0 = bz_get_fast(tt, &mut t_pos)?;
    nblock_used += 1;

    let mut state_out_len = 0;
    let mut state_out_ch = 0;

    while nblock_used <= nblock {
        if output.len() >= max_output {
            return Ok(());
        }

        if state_out_len > 0 {
            let emit_count = usize::try_from(state_out_len)
                .map_err(|_| invalid_data("NSIS bzip2 output run length out of range"))?
                .min(max_output - output.len());
            output.extend(std::iter::repeat_n(state_out_ch, emit_count));
            state_out_len -= i32::try_from(emit_count)
                .map_err(|_| invalid_data("NSIS bzip2 output run length out of range"))?;
            if state_out_len > 0 || output.len() >= max_output {
                return Ok(());
            }
            continue;
        }

        state_out_ch = k0;
        let mut count = 1_usize;

        if nblock_used < nblock {
            k0 = bz_get_fast(tt, &mut t_pos)?;
            nblock_used += 1;
            if k0 != state_out_ch {
                output.push(state_out_ch);
                continue;
            }
            count = 2;

            if nblock_used < nblock {
                k0 = bz_get_fast(tt, &mut t_pos)?;
                nblock_used += 1;
                if k0 != state_out_ch {
                    push_repeat(output, state_out_ch, 2, max_output);
                    continue;
                }
                count = 3;

                if nblock_used < nblock {
                    k0 = bz_get_fast(tt, &mut t_pos)?;
                    nblock_used += 1;
                    if k0 != state_out_ch {
                        push_repeat(output, state_out_ch, 3, max_output);
                        continue;
                    }
                    count = 4;

                    if nblock_used < nblock {
                        k0 = bz_get_fast(tt, &mut t_pos)?;
                        nblock_used += 1;
                        state_out_len = i32::from(k0)
                            + i32::try_from(count)
                                .expect("NSIS bzip2 literal repeat count fits in i32");
                        if nblock_used < nblock {
                            k0 = bz_get_fast(tt, &mut t_pos)?;
                            nblock_used += 1;
                        }
                        continue;
                    }
                }
            }
        }

        push_repeat(output, state_out_ch, count, max_output);
    }

    if state_out_len > 0 {
        let emit_count = usize::try_from(state_out_len)
            .map_err(|_| invalid_data("NSIS bzip2 output run length out of range"))?
            .min(max_output - output.len());
        output.extend(std::iter::repeat_n(state_out_ch, emit_count));
    }

    Ok(())
}

fn bz_get_fast(tt: &[u32], t_pos: &mut u32) -> Result<u8> {
    let entry = *tt
        .get(*t_pos as usize)
        .ok_or_else(|| invalid_data("NSIS bzip2 BWT position out of range"))?;
    *t_pos = entry >> 8;
    Ok((entry & 0xff) as u8)
}

fn push_repeat(output: &mut Vec<u8>, byte: u8, count: usize, max_output: usize) {
    let count = count.min(max_output.saturating_sub(output.len()));
    output.extend(std::iter::repeat_n(byte, count));
}

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}
