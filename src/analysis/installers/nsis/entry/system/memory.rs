use std::collections::BTreeMap;

use crate::analysis::installers::nsis::codepage;

const LIMIT: usize = 64 * 1024 * 1024;
const BLOCK_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
struct Block {
    bytes: Vec<u8>,
    known: bool,
    read_only: bool,
}

#[derive(Clone, Debug)]
pub struct Memory {
    blocks: BTreeMap<u64, Block>,
    next: u64,
    used: usize,
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            blocks: BTreeMap::new(),
            next: 0x10000,
            used: 0,
        }
    }
}

impl Memory {
    pub fn alloc(&mut self, size: usize) -> Option<u64> {
        if size == 0 {
            return Some(0);
        }
        if size > BLOCK_LIMIT || self.used.checked_add(size)? > LIMIT || self.blocks.len() >= 16384
        {
            return None;
        }
        let address = self.next;
        self.next = self
            .next
            .checked_add((size.max(16).checked_add(15)? & !15) as u64)?;
        if self.next >= 0x4000_0000 {
            return None;
        }
        self.blocks.insert(
            address,
            Block {
                bytes: vec![0; size],
                known: true,
                read_only: false,
            },
        );
        self.used += size;
        Some(address)
    }

    pub fn free(&mut self, address: u64) -> bool {
        if address == 0 {
            return true;
        }
        if self.blocks.get(&address).is_some_and(|b| b.read_only) {
            return false;
        }
        if let Some(block) = self.blocks.remove(&address) {
            self.used -= block.bytes.len();
            true
        } else {
            false
        }
    }

    pub fn size(&self, address: u64) -> Option<usize> {
        self.blocks.get(&address).map(|b| b.bytes.len())
    }

    pub fn available(&self, address: u64) -> Option<usize> {
        let (base, block) = self.blocks.range(..=address).next_back()?;
        block
            .bytes
            .len()
            .checked_sub(usize::try_from(address.checked_sub(*base)?).ok()?)
    }

    pub fn map_shared(&mut self, address: u64, bytes: Vec<u8>) {
        self.blocks.insert(
            address,
            Block {
                bytes,
                known: true,
                read_only: true,
            },
        );
    }

    pub fn invalidate(&mut self, address: u64) {
        if let Some((base, block)) = self.blocks.range_mut(..=address).next_back()
            && !block.read_only
            && address
                .checked_sub(*base)
                .is_some_and(|offset| offset < block.bytes.len() as u64)
        {
            block.known = false;
        }
    }

    pub fn read(&self, address: u64, size: usize) -> Option<&[u8]> {
        let (base, block) = self.blocks.range(..=address).next_back()?;
        if !block.known {
            return None;
        }
        let offset = usize::try_from(address.checked_sub(*base)?).ok()?;
        block.bytes.get(offset..offset.checked_add(size)?)
    }

    pub fn write(&mut self, address: u64, value: &[u8]) -> Option<()> {
        let (base, block) = self.blocks.range_mut(..=address).next_back()?;
        if block.read_only {
            return None;
        }
        let offset = usize::try_from(address.checked_sub(*base)?).ok()?;
        block
            .bytes
            .get_mut(offset..offset.checked_add(value.len())?)?
            .copy_from_slice(value);
        if offset == 0 && value.len() == block.bytes.len() {
            block.known = true;
        }
        Some(())
    }

    pub fn number(&self, address: u64, size: usize) -> Option<u64> {
        if size > 8 {
            return None;
        }
        let mut bytes = [0; 8];
        bytes[..size].copy_from_slice(self.read(address, size)?);
        Some(u64::from_le_bytes(bytes))
    }

    pub fn put_number(&mut self, address: u64, value: u64, size: usize) -> Option<()> {
        self.write(address, value.to_le_bytes().get(..size)?)
    }

    pub fn string(&self, address: u64, wide: bool) -> Option<String> {
        if address == 0 {
            return Some(String::new());
        }
        let (base, block) = self.blocks.range(..=address).next_back()?;
        if !block.known {
            return None;
        }
        let offset = usize::try_from(address.checked_sub(*base)?).ok()?;
        let bytes = block.bytes.get(offset..)?;
        if wide {
            let units: Vec<_> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .take(8192)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .take_while(|&c| c != 0)
                .collect();
            Some(String::from_utf16_lossy(&units))
        } else {
            let end = bytes
                .iter()
                .take(8192)
                .position(|&c| c == 0)
                .unwrap_or(bytes.len().min(8192));
            Some(codepage::decode(&bytes[..end]).into_owned())
        }
    }

    pub fn inline_string(&self, address: u64, wide: bool, count: usize) -> Option<String> {
        let width = if wide { 2 } else { 1 };
        let requested = count.checked_mul(width)?;
        let available = self.available(address)?;
        let bytes = self.read(address, requested.min(available))?;
        if wide {
            let units: Vec<_> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            let end = units.iter().position(|&v| v == 0);
            if end.is_none() && available < requested {
                return None;
            }
            Some(String::from_utf16_lossy(
                &units[..end.unwrap_or(units.len())],
            ))
        } else {
            let end = bytes.iter().position(|&v| v == 0);
            if end.is_none() && available < requested {
                return None;
            }
            Some(codepage::decode(&bytes[..end.unwrap_or(bytes.len())]).into_owned())
        }
    }

    pub fn encoded(value: &str, wide: bool) -> Vec<u8> {
        if wide {
            value
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .chain([0, 0])
                .collect()
        } else {
            let mut bytes = codepage::encode(value);
            bytes.push(0);
            bytes
        }
    }

    pub fn put_string(
        &mut self,
        address: u64,
        value: &str,
        wide: bool,
        capacity: usize,
    ) -> Option<usize> {
        if capacity == 0 || capacity > 8192 {
            return None;
        }
        let mut bytes = Self::encoded(value, wide);
        let width = if wide { 2 } else { 1 };
        bytes.truncate(capacity.checked_mul(width)?);
        if bytes.len() < width {
            return None;
        }
        let end = bytes.len() - width;
        bytes[end..].fill(0);
        self.write(address, &bytes)?;
        Some(end / width)
    }

    pub fn alloc_string(&mut self, value: &str, wide: bool, capacity: usize) -> Option<u64> {
        let width = if wide { 2 } else { 1 };
        let address = self.alloc(capacity.checked_mul(width)?)?;
        self.put_string(address, value, wide, capacity)?;
        Some(address)
    }

    pub fn copy(&mut self, destination: u64, source: u64, size: usize) -> Option<()> {
        let value = self.read(source, size)?.to_vec();
        self.write(destination, &value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_lifetimes_aliases_and_encoding_are_enforced() {
        let mut memory = Memory::default();
        let address = memory.alloc(24).unwrap();
        memory.put_number(address + 4, 0x12345678, 4).unwrap();
        assert_eq!(memory.number(address + 5, 2), Some(0x3456));
        assert!(memory.write(address + 23, &[1, 2]).is_none());
        assert!(memory.read(u64::MAX, 1).is_none());
        memory.put_string(address, "€🚀", true, 12).unwrap();
        assert_eq!(memory.string(address, true).as_deref(), Some("€🚀"));
        assert!(memory.free(address));
        assert!(memory.string(address, true).is_none());
        assert!(memory.alloc(usize::MAX).is_none());
    }
}
