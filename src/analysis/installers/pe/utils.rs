use std::{io, io::Read, mem::offset_of};

use zerocopy::LE;

use super::DosHeader;
use crate::read::ReadBytesExt;

/// Reads a PE machine value, validating both signatures before trusting its offsets.
pub fn machine_from_exe_reader<R: Read>(mut reader: R) -> io::Result<u16> {
    const PE_POINTER_OFFSET: u64 = offset_of!(DosHeader, pe_pointer) as u64;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Invalid PE header");
    let mut magic = [0; 2];
    reader.read_exact(&mut magic)?;
    if &magic != b"MZ" {
        return Err(invalid());
    }
    let skip = PE_POINTER_OFFSET - magic.len() as u64;
    if io::copy(&mut reader.by_ref().take(skip), &mut io::sink())? != skip {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let coff_offset = u64::from(reader.read_u32::<LE>()?);
    let skip = coff_offset
        .checked_sub(PE_POINTER_OFFSET + 4)
        .ok_or_else(invalid)?;
    if io::copy(&mut reader.by_ref().take(skip), &mut io::sink())? != skip {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut signature = [0; 4];
    reader.read_exact(&mut signature)?;
    if &signature != b"PE\0\0" {
        return Err(invalid());
    }
    reader.read_u16::<LE>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_embedded_executables() {
        let mut data = vec![0; 134];
        data[..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        data[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        assert_eq!(machine_from_exe_reader(data.as_slice()).unwrap(), 0x8664);
        data[128] = 0;
        assert!(machine_from_exe_reader(data.as_slice()).is_err());
        data[60..64].copy_from_slice(&0u32.to_le_bytes());
        assert!(machine_from_exe_reader(data.as_slice()).is_err());
        assert!(machine_from_exe_reader(b"not a PE".as_slice()).is_err());
    }
}
