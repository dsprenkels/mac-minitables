use std::fmt;
use std::io;
use std::io::prelude::*;

use sha2::{Digest, digest::FixedOutput, Sha256};

const TABLE_SIZE: usize = 0x100_0000;
const FILE_INDEX_LEN: u64 = 0x30000;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy)]
pub struct MACAddress {
    v: u64,
}

impl fmt::Display for MACAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let arr = self.into_array();
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]
        )
    }
}

impl<'a> From<&'a [u8; 6]> for MACAddress {
    fn from(addr: &[u8; 6]) -> Self {
        let v = u64::from(addr[5])
            | (u64::from(addr[4]) << 8)
            | (u64::from(addr[3]) << 16)
            | (u64::from(addr[2]) << 24)
            | (u64::from(addr[1]) << 32)
            | (u64::from(addr[0]) << 40);
        Self::from(v)
    }
}

impl<'a> From<(&'a [u8; 3], &'a [u8; 3])> for MACAddress {
    fn from(limbs: (&[u8; 3], &[u8; 3])) -> Self {
        let (prefix, suffix) = limbs;
        let addr = [
            prefix[0], prefix[1], prefix[2], suffix[0], suffix[1], suffix[2],
        ];
        Self::from(&addr)
    }
}

impl From<usize> for MACAddress {
    fn from(v: usize) -> Self {
        let addr = Self { v: v as u64 };
        assert!(
            addr.check_range(),
            "invalid value for MACAddress ({:02X})",
            v
        );
        addr
    }
}

impl From<u64> for MACAddress {
    fn from(v: u64) -> Self {
        let addr = Self { v };
        assert!(
            addr.check_range(),
            "invalid value for MACAddress ({:02X})",
            v
        );
        addr
    }
}

impl Into<usize> for MACAddress {
    #[cfg(not(target_pointer_width = "64"))]
    fn into(self) -> usize {
        compile_error!("Cannot fit MAC address into pointer type")
    }

    #[cfg(target_pointer_width = "64")]
    fn into(self) -> usize {
        self.v as usize
    }
}

impl Into<u64> for MACAddress {
    fn into(self) -> u64 {
        self.v as u64
    }
}

impl MACAddress {
    fn check_range(self) -> bool {
        self.v < 2_u64.pow(48)
    }

    pub fn into_array(self) -> [u8; 6] {
        debug_assert!(self.check_range());
        [
            (self.v >> 40) as u8,
            (self.v >> 32) as u8,
            (self.v >> 24) as u8,
            (self.v >> 16) as u8,
            (self.v >> 8) as u8,
            self.v as u8,
        ]
    }

    pub fn prefix(self) -> [u8; 3] {
        debug_assert!(self.check_range());
        [
            (self.v >> 40) as u8,
            (self.v >> 32) as u8,
            (self.v >> 24) as u8,
        ]
    }

    pub fn suffix(self) -> [u8; 3] {
        debug_assert!(self.check_range());
        [(self.v >> 16) as u8, (self.v >> 8) as u8, self.v as u8]
    }
}

type MemTable = Vec<(u16, MACAddress)>;

pub fn compute(prefix: &[u8; 3], writer: &mut dyn Write) -> io::Result<()> {
    let memtable = compute_memtable(prefix);
    write_memtable(&memtable, writer)
}

/// Compute the complete lookup table for a given MAC address prefix
fn compute_memtable(prefix: &[u8; 3]) -> MemTable {
    let mut hasher = Sha256::new();
    let prefix_val =
        (u64::from(prefix[0]) << 40) | (u64::from(prefix[1]) << 32) | (u64::from(prefix[2]) << 24);

    let mut memtable = Vec::with_capacity(TABLE_SIZE);
    for idx in 0..2_u64.pow(24) {
        let preimage = MACAddress::from(prefix_val | idx);
        hasher.update(preimage.into_array());
        let hash = hasher.finalize_fixed_reset();
        let first_hash_word = (u16::from(hash[0]) << 8) | u16::from(hash[1]);
        memtable.push((first_hash_word, preimage));
    }
    memtable.sort_unstable();
    memtable
}

fn write_memtable(table: &[(u16, MACAddress)], w: &mut dyn Write) -> io::Result<()> {
    assert_eq!(table.len(), 2_usize.pow(24));
    let prefix = table[0].1.prefix();
    for (_, addr) in table {
        assert_eq!(addr.prefix(), prefix);
    }

    // File format:
    //   - First 256 kibibytes contains the "index". The index contains 2^16 24-bit offsets of
    //     each chunk that stores the preimages for a hash beginning with the bytes equal to the
    //     offset.
    //   - After 196608 bytes (`FILE_INDEX_LEN`), there are 2^24 24-bit MAC address suffixes
    //     (48Mb of data).
    // Totalling up to 48.25 mibibytes of table. All data is written in big endian.

    // Write the index
    for idx in 0..2_usize.pow(16) {
        let offset = get_hash_offset(idx as u16, &table);
        assert!(offset < 2_usize.pow(24));
        let buf: [u8; 3] = [(offset >> 16) as u8, (offset >> 8) as u8, offset as u8];
        w.write_all(&buf)?;
    }

    // Write the address suffixes
    for (_, addr) in table {
        let buf = addr.suffix();
        w.write_all(&buf)?;
    }
    Ok(())
}

fn get_hash_offset(index_val: u16, table: &[(u16, MACAddress)]) -> usize {
    let zero = MACAddress::from(0_usize);
    table
        .binary_search(&(index_val, zero))
        .unwrap_or_else(|x| x)
}

pub fn lookup<R>(hash: &[u8], prefix: &[u8; 3], mut table: R) -> io::Result<Option<MACAddress>>
where
    R: Read + Seek,
{
    let first_hash_word = u16::from(hash[0]) << 8 | u16::from(hash[1]);
    let mut buf = [0, 0, 0];

    let index_val_offset = 3 * u64::from(first_hash_word);
    table
        .seek(io::SeekFrom::Start(index_val_offset))
        .expect("unreachable: negative u64");
    // Read the start index of the preimage list
    table.read_exact(&mut buf)?;
    let start_idx = u64::from(buf[0]) << 16 | u64::from(buf[1]) << 8 | u64::from(buf[2]);
    assert!(start_idx < 2_u64.pow(24));
    // Read the end index of the preimage list
    let end_idx = match table.read_exact(&mut buf) {
        Ok(()) => u64::from(buf[0]) << 16 | u64::from(buf[1]) << 8 | u64::from(buf[2]),
        Err(x) if x.kind() == io::ErrorKind::UnexpectedEof => 2_u64.pow(24),
        Err(_) => unreachable!(),
    };

    // Scan the preimage list
    let mut hasher = Sha256::new();
    table
        .seek(io::SeekFrom::Start(FILE_INDEX_LEN + 3 * start_idx))
        .expect("unreachable: negative u64");
    for _ in 0..end_idx.saturating_sub(start_idx) {
        table.read_exact(&mut buf)?;
        let addr = MACAddress::from((prefix, &buf));
        hasher.update(addr.into_array());
        let addr_hash = hasher.finalize_fixed_reset();
        if hash == &addr_hash[..] {
            return Ok(Some(addr));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
            fn prop_macaddress_prefix(p0: u8, p1: u8, p2: u8, s0: u8, s1: u8, s2: u8) -> bool {
                let prefix = [p0, p1, p2];
                let suffix = [s0, s1, s2];
                let addr = MACAddress::from((&prefix, &suffix));
                addr.prefix() == prefix
            }
    }

    quickcheck! {
            fn prop_macaddress_suffix(p0: u8, p1: u8, p2: u8, s0: u8, s1: u8, s2: u8) -> bool {
                let prefix = [p0, p1, p2];
                let suffix = [s0, s1, s2];
                let addr = MACAddress::from((&prefix, &suffix));
                addr.suffix() == suffix
            }
    }

    quickcheck! {
            fn prop_macaddress_both(p0: u8, p1: u8, p2: u8, s0: u8, s1: u8, s2: u8) -> bool {
                let prefix = [p0, p1, p2];
                let suffix = [s0, s1, s2];
                let addr = MACAddress::from((&prefix, &suffix));
                addr.prefix() == prefix && addr.suffix() == suffix
            }
    }

    quickcheck! {
            fn prop_macaddress_intoarray(p0: u8, p1: u8, p2: u8, s0: u8, s1: u8, s2: u8) -> bool {
                let prefix = [p0, p1, p2];
                let suffix = [s0, s1, s2];
                let addr = MACAddress::from((&prefix, &suffix));
                addr.into_array() == [p0, p1, p2, s0, s1, s2]
            }
    }

    #[test]
    fn test_macaddress_usize() {
        let n: usize = 0x0102_0304_0506;
        let addr = MACAddress::from(n);
        assert_eq!(addr.into_array(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let n2: usize = addr.into();
        assert_eq!(n2, n);
    }

    #[test]
    fn test_macaddress_u64() {
        let n: u64 = 0x0102_0304_0506;
        let addr = MACAddress::from(n);
        assert_eq!(addr.into_array(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let n2: u64 = addr.into();
        assert_eq!(n2, n);
    }

    lazy_static! {
        static ref PREFIX: [u8; 3] = [0, 0, 1];
        static ref TABLE: Vec<u8> = {
            let len = 3 * 2_usize.pow(16) + 3 * 2_usize.pow(24);
            let mut table = Vec::with_capacity(len);
            compute(&*PREFIX, &mut table).unwrap();
            table
        };
    }

    quickcheck! {
            fn prop_lookup(s0: u8, s1: u8, s2: u8) -> bool {
                let suffix = [s0, s1, s2];
                let mut cursor = io::Cursor::new(&*TABLE);
                let addr = MACAddress::from((&*PREFIX, &suffix));
                let mut hasher = Sha256::new();
                hasher.update(addr.into_array());
                let hash = hasher.finalize_fixed_reset();
                let preimage = lookup(&hash, &*PREFIX, &mut cursor).unwrap();
                preimage == Some(addr)
            }
    }

}
