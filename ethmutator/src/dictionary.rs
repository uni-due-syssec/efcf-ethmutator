// Copyright 2021 Michael Rodler
// This file is part of ethmutator.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! This file contains a custom AFL dictionary parser and create a fast way to look up dictionary entries
//! of a specific length - i.e., we want to get all 32-byte constants in the dictionary when mutating
//! a U256; also we want to be able to quickly get all the 4-byte constants for e.g., selecting
//! somewhat useful 4-byte functions signatures.
//!
//! Everything interesting is in the [`Dictionary`] struct.
//!

use anyhow::{anyhow, bail};
use ethereum_types::{Address, U256};
use rand::seq::IteratorRandom;
use rand::Rng;

const DICTIONARY_MAX_LOAD: usize = 1024 * 10;
const INT_SIZES: [usize; 6] = [8, 16, 32, 64, 128, 256];

#[inline]
fn bitsize_to_index(bitsize: usize) -> usize {
    if bitsize <= 8 {
        0
    } else if bitsize <= 16 {
        1
    } else if bitsize <= 32 {
        2
    } else if bitsize <= 64 {
        3
    } else if bitsize <= 128 {
        4
    } else if bitsize <= 256 {
        5
    } else {
        panic!("Unsupported bit size: {}", bitsize);
    }
}

fn calculate_entropy_score(value: U256) -> f32 {
    let bits = crate::useful_bit_size(value.bits());
    calculate_entropy_score_for_bits(value, bits)
}

fn calculate_entropy_score_for_bits(value: U256, bits: usize) -> f32 {
    use byte_slice_cast::AsByteSlice;

    let bytes = bits / 8;

    let mut entropy: f32 = 0.0;
    let mut byte_count = [0u8; 256];
    for b in value.as_byte_slice().iter() {
        byte_count[*b as usize] += 1;
    }
    byte_count[0] -= (32 - bytes) as u8;
    for count in byte_count.iter() {
        if *count > 0 {
            let count: f32 = (*count) as f32;
            let p = count / (bytes as f32);
            entropy -= p * p.log(256.0);
        }
    }
    entropy
}

const VALUE_ENTROPY_THRESHOLD: f32 = 0.20;

/// Custom dictionary for the [`EthMutator`] - supports several EVM ABI types and implements
/// sampling. Can be loaded from an AFL++-style dictionary with [`Dictionary::load_from_file`] and
/// [`Dictionary::from_string`]. It can also be extended with [`Dictionary::add_from_string`] and
/// [`Dictionary::add_from_file`], if multiple dictionary files should be merged. Can be manually
/// extended with [`Dictionary::add_value`] or the [`Dictionary::add_u32`] for 32-bit valued 4-byte
/// signature, or [`Dictionary::add_u64`] for 64-bit valued special constants and
/// [`Dictionary::add_bytes`] and [`Dictionary::add_string`] for general bytes/string constants.
#[derive(Debug, Clone, PartialEq)]
pub struct Dictionary {
    /// contains the raw values; INVARIANT: does not contain duplicate values - fast random access is
    /// important so we do not use a [`HashSet`] and stick to a normal [`Vec`] type.
    values: Vec<U256>,
    /// special vector containing 4-byte signatures value as u32; INVARIANT: no duplicates!
    fourbytes: Vec<u32>,
    /// special vector containing 8-byte values as u64; INVARIANT: does not contain duplicates
    eightbytes: Vec<u64>,
    /// special vector containing Address types; note that we have a rough heuristic that skips all
    /// numeric values that do not "look" like a real address (i.e., a lot of bits are set)
    addresses: Vec<Address>,
    /// vector to quickly look up U256 values for a particular integer size requirement - the contained u32 is a references to an entry in the [`values`] Vec
    sizes: [Vec<u32>; INT_SIZES.len()],
    /// Arbitrary bytestrings
    bytes: Vec<Box<[u8]>>,
    /// Strings should be valid utf-8 so we also use the rust String type
    strings: Vec<String>,
}

impl Default for Dictionary {
    fn default() -> Dictionary {
        Dictionary::new()
    }
}

#[allow(dead_code)]
impl Dictionary {
    pub fn new() -> Dictionary {
        let mut d = Dictionary {
            values: Vec::with_capacity(512),
            fourbytes: Vec::with_capacity(32),
            eightbytes: Vec::with_capacity(64),
            addresses: Vec::with_capacity(32),
            sizes: [
                Vec::with_capacity(512),
                Vec::with_capacity(256),
                Vec::with_capacity(128),
                Vec::with_capacity(128),
                Vec::with_capacity(128),
                Vec::with_capacity(128),
            ],
            bytes: vec![],
            strings: vec![],
        };
        d.add_value(U256::zero());
        d
    }

    pub fn stats(&self) -> String {
        format!(
            "Dict(#values={}, #4bytes={}, #address={}, #bytes={}, #strings={})",
            self.values.len(),
            self.fourbytes.len(),
            self.addresses.len(),
            self.bytes.len(),
            self.strings.len()
        )
    }

    pub fn is_empty(&self) -> bool {
        self.values.len() == 1
    }

    pub fn entry_count(&self) -> usize {
        self.values.len() - 1
    }

    pub fn entry_count_for_bitsize(&self, bitsize: usize) -> usize {
        let x = bitsize_to_index(bitsize);
        self.sizes[x].len() - 1
    }

    pub fn has_string(&self) -> bool {
        !self.strings.is_empty()
    }

    pub fn has_bytes(&self) -> bool {
        !self.bytes.is_empty()
    }

    pub fn has_4byte(&self) -> bool {
        !self.fourbytes.is_empty()
    }

    pub fn has_8byte(&self) -> bool {
        !self.eightbytes.is_empty()
    }

    pub fn has_address(&self) -> bool {
        !self.addresses.is_empty()
    }

    pub fn contains_value(&self, value: &U256) -> bool {
        self.values.contains(value)
    }

    pub fn contains_value_for_bitsize(&self, value: &U256, bitsize: usize) -> bool {
        let idx = bitsize_to_index(bitsize);
        self.sizes[idx].iter().any(|&o| {
            let i = self.sizes[idx][o as usize] as usize;
            self.values[i] == *value
        })
    }

    pub fn add_address(&mut self, value: Address) {
        if !self.addresses.contains(&value) {
            self.addresses.push(value);
        }
    }

    pub fn add_u32(&mut self, value: u32) {
        if !self.fourbytes.contains(&value) {
            self.fourbytes.push(value);
        }
    }

    pub fn add_u64(&mut self, value: u64) {
        if !self.eightbytes.contains(&value) {
            self.eightbytes.push(value);
        }
    }

    pub fn add_value_maybe(&mut self, value: U256) -> bool {
        // ignore all byte values
        if value.bits() < 16 {
            false
        } else if 152 <= value.bits() && value.bits() <= 160 {
            let entropy = calculate_entropy_score_for_bits(value, 160);
            if entropy > VALUE_ENTROPY_THRESHOLD {
                self.add_value(value)
            } else {
                false
            }
        } else {
            let entropy = calculate_entropy_score(value);
            if entropy > VALUE_ENTROPY_THRESHOLD {
                self.add_value(value)
            } else {
                false
            }
        }
    }

    pub fn add_value(&mut self, value: U256) -> bool {
        // avoid adding duplicate values
        if !self.values.contains(&value) {
            // we put the value into the dictionary and save the index of the new entry for later
            let d_idx = self.values.len() as u32;
            self.values.push(value); // push after len() to get index

            // now we check into which buckets the value fits
            let bitcnt = value.bits();

            // fast access to 4byte values (needed for sigs)
            if (24..=32).contains(&bitcnt) {
                self.add_u32(value.as_u32());
            }

            // fast access to potential addresses
            if (152..=160).contains(&bitcnt) {
                let mut v: Vec<u8> = vec![0; 32];
                value.to_big_endian(&mut v);
                self.add_address(Address::from_slice(&v[32 - 20..]));
            }

            // all other int sizes
            for (i, bitsize) in INT_SIZES.iter().enumerate() {
                if bitcnt <= *bitsize {
                    self.sizes[i].push(d_idx as u32);
                }
            }

            if bitcnt <= 64 {
                self.add_u64(value.as_u64());
            }

            true
        } else {
            false
        }
    }

    pub fn add_interesting_integer_values(&mut self) {
        // add some small values; we do not need the negative values here since the ethmutator will
        // automatically generate negative values based on positive values from the dictionary
        self.add_value(crate::U256_ONE);
        for i in 3..=16 {
            self.add_value(U256::from(i));
        }

        // add some interesting u64 values here
        self.add_u64(1);
        self.add_u64(1 << 10);
        for bitsize in &[8, 16, 32] {
            self.add_u64((1u64 << bitsize).overflowing_sub(1).0);
        }
        self.add_u64(std::u64::MAX);

        // we add the maximum integer value for all common bit widths here (e.g., to provoke
        // integer overflows) we also add the smallest integer value that require the given bit
        // width
        for bitsize in &[8, 16, 32, 64, 128, 256] {
            // maximum value within the bit width
            let (v, _) = (crate::U256_ONE << *bitsize).overflowing_sub(crate::U256_ONE);
            self.add_value(v);
            self.add_value(v / 2);
            // minimum value that requires the given bit width
            let v = crate::U256_ONE << (bitsize - 1);
            self.add_value(v);
        }
        // max uint256 aka (-1)
        let (v, _) = (crate::U256_ZERO).overflowing_sub(crate::U256_ONE);
        self.add_value(v);
    }

    pub fn add_string(&mut self, string: String) -> bool {
        if !self.strings.contains(&string) {
            self.strings.push(string);
            true
        } else {
            false
        }
    }

    pub fn add_bytes(&mut self, bytes: Box<[u8]>) -> bool {
        if !self.bytes.contains(&bytes) {
            self.bytes.push(bytes);
            true
        } else {
            false
        }
    }

    pub fn sample_4byte<R: Rng + ?Sized>(&self, rng: &mut R) -> u32 {
        if self.fourbytes.len() > 0 {
            self.fourbytes[rng.gen_range(0..self.fourbytes.len())]
        } else {
            0u32
        }
    }

    pub fn sample_8byte<R: Rng + ?Sized>(&self, rng: &mut R) -> u64 {
        if self.eightbytes.len() > 0 {
            self.eightbytes[rng.gen_range(0..self.eightbytes.len())]
        } else {
            0u64
        }
    }

    pub fn sample_1byte<R: Rng + ?Sized>(&self, rng: &mut R) -> u8 {
        let i = self.sizes[0][rng.gen_range(0..self.sizes[0].len())];
        self.values[i as usize].byte(0)
    }

    pub fn sample_address<R: Rng + ?Sized>(&self, rng: &mut R) -> Address {
        if self.addresses.len() > 0 {
            self.addresses[rng.gen_range(0..self.addresses.len())]
        } else {
            Address::zero()
        }
    }

    #[inline]
    pub fn sample_bitsize<R: Rng + ?Sized>(&self, bitsize: usize, rng: &mut R) -> U256 {
        let x = bitsize_to_index(bitsize);
        let i = self.sizes[x][rng.gen_range(0..self.sizes[x].len())];
        self.values[i as usize]
    }

    #[inline]
    pub fn sample_bytesize<R: Rng + ?Sized>(&self, bytesize: usize, rng: &mut R) -> U256 {
        self.sample_bitsize(bytesize * 8, rng)
    }

    pub fn sample_min_bitsize<R: Rng + ?Sized>(&self, bitsize: usize, rng: &mut R) -> U256 {
        let r: Option<&U256> = self
            .values
            .iter()
            .filter(|x| x.bits() >= bitsize)
            .choose(rng);
        if let Some(v) = r {
            v.clone()
        } else {
            U256::one() << bitsize
        }
    }

    pub fn sample_string<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<String> {
        let r = self.strings.iter().choose(rng);
        if let Some(v) = r {
            Some(v.clone())
        } else {
            None
        }
    }

    pub fn sample_bytes<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<Box<[u8]>> {
        let r = self.bytes.iter().choose(rng);
        if let Some(v) = r {
            Some(v.clone())
        } else {
            None
        }
    }

    pub fn sample_bytes_exact<R: Rng + ?Sized>(
        &self,
        len: usize,
        rng: &mut R,
    ) -> Option<Box<[u8]>> {
        let r = self.bytes.iter().filter(|x| x.len() == len).choose(rng);
        if let Some(v) = r {
            Some(v.clone())
        } else {
            None
        }
    }

    pub fn from_string(dict_string: &str) -> anyhow::Result<Dictionary> {
        let mut d = Self::new();
        d.add_from_string(dict_string)?;
        anyhow::Result::Ok(d)
    }

    pub fn add_from_string(&mut self, dict_string: &str) -> anyhow::Result<()> {
        let mut loaded = 0usize;
        for line in dict_string.split("\n") {
            let line = line.trim();
            if line.len() == 0 || line.starts_with("#") || line.len() == 2 {
                // ignorable line
                continue;
            }
            if !line.starts_with("\"") || !line.ends_with("\"") || (line.len() - 2) % 4 != 0 {
                bail!(
                    "Invalid line {:?} must begin and end with '\"' and have length {} - 2 % 4 == {} != 0.",
                    line,
                    line.len(),
                    (line.len() - 2) % 4
                );
            }

            let hex = line[1..(line.len() - 1)].replace("\\x", "");
            let mut bytes =
                hexutil::read_hex(&hex).map_err(|e| anyhow!("Failed to decode hex: {:?}", e))?;

            // we treat all dictionary entries <= 32 bytes / 256 bit as integer types
            if bytes.len() <= 32 {
                let orig_len = bytes.len();

                // left pad since we have big-endian integers
                bytes.reserve(32 - bytes.len());
                for _ in 0..(32 - bytes.len()) {
                    bytes.insert(0, 0);
                }

                let value = U256::from_big_endian(&bytes);

                self.add_value(value);

                if 3 <= orig_len && orig_len <= 4 {
                    self.add_u32(value.as_u32());
                }
                if orig_len <= 8 {
                    self.add_u64(value.as_u64());
                }
            }

            // we treat all dictionary entries >= 32 bytes as potential bytes/strings
            if bytes.len() >= 32 {
                // larger ones might be bytes or strings
                if let Ok(s) = String::from_utf8(bytes.clone()) {
                    self.add_string(s);
                }
                self.add_bytes(bytes.into_boxed_slice());
            }

            loaded += 1;
            if loaded > DICTIONARY_MAX_LOAD {
                eprintln!("[EthMutator] warning truncating dictionary load!");
                break;
            }
        }
        anyhow::Result::Ok(())
    }

    pub fn to_string(&self) -> String {
        let mut strbuf = String::new();

        fn append_bytes(strbuf: &mut String, buf: &[u8]) {
            strbuf.push_str("\"");
            for b in buf.iter() {
                strbuf.push_str(&format!("\\x{:02X}", b));
            }
            strbuf.push_str("\"\n");
        }

        for (i, _bitsize) in INT_SIZES.iter().enumerate() {
            for off in self.sizes[i].iter().cloned() {
                let val = &self.values[off as usize];
                let mut buf = [0u8; 32];
                val.to_big_endian(&mut buf);
                append_bytes(&mut strbuf, &buf);
            }
        }
        for fb in self.fourbytes.iter().cloned() {
            let buf = fb.to_be_bytes();
            append_bytes(&mut strbuf, &buf);
        }

        for b8 in self.eightbytes.iter().cloned() {
            // we utilize LE here, because this is harness byteorder and not evm byteorder
            let buf = b8.to_le_bytes();
            append_bytes(&mut strbuf, &buf);
        }

        for s in self.strings.iter() {
            strbuf.push_str(&format!("\"{}\"\n", s));
        }

        for buf in self.bytes.iter() {
            append_bytes(&mut strbuf, &buf);
        }

        for a in self.addresses.iter() {
            let buf = a.as_bytes();
            append_bytes(&mut strbuf, &buf);
        }

        strbuf
    }

    pub fn add_from_file(&mut self, path: &std::path::Path) -> anyhow::Result<()> {
        //let path = std::path::Path::new(path);
        //let file = std::fs::File::open(path)?;
        let contents = std::fs::read_to_string(path)?;
        self.add_from_string(&contents)
    }

    pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Dictionary> {
        //let path = std::path::Path::new(path);
        //let file = std::fs::File::open(path)?;
        let contents = std::fs::read_to_string(path)?;
        Self::from_string(&contents)
    }

    pub fn write_to_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        use std::fs::File;
        use std::io::prelude::*;
        let s = self.to_string();
        let mut f = File::create(path)?;
        f.write_all(s.as_bytes())?;
        anyhow::Result::Ok(())
    }

    pub fn populate_with_interesting_values(&mut self) {
        // first add some interesting integer values
        self.add_interesting_integer_values();

        #[cfg(feature = "dictionary_for_storage_corruption")]
        {
            use sha3::Digest;

            // now we compute some potentially interesting storage addresses.
            // https://docs.soliditylang.org/en/v0.8.4/internals/layout_in_storage.html#mappings-and-dynamic-arrays
            //
            // TODO: I am not sure this is really beneficial? the idea is that this might allow us to
            // discover storage-corruption exploits that were possible in early solidity versions. But
            // the storage address space is so big that this is more of a lucky guess really.
            //
            let mut buf = [0u8; 32];
            let mut buf2 = [0u8; 64];
            for i in 0..64 {
                // "Array data is located starting at keccak256(p) and it is laid out in the same way as
                // statically-sized array data would." according to the solidity docs
                // So we compute this for the first couple of storage slots
                let u = U256::from(i);
                u.to_big_endian(&mut buf);
                let hash = sha3::Keccak256::digest(&buf);
                let dict_val = U256::from_big_endian(&hash);
                self.add_value(dict_val);
                // the value as negative (i.e., to trigger overflows)
                self.add_value(crate::U256_ZERO.overflowing_sub(dict_val).0);

                // For `mapping` types, we have the following rule: given a key `k` and the storage slot
                // `p` for the mapping variable, the lookup is: `keccak256(h(k) . p)` as storage
                // address.
                //
                // We compute some potentially interesting storage addresses for all `mapping (address => X)` types, based on the addresses that we know of from the harness.
                //
                for sender in crate::TX_SENDER.iter() {
                    let b = ethereum_types::H256::from(sender.clone());
                    let sender_uint = U256::from(b.as_bytes());
                    sender_uint.to_big_endian(&mut buf2[0..32]);
                    u.to_big_endian(&mut buf2[32..64]);

                    let hash = sha3::Keccak256::digest(&buf2);
                    let dict_val = U256::from_big_endian(&hash);
                    self.add_value(dict_val);
                    self.add_value(crate::U256_ZERO.overflowing_sub(dict_val).0);
                }
            }

            // hash(0) til hash(255)
            for i in 0..256 {
                let u = U256::from(i);
                u.to_big_endian(&mut buf);
                let hash = sha3::Keccak256::digest(&buf);
                let dict_val = U256::from_big_endian(&hash);
                self.add_value(dict_val);
                self.add_bytes(buf.to_vec().into_boxed_slice());
            }

            // also add the hash of two/three consecutive 0 evm-words
            buf2.iter_mut().for_each(|m| *m = 0);
            let hash = sha3::Keccak256::digest(&buf2);
            let dict_val = U256::from_big_endian(&hash);
            self.add_value(dict_val);
            self.add_bytes(buf2.to_vec().into_boxed_slice());
            let buf3 = [0u8; 3 * 32];
            let hash = sha3::Keccak256::digest(&buf3);
            let dict_val = U256::from_big_endian(&hash);
            self.add_value(dict_val);
            self.add_bytes(buf3.to_vec().into_boxed_slice());
        }

        // then add some fixed strings / bytes to the dictionary, in case the contract uses an
        // arbitrary string as an identifier or something like that.
        self.add_string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        self.add_string("AAAA".to_string());
        let b: Vec<u8> = std::iter::repeat(b'A').take(32).collect();
        let b = b.into_boxed_slice();
        self.add_bytes(b);
        for length in &[8, 32, 64, 128] {
            let b: Vec<u8> = std::iter::repeat(b'\x3c').take(*length).collect();
            let b = b.into_boxed_slice();
            self.add_bytes(b);
        }

        // default block number in the fuzzing harness
        self.add_value(U256::from(100000));
        // default timestamp in the fuzzing harness
        self.add_value(U256::from(1420066800));

        // we also add the values from 1 up to 10 ether to the dictionary
        for i in 1..=10 {
            self.add_value(U256::from(crate::ONE_ETHER_WEI) * i);
        }

        // the sender addresses from the harness are also added to the dictionary as regular
        // integers (and automatically also as addresses via the add_value function)
        for sender in crate::TX_SENDER.iter() {
            let b = ethereum_types::H256::from(*sender);
            let sender_uint = U256::from(b.as_bytes());
            self.add_value(sender_uint);
        }

        for sender in crate::OTHER_ADDRESSES.iter() {
            let b = ethereum_types::H256::from(*sender);
            let sender_uint = U256::from(b.as_bytes());
            self.add_value(sender_uint);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitsize_to_index() {
        for (i, bitsize) in INT_SIZES.iter().enumerate() {
            assert_eq!(i, bitsize_to_index(*bitsize));
        }
    }

    #[test]
    fn test_odd_bitsize_to_index() {
        for (i, bitsize) in &[(0, 0), (0, 7), (5, 160), (4, 127), (4, 120)] {
            assert_eq!(*i, bitsize_to_index(*bitsize));
        }
    }

    #[test]
    fn test_dictionary_add() {
        let mut d = Dictionary::new();
        assert!(d.is_empty());

        d.add_value(U256::from(1));
        assert_eq!(d.entry_count(), 1);
        assert_eq!(d.fourbytes.len(), 0);
        assert_eq!(d.addresses.len(), 0);

        d.add_value(U256::from(0x01020304));

        assert_eq!(d.fourbytes.len(), 1);
        assert_eq!(d.fourbytes[0], 0x01020304);
        assert_eq!(d.addresses.len(), 0);

        let a_raw = [
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8,
            0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8,
        ];
        let a = U256::from(a_raw);
        d.add_value(a.clone());

        assert_eq!(d.fourbytes.len(), 1);
        assert_eq!(d.addresses.len(), 1);
        itertools::assert_equal(
            d.addresses[0].as_bytes().iter().rev(),
            a_raw.iter().rev().take(20),
        );
        assert_eq!(d.entry_count_for_bitsize(256), 3);
    }

    #[test]
    fn test_new_dictionary_from_string() {
        let testcase = r#"
# 8
"\x01"
# 16
"\x01\x02"
# 32
"\x01\x02\x03\x04"
# 64
"\x01\x02\x03\x04\x05\x06\x07\x08"
# 128
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
# 256
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
# > 256
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\xff\xff\xff\xff"
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            "#;
        let d = Dictionary::from_string(testcase).unwrap();
        assert!(!d.is_empty());
        assert_eq!(d.entry_count(), 6);
        for (i, bitsize) in INT_SIZES.iter().enumerate() {
            assert_eq!(d.entry_count_for_bitsize(*bitsize), i + 1);
        }

        assert_eq!(d.fourbytes.len(), 1);
        assert_eq!(d.fourbytes[0], 0x01020304);

        assert_eq!(d.eightbytes.len(), 5);

        assert!(d.bytes.len() > 2);
        assert!(d.strings.len() > 1);
    }

    #[test]
    fn test_adding_interesting_integer_values() {
        let mut d = Dictionary::new();
        d.add_interesting_integer_values();

        for (i, bucket) in d.sizes.iter().enumerate() {
            assert!(bucket.len() > (i + 3), "bucket {} len {}", i, bucket.len());
        }
    }

    #[test]
    fn populate_interesting_values() {
        let mut d = Dictionary::new();
        d.populate_with_interesting_values();

        // check that we have something in every category the dictionary knows
        for (i, bucket) in d.sizes.iter().enumerate() {
            assert!(
                bucket.len() > (i + 3),
                "integer bucket {} len {}",
                i,
                bucket.len()
            );
        }
        assert!(
            d.addresses.len() > 0,
            "addresses count {}",
            d.addresses.len()
        );
        assert!(d.bytes.len() > 0, "byte string count {}", d.bytes.len());
        assert!(d.strings.len() > 0, "strings count {}", d.strings.len());
    }

    #[test]
    fn to_from_string() {
        // we test a bit here converting to and from a string. However, this does not make a whole
        // lot of sence since to/from_string are not really an exact opposites, i..e.,
        // in many cases: d != from_string(to_string(d))
        // This is intentional, since creating a dictionary in memory is a bit optimized and parsing
        // the format is also a bit fuzzy, s.t., not everything will be extremely cluttered...

        // empty dict
        let d1 = Dictionary::new();
        let s = d1.to_string();
        let d2 = Dictionary::from_string(&s).unwrap();
        assert_eq!(d2.entry_count(), 0);

        let mut d1 = Dictionary::new();
        d1.populate_with_interesting_values();
        let s = d1.to_string();
        let d2 = Dictionary::from_string(&s).unwrap();

        for (i, bitsize) in INT_SIZES.iter().enumerate() {
            for off in d1.sizes[i].iter().cloned() {
                let val1 = &d1.values[off as usize];
                assert!(
                    d2.contains_value_for_bitsize(val1, *bitsize),
                    "value {} from first dictionary not contained in new dictionary",
                    val1
                );
            }
        }

        //assert!(
        //    d1.bytes.is_subset(&d2.bytes),
        //    "Bytes Dict {:?} is not a subset of {:?}",
        //    d1.bytes,
        //    d2.bytes
        //);
        //assert!(
        //    d1.strings.is_subset(&d2.strings),
        //    "Strings dict {:?} is not a subset of {:?}",
        //    d1.strings,
        //    d2.strings
        //);
    }

    #[test]
    fn test_maybe_adding() {
        let mut d = Dictionary::new();
        assert!(!d.add_value_maybe(crate::U256_ZERO));
        assert!(!d.add_value_maybe(crate::U256_ONE));
        assert!(!d.add_value_maybe(crate::U256_ZERO.overflowing_sub(crate::U256_ONE).0));
        assert!(!d.add_value_maybe(crate::U256_ZERO.overflowing_sub(U256::from(128u32)).0));

        let v = U256::from(42u32);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {} is {}", v, entropy);
        assert!(!d.add_value_maybe(v));
        let v = U256::from(1342u32);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {} is {}", v, entropy);
        assert!(!d.add_value_maybe(v));

        let v = U256::from(0x45321239u32);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {} is {}", v, entropy);
        assert!(d.add_value_maybe(v));

        let v = U256::from(0x45000039u32);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {:#x} is {}", v, entropy);
        assert!(!d.add_value_maybe(v));

        let v = U256::from(0x45ff45ffu32);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {:#x} is {}", v, entropy);
        assert!(!d.add_value_maybe(v));

        let bytes: [u8; 32] = [
            0x32, 0xd8, 0xaa, 0x16, 0xdd, 0x2c, 0xf0, 0x92, 0x2e, 0x09, 0x86, 0x90, 0xa0, 0x4a,
            0xa3, 0xcb, 0x7d, 0x96, 0x7d, 0x71, 0x13, 0xc0, 0xea, 0xef, 0x3a, 0xed, 0x74, 0x7f,
            0xf0, 0xe1, 0x21, 0x80,
        ];
        let v = U256::from(bytes);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {:#x} is {}", v, entropy);
        assert!(d.add_value_maybe(v));

        let bytes: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x99, 0x3a, 0xa2, 0xbb, 0xb0, 0x29, 0x1a, 0x4c, 0xb3, 0x6a, 0x6d, 0xfc,
            0xe1, 0x70, 0xac, 0x8c,
        ];
        let v = U256::from(bytes);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {:#x} is {}", v, entropy);
        assert!(d.add_value_maybe(v));

        let bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let v = U256::from(bytes);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {:#x} is {}", v, entropy);
        assert!(!d.add_value_maybe(v));

        let bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x29, 0x1a, 0x4c, 0xb3, 0x6a, 0x6d, 0xfc,
            0xe1, 0x70, 0xac, 0x8c,
        ];
        let v = U256::from(bytes);
        let entropy = calculate_entropy_score(v);
        println!("entropy score of {:#x} is {}", v, entropy);
        assert!(d.add_value_maybe(v));

        let bytes: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd7, 0x0b,
            0x4b, 0xc7, 0xb6, 0x31, 0xb8, 0x4d, 0x1e, 0xf4, 0xb6, 0xba, 0x24, 0xcb, 0x8b, 0xcd,
            0xc3, 0x90, 0x02, 0xc8,
        ];
        let v = U256::from(bytes);
        let entropy = calculate_entropy_score(v);
        let entropy2 = calculate_entropy_score_for_bits(v, 160);
        println!(
            "entropy score of {:#x} is {} ({} as uint256)",
            v, entropy2, entropy
        );
        assert!(d.add_value_maybe(v));
    }
}
