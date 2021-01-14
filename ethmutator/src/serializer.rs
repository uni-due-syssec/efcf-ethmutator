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

//use packed_struct::prelude::*;
use std::rc::Rc;
use zerocopy::{AsBytes, FromBytes};

use crate::types::*;
use crate::HARNESS_MAX_RETURNS;

const TX_DATA_SIZE: usize = core::mem::size_of::<TransactionHeader>();
const BLOCK_HEADER_SIZE: usize = core::mem::size_of::<BlockHeader>();
const RETURN_HEADER_SIZE: usize = core::mem::size_of::<ReturnHeader>();

/// Parse bytes to a FuzzCase data structure - does not fail, but skips remaining bytes whenever
/// something unforseen occurs. In the worst case, this returns the default blockheader with an
/// empty transaction list. The reverse operation is [`pack_to_bytes`] or [`pack_into_bytes`].
pub fn parse_bytes(bytes: &[u8]) -> FuzzCase {
    let mut i = 0;

    let block_header = if bytes.len() >= BLOCK_HEADER_SIZE {
        match BlockHeader::read_from_prefix(&bytes[0..BLOCK_HEADER_SIZE]) {
            Some(blockheader) => {
                i += BLOCK_HEADER_SIZE;
                blockheader
            }
            None => BlockHeader::default(),
        }
    } else {
        BlockHeader::default()
    };

    // avoid frequent re-allocations, so we reserve a lot of capacity up-front
    // at least 10 empty TXs or roughly half of the length of the given bytes
    let mut transactions: TransactionList = Vec::with_capacity(std::cmp::max(
        (TX_DATA_SIZE) * 10,
        bytes.len() / TX_DATA_SIZE / 2,
    ));
    while (i + TX_DATA_SIZE) <= bytes.len() {
        match TransactionHeader::read_from_prefix(&bytes[i..(i + TX_DATA_SIZE)]) {
            Some(mut txdata) => {
                // padding is ignore, but to ensure consistency we set it to 0
                txdata.clear_padding();
                i += TX_DATA_SIZE;
                let data_end = i + txdata.length as usize;
                let data_end = if data_end > bytes.len() {
                    bytes.len()
                } else {
                    data_end
                };
                let input_bytes = &bytes[i..data_end];

                txdata.length = input_bytes.len() as u16;
                i += txdata.length as usize;

                let mut return_data: Vec<ReturnData> =
                    Vec::with_capacity(txdata.return_count as usize);
                for _ in 0..txdata.return_count {
                    if (i + RETURN_HEADER_SIZE) > bytes.len() {
                        txdata.return_count = return_data.len() as u8;
                        break;
                    }
                    match ReturnHeader::read_from_prefix(&bytes[i..(i + RETURN_HEADER_SIZE)]) {
                        Some(mut retdata) => {
                            i += RETURN_HEADER_SIZE;

                            let data_end = i + retdata.data_length as usize;
                            let data_end = if data_end > bytes.len() {
                                bytes.len()
                            } else {
                                data_end
                            };
                            let retdata_bytes = &bytes[i..data_end];
                            i += retdata_bytes.len();
                            retdata.data_length = retdata_bytes.len() as u16;

                            return_data.push(ReturnData {
                                header: retdata,
                                data: Rc::new(Vec::from(retdata_bytes)),
                            });
                        }
                        None => {
                            break;
                        }
                    }
                }

                txdata.return_count = return_data.len() as u8;

                transactions.push(Transaction {
                    header: txdata,
                    input: Rc::new(Vec::from(input_bytes)),
                    returns: return_data,
                });
            }
            None => {
                break;
            }
        }
    }
    FuzzCase {
        header: block_header,
        txs: transactions,
    }
}

/// Pack/Serialize a [`FuzzCase`] into a bunch of bytes, ready to be consumed by the harness or the
/// bitflipping fuzzer.
///
/// Dangerzone: this function contains some unsafety with Vec usage to achieve better performance.
pub fn pack_into_bytes(data: &FuzzCase, bytes: &mut Vec<u8>) {
    let (bh, txs) = (&data.header, &data.txs);

    bytes.clear();
    // to avoid frequent re-allocations we reserve some approximate length
    let approx_size =
        BLOCK_HEADER_SIZE + (txs.len() * (TX_DATA_SIZE + 128 + (2 * RETURN_HEADER_SIZE)));
    bytes.reserve(approx_size);

    // first pack block header to vector; unsafe block for performance
    unsafe {
        // we get a mutable unchecked slice, which should be safe, because we already reserved
        // enough space above.
        let x = bytes.get_unchecked_mut(0..BLOCK_HEADER_SIZE);
        // we pack directly into the obtained slice, which is backed by the Vec's buffer
        bh.write_to(x).unwrap();
        // finally we need to set the length of the vector to accomodate for the new data
        bytes.set_len(BLOCK_HEADER_SIZE);
    }

    // afterwards we pack the transactions up to the maximum supported by the harness
    for tx in txs.iter() {
        let (txdata, input, retdata) = (&tx.header, &tx.input, &tx.returns);
        let mut txdata = *txdata;
        // not needed, should be 0 all the time anyway
        //txdata.clear_padding();
        txdata.return_count = std::cmp::min(tx.returns.len(), HARNESS_MAX_RETURNS) as u8;
        let input_len = input.len();
        txdata.length = input_len as u16;
        // potential unsafety here!
        // first we reserve enough space for tx header, input and return data structs
        bytes.reserve(
            TX_DATA_SIZE
                + input.len()
                + ((txdata.return_count as usize) * (RETURN_HEADER_SIZE + 32)),
        );
        // we obtain the current length
        let current_len = bytes.len();
        unsafe {
            // same unsafe as above
            let x = bytes.get_unchecked_mut(current_len..(current_len + TX_DATA_SIZE));
            txdata.write_to(x).unwrap();
            bytes.set_len(current_len + TX_DATA_SIZE);
        }
        // then we append the input
        //bytes.extend(input.iter().take(txdata.length as usize));
        let current_len = bytes.len();
        unsafe {
            // same unsafe as above
            let x = bytes.get_unchecked_mut(current_len..(current_len + input_len));
            x.copy_from_slice(&input[0..input_len]);
            //txdata.write_to(x).unwrap();
            bytes.set_len(current_len + input_len);
        }

        // the harness on-the-wire format currently only supports 255 return data fields. So
        // we have to ignore the rest if there is some.
        for ret in retdata.iter().take(txdata.return_count as usize) {
            let current_len = bytes.len();
            let mut ret_header = ret.header;
            let ret_data_len = (ret.data.len() as u16) as usize; // truncates
            ret_header.data_length = ret.data.len() as u16;
            // handle the return data
            bytes.reserve(RETURN_HEADER_SIZE + ret_data_len);
            unsafe {
                // same unsafe as above
                let x = bytes.get_unchecked_mut(current_len..(current_len + RETURN_HEADER_SIZE));
                ret_header.write_to(x).unwrap();
                bytes.set_len(current_len + RETURN_HEADER_SIZE);
            }

            // in case ret.data is actually longer than supported by the length field data type,
            // we drop the remaining bytes.
            //bytes.extend(ret.data.iter().take(ret_data_len));
            let current_len = bytes.len();
            unsafe {
                // same unsafe as above
                let x = bytes.get_unchecked_mut(current_len..(current_len + ret_data_len));
                x.copy_from_slice(&ret.data[0..ret_data_len]);
                //txdata.write_to(x).unwrap();
                bytes.set_len(current_len + ret_data_len);
            }
        }
    }
}

/// Transform a [`FuzzCase`] datastructure into a bunch of bytes. Seed [`pack_into_bytes`] if you
/// already have a Vec of bytes.
pub fn pack_to_bytes(data: &FuzzCase) -> Vec<u8> {
    let txs = &data.txs;
    // we allocate a byte Vec with at least the block header and with enough size for all
    // transaction headers and 128 bytes of input per transaction.
    let mut bytes: Vec<u8> =
        Vec::with_capacity(BLOCK_HEADER_SIZE + (txs.len() * (TX_DATA_SIZE + 128)));
    pack_into_bytes(data, &mut bytes);
    bytes
}

/// Use this `mod` with the `#[serde(with = "crate::serializer::serde_bytes_as_hex")]` tag to
/// de-/serialize a `Rc<Vec<u8>>` type as a hex string. Nicer if you want human readable output.
pub mod serde_bytes_as_hex {

    use serde::de::Deserialize;
    use serde::{Deserializer, Serializer};

    pub fn serialize<'a, S>(t: &std::rc::Rc<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = hexutil::to_hex(t);
        s.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<std::rc::Rc<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        //let string = deserializer.deserialize_str()?.to_string();
        let string = String::deserialize(deserializer)?;
        let bytes =
            hexutil::read_hex(&string).map_err(|err| Error::custom(format!("{:?}", err)))?;
        Ok(std::rc::Rc::new(bytes))
    }
}

pub fn fuzzcase_from_yaml(input: &str) -> anyhow::Result<FuzzCase> {
    Ok(serde_yaml::from_str(input)?)
}

pub fn fuzzcase_to_yaml(input: &FuzzCase) -> String {
    serde_yaml::to_string(input).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    //use rand::prelude::*;

    #[test]
    fn yaml_serialize_unserialize_zeroed() {
        let fc = FuzzCase::zeroed();
        let yaml = fuzzcase_to_yaml(&fc);
        println!("got yaml:\n {}", yaml);
        let fcp = fuzzcase_from_yaml(&yaml).unwrap();

        assert_eq!(fc, fcp);
    }

    #[test]
    fn yaml_serialize_unserialize_default() {
        let fc = FuzzCase::default();
        let yaml = fuzzcase_to_yaml(&fc);
        println!("got yaml:\n {}", yaml);
        let fcp = fuzzcase_from_yaml(&yaml).unwrap();

        assert_eq!(fc, fcp);
    }

    #[test]
    fn pack_unpack_zeroed() {
        let fc = FuzzCase::zeroed();
        assert_eq!(fc.header, BlockHeader::default());
        assert_eq!(fc.txs.len(), 1);
        let x = pack_to_bytes(&fc);
        let fcp = parse_bytes(&x);
        println!("fc = {:#?}", fc);
        println!("fc' = {:#?}", fcp);
        assert_eq!(fcp.header, BlockHeader::default());
        assert_eq!(fcp.txs.len(), 1);
        assert_eq!(
            fcp.txs[0].header.sender_select,
            fc.txs[0].header.sender_select
        );
        assert_eq!(fc, fcp);
    }

    #[test]
    fn pack_unpack_empty() {
        let fc = FuzzCase::default();
        assert_eq!(fc.header, BlockHeader::default());
        assert_eq!(fc.txs.len(), 0);
        let x = pack_to_bytes(&fc);
        let fcp = parse_bytes(&x);
        assert_eq!(fc, fcp);
    }

    #[test]
    fn unpack_null_byte() {
        let testcase = [0u8; 1];
        let fc = parse_bytes(&testcase);
        println!("{:?}", fc);
        assert_eq!(fc.header, BlockHeader::default());
        assert_eq!(fc.txs.len(), 0);
    }

    #[test]
    fn pack_unpack_zeros() {
        const BLOCK_HEADER_LENGTH: usize = 8 * 5;
        //
        const TX_HEADER_LENGTH: usize = 1 + 8 + 2 + 1 + 1 + 3;
        const PACKED_LENGTH: usize = BLOCK_HEADER_LENGTH + TX_HEADER_LENGTH;
        let testcase = [0u8; PACKED_LENGTH];
        let parsed = parse_bytes(&testcase);
        println!("{:?}", parsed);
        print_fuzzcase(&parsed, None).unwrap();
        let packed = pack_to_bytes(&parsed);
        assert_eq!(testcase.len(), packed.len());
        assert_eq!(testcase[..], packed[..]);
    }

    #[test]
    fn pack_unpack_valued() {
        const BLOCK_HEADER_LENGTH: usize = 8 * 5;
        const TX_HEADER_LENGTH: usize = 1 + 8 + 2 + 1 + 1 + 3;
        const PACKED_LENGTH: usize = BLOCK_HEADER_LENGTH + TX_HEADER_LENGTH + 1;
        let mut testcase = [0u8; PACKED_LENGTH];
        // BlockHeader
        testcase[0] = 1;
        testcase[8] = 1;
        testcase[16] = 1;
        testcase[24] = 1;
        testcase[32] = 1;
        // first TransactionHeader
        testcase[40] = 1; // length
        testcase[40 + 1] = 0;
        testcase[40 + 2] = 0; // return count
        testcase[40 + 3] = 0; // pading 0
        testcase[40 + 4] = 1; // sender select
        testcase[40 + 5] = 1; // block_advance
        testcase[40 + 6] = 0; // padding 1
        testcase[40 + 7] = 0; // padding 1
        testcase[40 + 8] = 1; // call value
                              // input of first transaction
        testcase[40 + 16] = 1; // input
        let parsed = parse_bytes(&testcase);
        println!("{:?}", parsed);
        let packed = pack_to_bytes(&parsed);
        assert_eq!(testcase[..], packed[..]);
        assert_eq!(testcase.len(), packed.len());
    }

    #[test]
    fn test_repeated_parsing_packing() {
        let mut rng = rand_pcg::Pcg64Mcg::new(42);
        for length in &[0, 32, 128, 256, 512, 1024, 2048] {
            for _ in 0..256 {
                let randoms = (&mut rng).sample_iter(rand::distributions::Standard);
                let mut bytes: Vec<u8> = randoms.take(*length).collect();
                let mut fc: FuzzCase = parse_bytes(&bytes);
                let orig_fc = fc.clone();
                for _ in 0..6 {
                    fc = parse_bytes(&bytes);
                    assert_eq!(fc, orig_fc);
                    pack_into_bytes(&fc, &mut bytes);
                }
            }
        }
    }
}
