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

//! Type definition and core datastructures

//use packed_struct::prelude::*;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::default::Default;
use std::rc::Rc;

use zerocopy::{AsBytes, FromBytes, Unaligned};

/// Header for a single Transaction.
#[derive(
    FromBytes, AsBytes, Unaligned, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash,
)]
#[repr(packed)]
#[serde(default)]
pub struct TransactionHeader {
    // 1 + 8 + 2 + 1 + 1 == 13 (+ 3 == 16)
    /// the length must be synced with the length of the input vector before "serializing"
    pub length: u16, // offset 0
    pub return_count: u8, // offset 2
    pub receiver_select: u8,
    pub sender_select: u8, // offset 4
    pub block_advance: u8, // offset 5
    #[serde(skip)]
    padding1: [u8; 2], // offset 6
    pub call_value: u64,   // offset 8
}

impl Default for TransactionHeader {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl TransactionHeader {
    pub fn new(
        sender_select: u8,
        receiver_select: u8,
        call_value: u64,
        length: u16,
        block_advance: u8,
        return_count: u8,
    ) -> Self {
        Self {
            sender_select,
            receiver_select,
            call_value,
            length,
            block_advance,
            return_count,
            padding1: [0, 0],
        }
    }

    pub fn zeroed() -> Self {
        Self {
            sender_select: 0,
            receiver_select: 0,
            call_value: 0,
            length: 0,
            block_advance: 0,
            return_count: 0,
            padding1: [0, 0],
        }
    }

    pub fn clear_padding(&mut self) {
        self.padding1 = [0u8; 2];
    }

    pub fn get_sender_select(&self) -> u8 {
        self.sender_select
    }

    pub fn get_receiver_select(&self) -> u8 {
        self.receiver_select
    }

    pub fn get_block_advance(&self) -> u8 {
        self.block_advance
    }

    pub fn get_packed_call_value(&self) -> u64 {
        self.call_value
    }

    pub fn get_call_value(&self) -> crate::U256 {
        crate::normalize_call_value(self.call_value)
    }
}

/// Header for the initial Block parameters. This is only provided once at the start of a fuzzing
/// run.
#[derive(
    FromBytes, AsBytes, Unaligned, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash,
)]
#[repr(packed)]
#[serde(default)]
pub struct BlockHeader {
    pub number: u64,
    pub difficulty: u64,
    pub gas_limit: u64,
    pub timestamp: u64,
    pub initial_ether: u64,
}

#[allow(dead_code)]
impl BlockHeader {
    pub fn get_number(&self) -> u64 {
        self.number
    }
    pub fn get_difficulty(&self) -> u64 {
        self.difficulty
    }
    pub fn get_gas_limit(&self) -> u64 {
        self.gas_limit
    }
    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn get_initial_ether(&self) -> u64 {
        self.initial_ether
    }
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            number: 0,
            difficulty: 0,
            gas_limit: 0,
            timestamp: 0,
            initial_ether: 0,
        }
    }
}

#[derive(
    FromBytes, AsBytes, Unaligned, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash,
)]
#[repr(packed)]
#[serde(default)]
pub struct ReturnHeader {
    // 1 + 1 + 2 == 4
    pub value: u8,
    pub reenter: u8,
    pub data_length: u16,
}

impl Default for ReturnHeader {
    fn default() -> Self {
        Self {
            value: 0,
            reenter: 0,
            data_length: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(default)]
pub struct ReturnData {
    #[serde(flatten)]
    pub header: ReturnHeader,
    #[serde(with = "crate::serializer::serde_bytes_as_hex")]
    pub data: Rc<Vec<u8>>,
}

impl Default for ReturnData {
    /// Create an empty fuzzcase without any transactions at all.
    fn default() -> Self {
        Self {
            header: ReturnHeader::default(),
            data: Rc::new(vec![]),
        }
    }
}

/// A single Transaction consisting of a [`TransactionHeader`] and a Vec of input bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(default)]
pub struct Transaction {
    #[serde(flatten)]
    pub header: TransactionHeader,
    #[serde(with = "crate::serializer::serde_bytes_as_hex")]
    pub input: Rc<Vec<u8>>,
    pub returns: Vec<ReturnData>,
}

impl Default for Transaction {
    /// Create an empty fuzzcase without any transactions at all.
    fn default() -> Self {
        Self {
            header: TransactionHeader::default(),
            input: Rc::new(vec![]),
            returns: vec![],
        }
    }
}

impl Transaction {
    pub fn get_receiver(&self) -> usize {
        self.header.get_receiver_select() as usize
    }
}

/// A list of transactions, each consisting of the [`TransactionHeader`] and the respective input
/// bytes
pub type TransactionList = Vec<Transaction>;

/// the primary definition of the input format consumed by the harness: consists of the
/// [`BlockHeader`] followed by the [`TransactionList`]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Hash)]
#[serde(default)]
pub struct FuzzCase {
    #[serde(flatten)]
    pub header: BlockHeader,
    pub txs: TransactionList,
}

impl Default for FuzzCase {
    /// Create an empty fuzzcase without any transactions at all.
    fn default() -> Self {
        Self {
            header: BlockHeader::default(),
            txs: vec![],
        }
    }
}

impl FuzzCase {
    /// Create a minimal fuzzcase. This is a fuzzcase with a single transaction with all 0 initialized and 36 zero bytes as
    /// input + one return data mock with 32 zero bytes as return value.
    pub fn zeroed() -> FuzzCase {
        let bh = BlockHeader::default();
        let tx_input = [0u8; 32 + 4].to_vec();
        let mut tx_header = TransactionHeader::zeroed();
        tx_header.length = tx_input.len().try_into().unwrap();
        tx_header.return_count = 1;
        let tx_input = Rc::new(tx_input);
        const RET_LENGTH: usize = 32;
        let ret = ReturnData {
            header: ReturnHeader {
                data_length: RET_LENGTH as u16,
                reenter: 0,
                value: 1,
            },
            data: Rc::new(vec![0; RET_LENGTH]),
        };
        FuzzCase {
            header: bh,
            txs: vec![Transaction {
                header: tx_header,
                input: tx_input,
                returns: vec![ret],
            }],
        }
    }
}

/// This type represents what we need to know about a contracts ABI. This is primarily stored in the
/// [`ethabi::Contract`] struct. However, we also need to perform a quick lookup of u32/4byte
/// function sig to the corresponding [`ethabi::Function`] struct. Unfortunately the current API of
/// [`ethabi::Contract`] doesn't really allow this so we have to work around this by searching a
/// vector, which stores the [`ethabi::Function`] and the corresponding 4byte signature as `u32`.
pub type ContractInfo = (ethabi::Contract, Vec<(u32, ethabi::Function)>);
