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

//! ABI-aware mutation of smart contract transaction lists and related inputs.

/// version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION", "0-dev");

#[cfg(feature = "use_jemalloc")]
extern crate jemallocator;

#[cfg(not(any(feature = "use_mimalloc", feature = "use_mimalloc_secure")))]
#[cfg(not(feature = "use_snmalloc"))]
#[cfg(feature = "use_jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(not(feature = "use_jemalloc"))]
#[cfg(not(feature = "use_snmalloc"))]
#[cfg(any(feature = "use_mimalloc", feature = "use_mimalloc_secure"))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(not(feature = "use_jemalloc"))]
#[cfg(not(any(feature = "use_mimalloc", feature = "use_mimalloc_secure")))]
#[cfg(feature = "use_snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

extern crate ethabi;
extern crate hexutil;
extern crate libc;
//extern crate packed_struct;
//extern crate packed_struct_codegen;
extern crate rand;
extern crate rand_pcg;
extern crate sha3;
#[macro_use]
extern crate lazy_static;
extern crate anyhow;
extern crate ethereum_types;
extern crate rand_distr;
extern crate serde;

extern crate byte_slice_cast;

use anyhow::Context;
use ethabi::{param_type::ParamType, Address, Token};
pub use ethereum_types::{H160, U256};
use indexmap::set::IndexSet;
use rand::prelude::*;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::hash::BuildHasherDefault;
use std::rc::Rc;
use twox_hash::XxHash64;

mod cmptrace;
mod dictionary;
pub mod serializer;
mod stagelists;
pub mod trim;
mod types;
mod utils;

mod smallset;

pub mod instructions;

//#[cfg(any(test, bench))]
pub mod test_helpers;
#[cfg(test)]
mod tests;

pub use dictionary::Dictionary;
pub use serializer::{pack_into_bytes, pack_to_bytes, parse_bytes};
pub use trim::FuzzcaseTrimmer;
pub use types::*;
pub use utils::*;

pub use stagelists::*;

use smallset::SmallSet;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// helper function to quickly round up to the next power of two
/// http://graphics.stanford.edu/%7Eseander/bithacks.html#RoundUpPowerOf2
#[inline]
fn round_to_pow2(v: usize) -> usize {
    debug_assert!(v <= 256);
    let mut v = v - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    //v |= v >> 8;
    //v |= v >> 16;
    v + 1
}

#[inline]
fn useful_bit_size(bit_size: usize) -> usize {
    if bit_size == 0 {
        256
    } else {
        std::cmp::max(round_to_pow2(bit_size), 8)
    }
}

pub type ContractInfo = (ethabi::Contract, Vec<(u32, ethabi::Function)>);

pub fn load_abi_filepath(path: &std::path::Path) -> anyhow::Result<ContractInfo> {
    let file = std::fs::File::open(path)?;
    let contract = ethabi::Contract::load(file)
        .with_context(|| format!("failed to load ABI definition from file {}", path.display()))?;
    let functions = contract
        .functions()
        .cloned()
        .map(|f| {
            (
                {
                    let pt: Vec<_> = f.inputs.iter().map(|p| p.kind.clone()).collect();
                    short_signature(&f.name, &pt)
                },
                f,
            )
        })
        .collect();
    Ok((contract, functions))
}

pub fn load_abi_file(path: &std::ffi::OsStr) -> anyhow::Result<ContractInfo> {
    let path = std::path::Path::new(path);
    load_abi_filepath(path)
}

pub fn print_contract_abi(cinfo: &ContractInfo) {
    let contract = &cinfo.0;
    if let Some(constructor) = contract.constructor.as_ref() {
        let inputs = constructor
            .inputs
            .iter()
            .map(|p| p.kind.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!("constructor({})", inputs);
    }
    for (hexsig, func) in cinfo.1.iter() {
        println!(
            "{:#x} => {} {:?}",
            hexsig,
            func.signature(),
            func.state_mutability
        );
    }
    if contract.receive {
        println!("0x => receive() external");
    }
    if contract.fallback {
        println!("0x => fallback() external");
    }
}

// TODO: implement a proper token map type?
//struct TokenMap<T>([T; 10]);
//impl<T> TokenMap<T> {
//    fn from(init: T) -> Self {
//        TokenMap([init; 10])
//    }

//    fn get(&self) -> T {
//    }
//}
#[inline]
fn token_to_index(token: &Token) -> usize {
    match token {
        Token::Address(_) => 0,
        Token::Int(_) => 1,
        Token::Uint(_) => 2,
        Token::Bool(_) => 3,
        Token::Bytes(_) => 4,
        Token::Array(_) => 5,
        Token::Tuple(_) => 6,
        Token::String(_) => 7,
        Token::FixedArray(_) => 8,
        Token::FixedBytes(b) => (9 + b.len() - 1),
    }
}

lazy_static! {
/// list of valid transaction senders. Needs to be synced with the harness!
pub static ref TX_SENDER: [Address; 7] = [
    // valid sender in the fuzzing harness (users)
      Address::from_slice(&hexutil::read_hex("c04689c0c5d48cec7275152b3026b53f6f78d03d").unwrap()),
      Address::from_slice(&hexutil::read_hex("c1af1d7e20374a20d4d3914c1a1b0ddfef99cc61").unwrap()),
      Address::from_slice(&hexutil::read_hex("c2018c3f08417e77b94fb541fed2bf1e09093edd").unwrap()),
      Address::from_slice(&hexutil::read_hex("c3cf2af7ea37d6d9d0a23bdf84c71e8c099d03c2").unwrap()),
      Address::from_slice(&hexutil::read_hex("c4b803ea8bc30894cc4672a9159ca000d377d9a3").unwrap()),
      Address::from_slice(&hexutil::read_hex("c5442b23ea5ca66c3441e62bf6456f010646ae94").unwrap()),
      // (contract creator)
      Address::from_slice(&hexutil::read_hex("cc079239d48f83be71dbbd18487f4acc279ee929").unwrap()),
];
/// list of invalid transaction senders. Needs to be synced with the harness!
pub static ref INVALID_TX_SENDER: [Address; 3] = [
      // invalid senders
      Address::zero(),
      Address::from_slice(&hexutil::read_hex("ffffffffffffffffffffffffffffffffffffffff").unwrap()),
      Address::from_slice(&hexutil::read_hex("a2b0e2c57d7a1232a80b59354f5a3d49c19c6c4a").unwrap()),
];
/// list of some other addresses harcoded in the harness
pub static ref OTHER_ADDRESSES: [Address; 2] = [
      // default address of the target contract itself
      Address::from_slice(&hexutil::read_hex("0xdeadbeefc5d48cec7275152b3026b53f6f78d03d").unwrap()),
      // default address of a "friendly" (i.e., non-attacker controlled) second account
      Address::from_slice(&hexutil::read_hex("0xcf7c6611373327e75f8ef1beef8227afb89816dd").unwrap()),
];
}

/// number of sender accounts that are possible in the fuzzing harness
pub const HARNESS_MAX_SENDER: u8 = 7;
/// this is an arbitrarily set limit that solely exists to make trimming faster.
pub const HARNESS_MAX_RECEIVER: u8 = 20;

/// We will try to avoid reaching this limit when mutating, although it is not enforced by the
/// harness anymore.
pub const HARNESS_MAX_TX: usize = 64;
pub const HARNESS_HARD_MAX_TX: usize = 1024;

pub const HARNESS_PARAMETER_MAX_SIZE: usize = (1 << 16) - 1;

pub const HARNESS_MAX_RETURNS: usize = 255;
/// We also try to parse the input according to the ABI. However, some types (e.g., arrays) may
/// happen to become very big when the regular bitflipping fuzzer goes wild. So this defines a hard
/// limit where we do not attempt to decode anymore.
pub const MAX_INPUT_TRY_DECODE: usize = 1024 * 8;
pub const MAX_OUTPUT_TRY_DECODE: usize = 1024 * 2;

/// this must be synched with the harness!
const HARNESS_CALL_VALUE_SHIFT_BITS: usize = 18;

pub const U256_ZERO: U256 = U256::zero();
pub const U256_ONE: U256 = U256([1, 0, 0, 0]);

pub const EVM_WORD_SIZE: usize = 32;

pub const ONE_ETHER_WEI: u64 = 1000000000000000000;
pub const ONE_ETHER_SHIFT: u64 = ONE_ETHER_WEI >> 18;
pub const ETHER_SHIFT_BITMASK: u64 = 1u64 << 63;

/// default value for the compare tracing timeout
pub const DEFAULT_TRACE_TIMEOUT: u64 = 2;

const NULL_BYTES_12: &[u8; 12] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

lazy_static! {
    static ref ADD_VIEW_FUNCTION_ABI: bool = {
        match std::env::var("EM_ADD_VIEW_FUNCS") {
            Ok(val) => {
                val.starts_with('y')
                    || val.starts_with('Y')
                    || val.starts_with('1')
                    || val.starts_with('T')
                    || val.starts_with('t')
            }
            Err(_) => false,
        }
    };
    static ref ALLOW_COMPTRACE: bool = {
        match std::env::var("EM_ALLOW_COMPTRACE") {
            Ok(val) => {
                !(val.starts_with('n')
                    || val.starts_with('N')
                    || val.starts_with('0')
                    || val.starts_with('F')
                    || val.starts_with('f'))
            }
            Err(_) => true,
        }
    };
    static ref TRACE_TIMEOUT: u64 = {
        match std::env::var("EM_COMPTRACE_TIMEOUT") {
            Ok(val) => match val.parse() {
                Ok(i) => i,
                Err(e) => panic!("invalid value for `EM_COMPTRACE_TIMEOUT={}`: {}", val, e),
            },
            Err(_) => DEFAULT_TRACE_TIMEOUT,
        }
    };
}

pub fn normalize_call_value(c: u64) -> U256 {
    if c & ETHER_SHIFT_BITMASK != 0 {
        let val = U256::from(c ^ ETHER_SHIFT_BITMASK);
        val << HARNESS_CALL_VALUE_SHIFT_BITS
    } else {
        U256::from(c)
    }
}

pub fn call_value_add(a: u64, b: u64) -> u64 {
    if a == 0 || a == ETHER_SHIFT_BITMASK {
        return b;
    }
    if b == 0 || b == ETHER_SHIFT_BITMASK {
        return a;
    }
    if a & ETHER_SHIFT_BITMASK != 0 || b & ETHER_SHIFT_BITMASK != 0 {
        // transform into the shifted lower domain
        let a_s = std::cmp::max(
            (a & (!ETHER_SHIFT_BITMASK)) >> HARNESS_CALL_VALUE_SHIFT_BITS,
            1,
        );
        let b_s = std::cmp::max(
            (b & (!ETHER_SHIFT_BITMASK)) >> HARNESS_CALL_VALUE_SHIFT_BITS,
            1,
        );
        // add within the shifted domain
        let r = a_s.saturating_add(b_s);
        // make sure the bitshift marker is set
        r | ETHER_SHIFT_BITMASK
    } else {
        // add and make sure that the marker is not set
        a.saturating_add(b) & (!ETHER_SHIFT_BITMASK)
    }
}

type RngI = rand_pcg::Pcg64Mcg;

/// The mutator will randomly select one of these stages when mutating the [`FuzzCase`]
/// structure.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum TxListStage {
    /// Mutate the [`BlockHeader`] structure; check [`BlockHeaderMutationStage`] for further
    /// mutations
    MutateBlockHeader,
    /// Add some initial ether to the [`BlockHeader`]
    GiveSomeInitialEther,
    /// Append a new transaction
    AddTransaction,
    /// Insert a new transaction randomly into the sequence
    InsertTransaction,
    /// Remove the last transaction and add a newly generated transaction. Since the last
    /// transaction is most likely to be a transaction that `revert`s, it makes sense to replace
    /// this TX more often.
    ReplaceLastTransaction,
    /// Replace a randomly chosen TX in the sequence wit a new one
    ReplaceRandomTransaction,
    /// Duplicate a rand_pcg chosen TX. Somewhat superseede by
    /// [`TxListStage::DuplicateWithReentrancy`]
    DuplicateTransaction,
    /// Duplicate a randomly selected transaction and ensure that the second Transaction can be
    /// called via a reentrant call.
    DuplicateWithReentrancy,
    /// Shuffle all transactions
    ShuffleTransactions,
    /// swap two transactions
    SwapTransactions,
    /// Deduplicate consecutive calls to the same function. Sometimes this is counter-productive,
    /// sometimes not.
    DeduplicateByFunctionSig,
    /// Drop transactions that do not fit the ABI of the contract.
    DropLikelyUselessTransactions,
    /// Remove a random transaction from the TX list.
    DropRandomTransaction,
    /// Drop all transactions that call a certain function (i.e., select a random 4byte function
    /// hash from all the current TXs and drop every TX where the input starts with that identifier)
    DropOneFunction,
    /// Mutate a single randomly chosen transaction in the list; check [`TxStage`] for mutations on the Transaction
    MutateSingleTx,
    /// Mutate the last transaction in the list; check [`TxStage`] for mutations on the Transaction
    MutateLastTx,
    /// Same as [`MutateSingleTx`] but for all transactions in the list
    MutateAllTx,
    /// insert a single transaction from another testcase
    SpliceTxFromQueue,
    /// insert a single transaction from multiple different testcases
    SpliceTxFromQueueMulti,
    /// splice a randomly chosen sub sequence from a different testcase. This overwrites a randomly
    /// chosen sub sequence of the current TX sequence.
    SpliceTxListFromQueue,
    /// Add some simple return value mocks to all the transactions
    AddReturnMocks,
    /// Apply mutations to many transactions, where the index of the transaction determines the
    /// likelyhood that a transaction is mutated.
    OnlyMutateManyTx,
    /// Randomly stack multiple other mutation operations
    StackedHavocMany,
    /// Propagate values between transactions according to the ABI, e.g., if `TX[0]` and `TX[1]` both have a parameter of
    /// type `address` set them both to the same value (of `TX[0]`)
    PropagateValuesInTransactions,
    /// Search through a parameter that looks like an known address of an attacker controlled
    /// account and set the sender value of following transactions accordingly.
    PropagateSenderInTransactions,
    /// run custom evm-level cmptrace stage
    ObtainCmpTrace,
}

/// This essentially defines how often a mutation stage is selected when choosing one at random.
/// Note that we intentionally exclude some stages here.
impl Distribution<TxListStage> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TxListStage {
        match rng.gen_range(0..=52) {
            0 => TxListStage::DropLikelyUselessTransactions,
            1 => TxListStage::ShuffleTransactions,
            2 => TxListStage::DeduplicateByFunctionSig,
            3 => TxListStage::MutateBlockHeader,
            4 => TxListStage::AddReturnMocks,
            5 => TxListStage::OnlyMutateManyTx,
            6 | 7 => TxListStage::DuplicateWithReentrancy,
            // Duplicating with Reentrancy is only a minor overhead compared to duplicating without,
            // so always do it with reentrancy. The additional return mocks can be trimmed/reduced
            // afterwards anyway.
            //8 => TxListStage::DuplicateTransaction,
            8 | 9 | 10 | 11 | 12 | 13 | 14 => TxListStage::MutateSingleTx,
            15 | 16 | 17 => TxListStage::SwapTransactions,
            18 | 19 | 20 | 21 | 22 => TxListStage::SpliceTxFromQueue,
            23 | 24 | 25 => TxListStage::SpliceTxListFromQueue,
            26 | 27 | 28 | 29 => TxListStage::InsertTransaction,
            30 | 31 | 32 | 33 | 34 => TxListStage::AddTransaction,
            35 | 36 | 37 | 38 => TxListStage::ReplaceLastTransaction,
            39 | 40 | 41 | 42 | 43 | 44 => TxListStage::MutateLastTx,
            45 | 46 => TxListStage::ReplaceRandomTransaction,
            47 => TxListStage::SpliceTxFromQueueMulti,
            48 => TxListStage::PropagateValuesInTransactions,
            49 => TxListStage::PropagateSenderInTransactions,
            50 => TxListStage::DropRandomTransaction,
            51 => TxListStage::DropOneFunction,
            52 => TxListStage::StackedHavocMany,

            // likely only useful in smaller tx sequences.
            // => TxListStage::MutateAllTx

            // should only be triggered manually for every new fuzzcase in the queue
            // => TxListStage::ObtainCmpTrace,

            // This is also somewhat covered by BlockHeader mutations and is only used as a
            // deterministic stage to apply at the beginning of every fuzzing round
            // => TxListStage::GiveSomeInitialEther,

            // else
            _ => panic!("Distribution<TxListStage>::sample invalid integer sampled"),
        }
    }
}

/// The mutator will randomly select one of these mutations when
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum TxStage {
    /// if callvalue > 0 set to 0; else set to random value > 0
    FlipCallValue,
    /// change the caller of the transaction
    MutateCaller,
    /// mutate the input
    MutateTransactionInput,
    /// mutate the block advance field
    MutateBlockAdvance,
    /// Flip the value of reenter
    FlipReenter,
    /// Mutate the potential return values
    MutateTransactionReturns,
    MutateTransactionReturnData,
}

impl Distribution<TxStage> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TxStage {
        match rng.gen_range(0..=15) {
            0 | 1 | 2 | 3 | 4 | 5 | 6 => TxStage::MutateTransactionInput,
            7 | 8 => TxStage::FlipCallValue,
            9 | 10 => TxStage::MutateCaller,
            11 => TxStage::MutateBlockAdvance,
            12 | 13 => TxStage::FlipReenter,
            14 => TxStage::MutateTransactionReturns,
            15 | 16 => TxStage::MutateTransactionReturnData,
            _ => panic!("Distribution<TxStage>::sample invalid integer sampled"),
        }
    }
}

/// Select a random mutation to apply to the input part of the transaction. Only relevant when no
/// ABI definition is available.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum InputMutationStage {
    AddParameter,
    RemoveParameter,
    ShuffleParameter,
    ChangeParameter,
    HugeEmptyInput,
}

/// When mutating input we mostly want to change parameters.
impl Distribution<InputMutationStage> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> InputMutationStage {
        match rng.gen_range(0..=10) {
            0 | 1 => InputMutationStage::AddParameter,
            2 => InputMutationStage::RemoveParameter,
            3 | 4 | 5 | 6 | 7 | 8 => InputMutationStage::ChangeParameter,
            9 => InputMutationStage::ShuffleParameter,
            10 => InputMutationStage::HugeEmptyInput,
            _ => panic!("Distribution<InputMutationStage>::sample invalid integer sampled"),
        }
    }
}

/// Primarily used to choose which field of the [`BlockHeader`] is mutated.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum BlockHeaderMutationStage {
    /// randomly assign the block number somewhere in the range 0..20_000_000 or so; seems sensible
    Number,
    /// randomly assign the difficulty
    Difficulty,
    /// randomly assign the gaslimit (doesn't matter much, because our harness EVM doesn't track gas)
    GasLimit,
    /// random timestamp
    RandomTimeStamp,
    /// sensible timestamp between first Ethereum release and ~20 years in the future
    SensibleTimeStamp,
    /// mutate the initial ether balance as specified in the block header
    InitialEtherBalance,
}

impl Distribution<BlockHeaderMutationStage> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BlockHeaderMutationStage {
        match rng.gen_range(0..=6) {
            0 => BlockHeaderMutationStage::Number,
            1 => BlockHeaderMutationStage::Difficulty,
            2 => BlockHeaderMutationStage::GasLimit,
            3 => BlockHeaderMutationStage::RandomTimeStamp,
            4 => BlockHeaderMutationStage::SensibleTimeStamp,
            // initial ether balance is more important
            5 | 6 => BlockHeaderMutationStage::InitialEtherBalance,
            _ => panic!("Distribution<BlockHeaderMutationStage>::sample invalid integer sampled"),
        }
    }
}

/// list of integer widths supported by the Ethereum ABI
static INT_SIZES: [usize; 6] = [8, 16, 32, 64, 128, 256];

/// Module that defines some inline functions that give sensible sizes for various ABI types.
mod rand_size {
    use super::{Rng, INT_SIZES};

    #[inline]
    pub fn int<R: Rng + ?Sized>(rng: &mut R) -> usize {
        INT_SIZES[rng.gen_range(0..INT_SIZES.len())]
    }

    #[inline]
    pub fn array<R: Rng + ?Sized>(rng: &mut R) -> usize {
        rng.gen_range(0..=9)
    }

    const MAX_BYTES_SIZE: usize = 128;
    const HUGE_BYTES_BUCKETS: usize = 8;

    #[inline]
    pub fn bytes<R: Rng + ?Sized>(rng: &mut R) -> usize {
        let x = rng.gen_range(0..=(MAX_BYTES_SIZE + HUGE_BYTES_BUCKETS));
        if x <= MAX_BYTES_SIZE {
            x
        } else {
            MAX_BYTES_SIZE * (x + 1 - MAX_BYTES_SIZE)
        }
    }

    #[inline]
    pub fn tuple<R: Rng + ?Sized>(rng: &mut R) -> usize {
        rng.gen_range(0..=5)
    }

    const MAX_STRING_SIZE: usize = 128;
    const HUGE_STRING_BUCKETS: usize = 8;

    #[inline]
    pub fn string<R: Rng + ?Sized>(rng: &mut R) -> usize {
        let x = rng.gen_range(0..=(MAX_STRING_SIZE + HUGE_STRING_BUCKETS));
        if x <= MAX_STRING_SIZE {
            x
        } else {
            MAX_STRING_SIZE * (x + 1 - MAX_STRING_SIZE)
        }
    }
}

/// This is probably quite important when fuzzing without an ABI definition and irrelevant when
/// fuzzing with ABI. This defines the "weight" of the different ABI types. We do this to select
/// some types, that the author perceived to be more common, more often than other more exotic
/// types. Every weight corresponds to one of the [`ParamTypeSelector`] variants. The function
/// [`ParamTypeSelector::from_index_and_rng`] maps from an integer to the actual
/// [`ParamTypeSelector`] variant. The function [`ParamTypeSelector::from_rng`] samples the integer
/// index according to the weights defined in this array.
static TYPE_SELECTOR_WEIGHTS: [usize; 10] = [1, 9, 8, 10, 1, 3, 1, 1, 1, 1];
lazy_static! {
    static ref TYPE_SELECTOR_DIST: rand_distr::WeightedAliasIndex<usize> =
        rand_distr::WeightedAliasIndex::new(TYPE_SELECTOR_WEIGHTS.to_vec()).unwrap();
}

/// "Wrapper" around [`ethabi::param_type::ParamType`], which has a bit more information, e.g., it
/// also contains sizes for dynamicallly sized abi types. This type can be easily constructed from
/// an RNG (see [`ParamTypeSelector::from_rng`]).
#[derive(Debug, PartialEq, Clone)]
pub enum ParamTypeSelector {
    /// weight index 0; weight 1 (small weight, because encoded bool is 1/0, which is also produced
    /// by unsigned integer with high probability)
    Bool,
    /// weight index 1; weight 9
    Address,
    /// weight index 2; weight 8
    Integer(usize),
    /// weight index 3; weight 10
    UnsignedInteger(usize),
    /// weight index 4; weight 1
    String,
    /// weight index 5; weight 3
    Array(usize, Box<ParamTypeSelector>),
    /// weight index 6; weight 1
    FixedArray(usize, Box<ParamTypeSelector>),
    /// weight index 7; weight 1
    Bytes(usize),
    /// weight index 8; weight 1
    FixedBytes(usize),
    /// weight index 9; weight 1
    Tuple(Vec<ParamTypeSelector>),
}

impl ParamTypeSelector {
    fn from_index_and_rng<R: Rng + ?Sized>(index: usize, rng: &mut R) -> ParamTypeSelector {
        match index {
            0 => ParamTypeSelector::Bool,
            1 => ParamTypeSelector::Address,
            2 => ParamTypeSelector::Integer(rand_size::int(rng)),
            3 => ParamTypeSelector::UnsignedInteger(rand_size::int(rng)),
            4 => ParamTypeSelector::String,
            5 => ParamTypeSelector::Array(
                rand_size::array(rng),
                Box::new(ParamTypeSelector::from_rng(rng)),
            ),
            6 => ParamTypeSelector::FixedArray(
                rand_size::array(rng),
                Box::new(ParamTypeSelector::from_rng(rng)),
            ),
            7 => ParamTypeSelector::Bytes(rand_size::bytes(rng)),
            8 => ParamTypeSelector::FixedBytes(rand_size::bytes(rng)),
            9 => {
                let sz = rand_size::tuple(rng);
                let mut v: Vec<ParamTypeSelector> = Vec::with_capacity(sz);
                for _ in 0..sz {
                    v.push(ParamTypeSelector::from_rng(rng));
                }
                ParamTypeSelector::Tuple(v)
            }
            _ => panic!("unreachable"),
        }
    }

    fn from_rng<R: Rng + ?Sized>(rng: &mut R) -> ParamTypeSelector {
        let selected_ptype_index = TYPE_SELECTOR_DIST.sample(rng);
        ParamTypeSelector::from_index_and_rng(selected_ptype_index, rng)
    }

    fn from_paramtype_and_rng<R: Rng + ?Sized>(
        paramtype: &ParamType,
        rng: &mut R,
    ) -> ParamTypeSelector {
        match paramtype {
            ParamType::Bool => ParamTypeSelector::Bool,
            ParamType::Address => ParamTypeSelector::Address,
            ParamType::Int(sz) => ParamTypeSelector::Integer(*sz),
            ParamType::Uint(sz) => ParamTypeSelector::UnsignedInteger(*sz),
            ParamType::String => ParamTypeSelector::String,
            ParamType::Bytes => ParamTypeSelector::Bytes(rand_size::bytes(rng)),
            ParamType::FixedBytes(sz) => ParamTypeSelector::FixedBytes(*sz),
            ParamType::Array(t) => ParamTypeSelector::Array(
                rand_size::array(rng),
                Box::new(ParamTypeSelector::from_paramtype_and_rng(t, rng)),
            ),
            ParamType::FixedArray(t, sz) => ParamTypeSelector::FixedArray(
                *sz,
                Box::new(ParamTypeSelector::from_paramtype_and_rng(t, rng)),
            ),
            ParamType::Tuple(types) => {
                let mut v: Vec<ParamTypeSelector> = Vec::with_capacity(types.len());
                for t in types.iter() {
                    v.push(ParamTypeSelector::from_paramtype_and_rng(t, rng));
                }
                ParamTypeSelector::Tuple(v)
            }
        }
    }
}

impl Into<ethabi::param_type::ParamType> for ParamTypeSelector {
    fn into(self) -> ethabi::param_type::ParamType {
        match self {
            ParamTypeSelector::Bool => ParamType::Bool,
            ParamTypeSelector::Address => ParamType::Address,
            ParamTypeSelector::Integer(sz) => ParamType::Int(sz),
            ParamTypeSelector::UnsignedInteger(sz) => ParamType::Uint(sz),
            ParamTypeSelector::String => ParamType::String,
            ParamTypeSelector::Bytes(_) => ParamType::Bytes,
            ParamTypeSelector::Array(_sz, t) => ParamType::Array(Box::new((*t).into())),
            ParamTypeSelector::FixedArray(sz, t) => {
                ParamType::FixedArray(Box::new((*t).into()), sz)
            }
            ParamTypeSelector::FixedBytes(sz) => ParamType::FixedBytes(sz),
            ParamTypeSelector::Tuple(types) => {
                ParamType::Tuple(types.into_iter().map(|x| x.into()).collect())
            }
        }
    }
}

impl Distribution<ParamTypeSelector> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ParamTypeSelector {
        let index = rng.gen_range(0..=9);
        ParamTypeSelector::from_index_and_rng(index, rng)
    }
}

/// This is used to provide some insights into the mutations without causing too much runtime
/// overhead. For every type of mutation we push an enum into a Vec. See [`EthMutator.stages`].
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum MutationStageLog {
    List(TxListStage),
    Tx(TxStage),
    Input(InputMutationStage),
    BlockHeader(BlockHeaderMutationStage),
    Dictionary,
    Abi,
}

#[derive(Debug, Copy, Clone)]
struct TestcaseStats {
    fuzzed_count: usize,
    obtained_cmp_logs: bool,
}
impl TestcaseStats {
    //fn new() -> Self {
    //    Self::default()
    //}

    fn default() -> Self {
        Self {
            fuzzed_count: 0,
            obtained_cmp_logs: false,
        }
    }
}

/// iterates over the fuzzcase an checks whether we have not created an excessive amount of data
/// somewhere.
fn ensure_reasonable_fuzzcase(fc: &mut FuzzCase) {
    fc.txs.truncate(HARNESS_HARD_MAX_TX);
    for tx in fc.txs.iter_mut() {
        if tx.input.len() >= HARNESS_PARAMETER_MAX_SIZE {
            let input = if let Some(x) = Rc::get_mut(&mut tx.input) {
                x
            } else {
                Rc::make_mut(&mut tx.input)
            };
            input.truncate(HARNESS_PARAMETER_MAX_SIZE);
            tx.header.length = HARNESS_PARAMETER_MAX_SIZE as u16;
        }
        tx.returns.truncate(255);
        tx.header.return_count = tx.returns.len() as u8;
        tx.header.length = tx.input.len() as u16;
        for ret in tx.returns.iter_mut() {
            if ret.data.len() >= HARNESS_PARAMETER_MAX_SIZE {
                let retdata = if let Some(x) = Rc::get_mut(&mut ret.data) {
                    x
                } else {
                    Rc::make_mut(&mut ret.data)
                };
                retdata.truncate(HARNESS_PARAMETER_MAX_SIZE);
            }
        }
    }
}

// TODO: encapsulate all ABI-specific things in this struct. Prepare the remainder ofthe code for multi-abi-target support.
#[derive(Clone)]
pub struct Contract {
    abi: ethabi::Contract,
    functions: Vec<(u32, ethabi::Function)>,
    funcsigs: Vec<u32>,
}

impl Contract {
    pub fn new(abi: ethabi::Contract, functions: Vec<(u32, ethabi::Function)>) -> Self {
        let mut funcsigs: Vec<u32> = functions.iter().map(|(x, _)| *x).collect();
        let mut functions = functions;
        functions.sort_unstable_by_key(|x| x.0);
        funcsigs.sort_unstable();
        Contract {
            abi,
            functions,
            funcsigs,
        }
    }

    #[inline]
    pub fn has_fallback_or_receive(&self) -> bool {
        self.abi.fallback || self.abi.receive
    }
}

/// This is the main struct of the mutator that encapsulates all the state needed to operate as part
/// of a fuzzing setup.
#[derive(Clone)]
pub struct EthMutator {
    /// whether the mutator is allowed to perform some println's
    pub allow_prints: bool,
    /// whether the mutator will allow ABI functions with view/pure state mutability
    pub allow_view_funcs: bool,
    /// whether the mutator is allowed to launch the binary in the value tracing mode to obtain
    /// values used in comparison and return instructions.
    pub allow_comptrace: bool,
    /// Contains the final testcase packed to bytes; reference to this is passed to the fuzzer for
    /// processing - or can be written to a file; whatever floats your boat.
    ///
    /// Note that the current design is inherently single-threaded. We assume this buffer is not
    /// touched until the testcase was processed.
    buffer: Vec<u8>,
    /// This is our source for randomness
    rng: RngI,
    /// Parsed contract ABI if available
    // contract: Option<Rc<ContractInfo>>,
    contracts: Vec<Rc<Contract>>,
    contract_funcsigs: Vec<u32>,
    /// log of the mutation stages we applied
    stages: Vec<MutationStageLog>,
    /// keep a CString around; e.g., if AFL++ ask for one we can return a pointer to this string
    stages_as_string: Option<CString>,
    /// Use to communicate the stages in a compact form to AFL++
    describe_string: [u8; 48],
    /// for trimming support see [`FuzzcaseTrimmer`]
    trimmer: Option<FuzzcaseTrimmer>,
    trim_buffer: Vec<u8>,
    trim_start_time: std::time::Instant,

    /// here we keep all transaction lists from prior testcases around. This roughly maps to the
    /// queue that AFL++ keeps. We fill it with every new entry. This allows us to perform custom
    /// splicing operations with interesting fuzzcases.
    queue: IndexSet<TransactionList, BuildHasherDefault<XxHash64>>,
    /// Dictionary to get knowns interesting values
    dict: Dictionary,

    testcase_info: HashMap<CString, TestcaseStats, BuildHasherDefault<XxHash64>>,
    cur_filename: Option<CString>,
    cur_binary_path: Option<CString>,
    cur_fuzzcase: Option<FuzzCase>,
    //round_stages: Box<dyn Iterator(TxListStage)>,
    round_stages: std::iter::Take<std::iter::Cycle<std::slice::Iter<'static, TxListStage>>>,

    cur_tx_idx: Option<usize>,
    tx_round_stages: std::iter::Take<std::iter::Cycle<std::slice::Iter<'static, TxStage>>>,

    /// we use this to quickly add 32 zero bytes as a return value without allocating a new Vec
    bytes32_zero: Rc<Vec<u8>>,
    bytes32_one: Rc<Vec<u8>>,
}

impl Default for EthMutator {
    fn default() -> Self {
        EthMutator::new()
    }
}

impl EthMutator {
    /// New mutator with default values.
    ///
    /// We initialize the dictionary with various interesting/useful values, such as the maximum
    /// integers to provoke overflows; a fixed string/bytes to handle arbitrary identifiers
    pub fn new<'a>() -> EthMutator {
        // dictionary init
        let mut d = Dictionary::new();
        d.populate_with_interesting_values();

        let allow_prints = if let Some(val) = std::env::var_os("AFL_NO_UI") {
            val == "1"
        } else {
            false
        };

        if allow_prints {
            println!("[EthMutator] initialized with dictionary {}", d.stats());
        }

        // default value
        EthMutator {
            buffer: vec![],
            rng: rand::SeedableRng::seed_from_u64(0),
            // contract: None,
            contracts: vec![],
            contract_funcsigs: vec![],
            stages: Vec::with_capacity(64),
            stages_as_string: None,
            describe_string: *b"EM-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\x00",
            trimmer: None,
            trim_buffer: vec![],
            trim_start_time: std::time::Instant::now(),
            queue: IndexSet::with_capacity_and_hasher(
                256,
                BuildHasherDefault::<XxHash64>::default(),
            ),
            dict: d,

            testcase_info: Default::default(),
            cur_filename: None,
            cur_fuzzcase: None,
            cur_binary_path: None,
            cur_tx_idx: None,
            round_stages: DEFAULT_STAGES_NONE.iter().cycle().take(0),
            tx_round_stages: DEFAULT_TX_STAGES_NONE.iter().cycle().take(0),
            allow_prints,
            allow_view_funcs: *ADD_VIEW_FUNCTION_ABI,
            allow_comptrace: *ALLOW_COMPTRACE,
            bytes32_zero: Rc::new(vec![0u8; 32]),
            bytes32_one: Rc::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ]),
        }
    }

    /// Construct the Mutator with a given ABI definition file
    pub fn from_abi_file<'a>(path: &std::ffi::OsStr) -> anyhow::Result<EthMutator> {
        let mut mutator = Self::new();

        let (abi, functions) = load_abi_file(path)?;
        let contract = Contract::new(abi, functions);

        mutator.contract_funcsigs = contract.functions.iter().map(|(x, _)| *x).collect();
        mutator.contract_funcsigs.sort_unstable();
        mutator.contracts.push(Rc::new(contract));

        if mutator.allow_prints {
            println!(
                "[EthMutator] loaded contract ABI with {} functions",
                mutator.contract_funcsigs.len()
            );
        }

        anyhow::Result::Ok(mutator)
    }

    pub fn from_multi_abi_file<'a>(
        abipaths: Vec<std::ffi::OsString>,
    ) -> anyhow::Result<EthMutator> {
        let mut mutator = Self::new();
        for path in abipaths.into_iter() {
            let (abi, functions) = load_abi_file(&path)?;
            let contract = Contract::new(abi, functions);
            mutator.contract_funcsigs.extend(contract.funcsigs.iter());

            if mutator.allow_prints {
                println!(
                    "[EthMutator] loaded contract ABI with {} functions from {:?}",
                    contract.funcsigs.len(),
                    path
                );
            }

            mutator.contracts.push(Rc::new(contract));
        }

        // need to make sure the list of all function sigs is sorted s.t., we can later do efficient
        // binary search.
        mutator.contract_funcsigs.sort_unstable();

        anyhow::Result::Ok(mutator)
    }

    /// Update the internal seed of the random number generator. Usually this is passed to us by the
    /// fuzzer.
    pub fn seed(&mut self, seed: u64) {
        self.rng = rand::SeedableRng::seed_from_u64(seed)
    }

    pub fn get_contract(&self, cidx: usize) -> Option<Rc<Contract>> {
        if self.contracts.is_empty() {
            None
        } else {
            let i = cidx % self.contracts.len();
            Some(self.contracts[i].clone())
        }
    }

    /// Select a random address - since in our test harness only a small (fixed) set of addresses
    /// are plausible. With p = 0.7 try to sample from dictionary (uniformly at random). In 0.8 of
    /// the cases we return a valid address, very rarely we also create the address of the creator,
    /// the contract itself, or some other misc address hard-coded in the harnes and in the rest we
    /// return an invalid address.
    fn create_random_address(&mut self) -> Address {
        if self.dict.has_address() && self.rng.gen_bool(0.5) {
            self.log(MutationStageLog::Dictionary);
            self.dict.sample_address(&mut self.rng)
        } else if self.rng.gen_bool(0.8) {
            let i = self.rng.gen_range(0..(TX_SENDER.len()));
            TX_SENDER[i]
        } else if self.rng.gen_bool(0.01) {
            let i = self.rng.gen_range(0..(OTHER_ADDRESSES.len()));
            OTHER_ADDRESSES[i]
        } else {
            let i = self.rng.gen_range(0..(INVALID_TX_SENDER.len()));
            INVALID_TX_SENDER[i]
        }
    }

    /// Select a random integer value using the following criteria:
    ///
    /// * return a zero valued integer and let the normal mutations do their job
    /// * return a one valued integer and let the normal mutations do their job
    /// * return (1 << s), where 0 <= s < 256, selected at random; the idea here is that we can
    ///   quickly explore different magnitudes and bypass checks like "if (value_arg > BIG_NUMBER)
    ///   ..."
    /// * return a dictionary integer (i.e., to bypass magic value comparison)
    /// * return a dictionary integer and either add or subtract one
    /// * small integer in the range (2, 32]
    /// * sample 64-bit constants with higher probability (i.e., timestamp or block number)
    ///
    /// if signed is set, roughly 50% of the values will be in the negative range
    ///
    fn create_random_integer(&mut self, bit_size: usize, signed: bool) -> U256 {
        let bit_size = useful_bit_size(bit_size);
        let v = match self.rng.gen_range(0..=8) {
            0 => U256_ZERO,
            1 => U256_ONE,
            2 => {
                let s: usize = self.rng.gen_range(1..bit_size);
                U256_ONE << s
            }
            3 | 4 => {
                self.log(MutationStageLog::Dictionary);
                self.dict.sample_bitsize(bit_size, &mut self.rng)
            }
            5 | 6 => {
                self.log(MutationStageLog::Dictionary);
                let v = self.dict.sample_bitsize(bit_size, &mut self.rng);
                if self.rng.gen_bool(0.5) {
                    v.overflowing_add(U256_ONE).0
                } else {
                    v.overflowing_sub(U256_ONE).0
                }
            }
            7 => {
                let s: usize = self.rng.gen_range(2..32);
                U256::from(s)
            }
            8 => {
                // sample a 64 bit constant with higher probability for larger datatypes
                // the idea is that we want to pass some timestamp or block numbers
                self.log(MutationStageLog::Dictionary);
                // if a smaller than 64-bit type is requested, we satisfy this.
                let bit_size = std::cmp::min(bit_size, 64);
                let v = self.dict.sample_bitsize(bit_size, &mut self.rng);
                match self.rng.gen_range(0..=2) {
                    0 => v,
                    1 => v.overflowing_add(U256_ONE).0,
                    2 => v.overflowing_sub(U256_ONE).0,
                    _ => panic!("gen_range out of range"),
                }
            }
            _ => panic!("gen_range out of range"),
        };
        if signed && !v.is_zero() {
            if self.rng.gen_bool(0.5) {
                U256_ZERO.overflowing_sub(v).0
            } else {
                v
            }
        } else {
            v
        }
    }

    /// create a random string (length 0..=129); with p = 0.75 try to sample from dictionary
    fn create_random_string(&mut self) -> String {
        if self.dict.has_string() && self.rng.gen_bool(0.75) {
            if let Some(s) = self.dict.sample_string(&mut self.rng) {
                self.log(MutationStageLog::Dictionary);
                return s;
            }
        }
        let length = rand_size::string(&mut self.rng);
        let chars: String = std::iter::repeat(())
            .map(|()| (&mut self.rng).sample(rand::distributions::Alphanumeric))
            .map(char::from)
            .take(length)
            .collect();
        chars
    }

    fn mutate_string(&mut self, s: &str) -> String {
        if s.is_empty() {
            self.create_random_string()
        } else {
            let mut s = s.to_string();
            if s.len() > 16 && self.rng.gen_bool(0.5) {
                // replace parts of string with AAAAA...
                let mut start = self.rng.gen_range(0..(s.len() - 2));
                while !s.is_char_boundary(start) {
                    start -= 1;
                }
                let mut end = self.rng.gen_range((start + 1)..s.len());
                while !s.is_char_boundary(end) {
                    end += 1;
                }
                let repl = "A".repeat(end - start);
                s.replace_range(start..end, &repl);
            } else {
                // truncate or extend string
                let by_len = self.rng.gen_range(0..=s.len());
                if self.rng.gen_bool(0.5) {
                    let mut truncate_to_length = s.len() - by_len;
                    while !s.is_char_boundary(truncate_to_length) {
                        truncate_to_length -= 1;
                    }
                    s.truncate(truncate_to_length);
                } else {
                    s.push_str(&"A".repeat(by_len));
                }
            }
            s
        }
    }

    fn mutate_fixed_bytes(&mut self, s: &[u8]) -> Vec<u8> {
        if s.is_empty() {
            // what? can this happen?
            s.to_vec()
        } else {
            let mut s = s.to_vec();
            if s.len() > 8 && self.rng.gen_bool(0.5) {
                // replace parts of string with AAAAA... or \x0000000...
                let start = self.rng.gen_range(0..(s.len() - 2));
                let end = self.rng.gen_range((start + 1)..s.len());
                let repl = match self.rng.gen_range(0..=2) {
                    0 => *b"A",
                    1 => *b"\x00",
                    _ => {
                        let v: u8 = self.rng.gen();
                        [v; 1]
                    }
                }
                .repeat(end - start);
                s.splice(start..end, repl.into_iter()).collect()
            } else if self.rng.gen_bool(0.1) {
                s.into_iter()
                    .map(|x| {
                        let xorval: u8 = self.rng.gen();
                        x ^ xorval
                    })
                    .collect()
            } else {
                let xorval: u8 = self.rng.gen();
                s.into_iter().map(|x| x ^ xorval).collect()
            }
        }
    }

    fn mutate_bytes(&mut self, s: &[u8]) -> Vec<u8> {
        if s.is_empty() {
            self.create_random_bytes(None)
        } else if s.len() > 16 && self.rng.gen_bool(0.7) {
            self.mutate_fixed_bytes(s)
        } else {
            let mut s = s.to_vec();
            // truncate or extend string up to double the length
            let by_len = self.rng.gen_range(0..=s.len());
            if self.rng.gen_bool(0.5) {
                s.truncate(s.len() - by_len);
            } else {
                s.extend(
                    if self.rng.gen_bool(0.5) {
                        b"A"
                    } else {
                        b"\x00"
                    }
                    .repeat(by_len),
                );
            }
            s
        }
    }

    /// create a random byte string of given length, if None is given choose lenght uniformly from
    /// range 0..=length; with p = 0.75 try to sample from dictionary.
    /// When sampling from dictionary choose one of three options:
    /// if length is given
    /// * try to sample bytestring with exact length from dictionary
    /// * otherwise with p = 0.5
    ///     * return fixed bytestring for given length
    ///     * sample single bytes from dictionary up to length
    ///
    /// if length is not given
    /// * try to sample some arbitrary bytestring from dictionary with p = 0.8
    /// * otherwise with p = 0.5
    ///     * return some bytestring from the dictionary
    ///       (note that we always have a at least one 32 byte bytestring in the dictionary)
    ///     * sample single bytes from dictionary for a random length in 4..=129
    ///
    /// if dictionary is not selected; sample `length` or [`rand_size::bytes`] random bytes.
    fn create_random_bytes(&mut self, length: Option<usize>) -> Vec<u8> {
        if self.rng.gen_bool(0.75) {
            if let Some(len) = length {
                // first we check whether the dictionary contains a constant for exactly the length
                // we need. The idea is that it is very likely that this is some important constant
                // or identifier.
                if self.dict.has_bytes() && self.rng.gen_bool(0.8) {
                    if let Some(bytes) = self.dict.sample_bytes_exact(len, &mut self.rng) {
                        self.log(MutationStageLog::Dictionary);
                        let bytes = Vec::from(bytes);
                        return bytes;
                    }
                }

                // otherwise we try a different strategy:
                // * repeat a fixed byte for exactly the required length
                // * sample arbitrary bytes from the integer values we know.
                self.log(MutationStageLog::Dictionary);
                return if self.rng.gen_bool(0.9) {
                    // dynamically create a fixed Token of the given length
                    let bytes: Vec<u8> = std::iter::repeat(b'\x3c').take(len).collect();
                    bytes
                } else {
                    let mut v = Vec::with_capacity(len);
                    for _ in 0..len {
                        v.push(self.dict.sample_1byte(&mut self.rng));
                    }
                    v
                };
            } else {
                if self.rng.gen_bool(0.5) {
                    // note that normally this call will never return None, since we always add a
                    // fixed bytestring to the dictionary.
                    if let Some(bytes) = self.dict.sample_bytes(&mut self.rng) {
                        self.log(MutationStageLog::Dictionary);
                        return bytes.to_vec();
                    }
                }
                if self.rng.gen_bool(0.1) {
                    let l = rand_size::bytes(&mut self.rng);
                    let mut v = Vec::with_capacity(l);
                    for _ in 0..l {
                        v.push(self.dict.sample_1byte(&mut self.rng));
                    }
                    self.log(MutationStageLog::Dictionary);
                    return v;
                }

                // else fall back to random sampling code below
            }
        }

        let length = if let Some(l) = length {
            l
        } else {
            rand_size::bytes(&mut self.rng)
        };
        let randoms = (&mut self.rng).sample_iter(rand::distributions::Standard);
        randoms.take(length).collect()
    }

    /// create a array with given length and given type selector and return a vector of randomly
    /// generated token
    fn create_random_array_for_type(&mut self, length: usize, t: ParamTypeSelector) -> Vec<Token> {
        let mut v: Vec<Token> = Vec::with_capacity(length);
        for _ in 0..length {
            v.push(self.create_random_token_for_type(t.clone()));
        }
        v
    }

    /// given a type selector - create a random Token for the given type
    fn create_random_token_for_type(&mut self, selected_ptype: ParamTypeSelector) -> Token {
        match selected_ptype {
            ParamTypeSelector::Address => {
                let a = self.create_random_address();
                Token::Address(a)
            }
            ParamTypeSelector::Bool => Token::Bool(self.rng.gen_bool(0.5)),
            ParamTypeSelector::Integer(size) => {
                let v = self.create_random_integer(size, true);
                Token::Int(v)
            }
            ParamTypeSelector::UnsignedInteger(size) => {
                let v = self.create_random_integer(size, false);
                Token::Uint(v)
            }
            ParamTypeSelector::String => Token::String(self.create_random_string()),
            ParamTypeSelector::Bytes(sz) => Token::Bytes(self.create_random_bytes(Some(sz))),
            ParamTypeSelector::FixedBytes(sz) => {
                Token::FixedBytes(self.create_random_bytes(Some(sz)))
            }
            ParamTypeSelector::Array(sz, t) => {
                Token::Array(self.create_random_array_for_type(sz, *t))
            }
            ParamTypeSelector::FixedArray(sz, t) => {
                Token::FixedArray(self.create_random_array_for_type(sz, *t))
            }
            ParamTypeSelector::Tuple(types) => {
                let mut v: Vec<Token> = Vec::with_capacity(types.len());
                for t in types.into_iter() {
                    v.push(self.create_random_token_for_type(t));
                }
                Token::Tuple(v)
            }
        }
    }

    fn mutate_integer(&mut self, i: &U256, signed: bool) -> U256 {
        if self.rng.gen_bool(0.1) {
            let bits = if self.rng.gen_bool(0.3) {
                256
            } else {
                // find the likely appropriate bit size
                let bs = i.bits();

                // from the bitsize it very much looks like an address, so we also return other
                // addresses.
                if (155..=160).contains(&bs) && self.rng.gen_bool(0.7) {
                    let a = self.create_random_address();
                    let b = ethereum_types::H256::from(a);
                    let ui = U256::from(b.as_bytes());
                    return ui;
                } else {
                    useful_bit_size(bs)
                }
            };
            self.create_random_integer(bits, signed)
        } else {
            match self.rng.gen_range(0..=13) {
                0 | 1 | 2 => i.overflowing_sub(U256_ONE).0,
                3 | 4 | 5 => i.overflowing_add(U256_ONE).0,
                6 | 7 | 8 => U256_ZERO.overflowing_sub(*i).0,
                9 | 10 | 11 => U256_ONE.overflowing_sub(*i).0,
                12 => {
                    let bits = useful_bit_size(i.bits());
                    let x = loop {
                        let x = self.create_random_integer(bits, signed);
                        if !x.is_zero() {
                            break x;
                        }
                    };
                    i.overflowing_sub(x).0
                }
                13 => {
                    let bits = useful_bit_size(i.bits());
                    let x = loop {
                        let x = self.create_random_integer(bits, signed);
                        if !x.is_zero() {
                            break x;
                        }
                    };
                    i.overflowing_add(x).0
                }
                14 => {
                    let x = loop {
                        let x = self.create_random_integer(256, signed);
                        if !x.is_zero() {
                            break x;
                        }
                    };
                    i.overflowing_add(x).0
                }
                _ => panic!("generated integer mutation op outside of range"),
            }
        }
    }

    /// in-place mutation of a token. For most types this just create a new random valuem, but e.g.,
    /// lengths of tuples and fixed-length array/bytes are preserved. Length of dynamically sized
    /// types (array, string) is also mutated.
    fn mutate_token(&mut self, token: &mut Token) {
        *token = match &*token {
            Token::Address(_) => Token::Address(self.create_random_address()),
            Token::FixedBytes(b) => Token::FixedBytes(self.mutate_fixed_bytes(b)),
            Token::Bytes(b) => Token::Bytes(self.mutate_bytes(b)),
            Token::Int(i) => Token::Int(self.mutate_integer(i, true)),
            Token::Uint(i) => Token::Uint(self.mutate_integer(i, false)),
            Token::Bool(b) => Token::Bool(!b),
            Token::String(s) => Token::String(self.mutate_string(s)),
            Token::FixedArray(a) => {
                let mut anext = a.clone();
                if self.rng.gen_bool(0.3) {
                    for t in anext.iter_mut() {
                        self.mutate_token(t);
                    }
                } else if !anext.is_empty() {
                    let i = self.rng.gen_range(0..anext.len());
                    self.mutate_token(&mut anext[i]);
                }
                Token::FixedArray(anext)
            }
            Token::Array(a) => {
                let origlen = a.len();
                let mut anext = a.clone();
                // problem is: we do not really know what to do if we do not have any existing
                // tokens... we cannot really grow at this point, because we do not know the type.
                if origlen > 0 {
                    // potentially grow/shrink the array
                    if self.rng.gen_bool(0.3) {
                        let newlen = self.rng.gen_range(
                            (if a.len() > 32 { a.len() - 32 } else { 0 })..(a.len() + 32),
                        );

                        use std::cmp::Ordering;
                        match origlen.cmp(&newlen) {
                            Ordering::Less => anext.truncate(newlen),
                            Ordering::Greater => {
                                let default = anext.last().unwrap().clone();
                                anext.resize(origlen, default);
                            }
                            Ordering::Equal => {}
                        }
                    }

                    // mutate the tokens
                    if self.rng.gen_bool(0.3) {
                        for t in anext.iter_mut() {
                            self.mutate_token(t);
                        }
                    } else if !anext.is_empty() {
                        let i = self.rng.gen_range(0..anext.len());
                        self.mutate_token(&mut anext[i]);
                    }
                }
                Token::Array(anext)
            }
            Token::Tuple(a) => {
                let mut anext = a.clone();
                if self.rng.gen_bool(0.3) {
                    for token in anext.iter_mut() {
                        self.mutate_token(token);
                    }
                } else if !anext.is_empty() {
                    let i = self.rng.gen_range(0..anext.len());
                    self.mutate_token(&mut anext[i]);
                }
                Token::Tuple(anext)
            }
        };
    }

    fn select_random_token_type(&mut self) -> ParamTypeSelector {
        // weighted random selection
        ParamTypeSelector::from_rng(&mut self.rng)
    }

    fn create_random_token_for_paramtype(&mut self, ptype: &ParamType) -> Token {
        let pts = ParamTypeSelector::from_paramtype_and_rng(ptype, &mut self.rng);
        self.create_random_token_for_type(pts)
    }

    /// Created a new random ABI token according to the weight defined by [`ParamTypeSelector`]
    fn create_random_token(&mut self) -> Token {
        let t = self.select_random_token_type();
        self.create_random_token_for_type(t)
    }

    /// Given a function definition create new random parameter for the function and encode them
    /// into the provided bytevec
    fn create_new_params_for_func(
        &mut self,
        tx_sig: u32,
        func: &ethabi::Function,
        bytes: &mut Vec<u8>,
    ) {
        let tokens: Vec<Token> = func
            .inputs
            .iter()
            .map(|x| self.create_random_token_for_paramtype(&x.kind))
            .collect();
        let encoded = ethabi::encode(&tokens);
        bytes.clear();
        // function short signature (we already know it so we do not have to rely on ethabi to
        // compute it by hashing the parameters again and again. This should avoid quite some keccark
        // calls.
        bytes.reserve(encoded.len() + 4);
        bytes.extend(tx_sig.to_be_bytes().iter());
        #[cfg(debug_assertions)]
        {
            for (t, pt) in tokens.iter().zip(func.inputs.iter().map(|p| &p.kind)) {
                debug_assert!(
                    t.type_check(pt),
                    "Token TypeCheck failed {:?} vs {:?}",
                    t,
                    *pt
                );
            }
            bytes.extend(&encoded);
            let encoded2 = func.encode_input(&tokens).unwrap();
            debug_assert!(*bytes == encoded2, "ethabi::encode and ethabi::Function::encode_input did not produce the same output!\n{:?}\nvs\n{:?}\n", encoded, encoded2);
        }
        #[cfg(not(debug_assertions))]
        {
            bytes.extend(encoded);
        }
    }

    /// load dictionary values from file
    pub fn load_dict_from_file(&mut self, path: &std::ffi::OsStr) -> anyhow::Result<()> {
        let path = std::path::Path::new(path);
        let r = self.dict.add_from_file(path);

        if self.allow_prints {
            println!(
                "[EthMutator] Dictionary Update => {} (loaded from file {:?}) ",
                self.dict.stats(),
                path
            );
        }
        r
    }

    /// return reference to the current buffer, which are the bytes produced during the last
    /// mutation run via [`mutate`]
    pub fn current_buffer(&self) -> &[u8] {
        &self.buffer
    }
    pub fn current_trim_buffer(&self) -> &[u8] {
        &self.trim_buffer
    }

    /// select a random call value. In only a minority of the cases we generate a uniformly random
    /// call value.  Tests on exact call values are (hopefully) rare anyway. So we try to cover a
    /// larger space of potential call values by randomly shifting the value 1 to the left. This
    /// should allow us to quickly discover the magnitutde required. Note that the call value is
    /// represented as a u64 here to save space. In reality this would be a u256. if the most
    /// significant bit is set, the fuzz harness shifts this value further to the left producing
    /// larger values. The call value is measured in the "wei" unit, which is rather small compared
    /// to the normal "ether" (1 ether == 1000000000000000000 wei)
    fn random_call_value(&mut self) -> u64 {
        if self.rng.gen_bool(0.9) {
            match self.rng.gen_range(0..=2) {
                0 => {
                    // explore the magnitude of the needed value by selecting a random $E$
                    // and return $2^E$
                    let shift = self.rng.gen_range(0..=(63 + HARNESS_CALL_VALUE_SHIFT_BITS));
                    if shift < 63 {
                        1 << shift
                    } else {
                        (1 << (shift - HARNESS_CALL_VALUE_SHIFT_BITS)) | ETHER_SHIFT_BITMASK
                    }
                }
                1 => {
                    // take a random call value between 1 and 100 ether
                    let ethers = self.rng.gen_range(1..100);
                    let (res, overflow) = ONE_ETHER_WEI.overflowing_mul(ethers);
                    if !overflow {
                        res
                    } else {
                        let (r, _) = ONE_ETHER_SHIFT.overflowing_mul(ethers);
                        r | ETHER_SHIFT_BITMASK
                    }
                }
                2 => {
                    if self.dict.has_8byte() && self.rng.gen_bool(0.7) {
                        self.log(MutationStageLog::Dictionary);
                        self.dict.sample_8byte(&mut self.rng)
                    } else {
                        let mut v = self.dict.sample_bitsize(128, &mut self.rng);
                        if !v.is_zero() {
                            self.log(MutationStageLog::Dictionary);
                        }
                        if v.bits() >= 64 {
                            v >>= HARNESS_CALL_VALUE_SHIFT_BITS;
                            v.low_u64() | ETHER_SHIFT_BITMASK
                        } else {
                            v.low_u64()
                        }
                    }
                }
                _ => panic!("invalid mode for random_call_value"),
            }
        } else {
            self.rng.gen()
        }
    }

    #[inline]
    fn create_new_tx_for_abi_func(&mut self, tx_sig: u32, func: &ethabi::Function) -> Transaction {
        let mut input_bytes: Vec<u8> = Vec::with_capacity(func.inputs.len() * 32);

        // create new random parameter for given function ABI
        self.create_new_params_for_func(tx_sig, func, &mut input_bytes);

        let txdata = TransactionHeader::new(
            self.rng.gen(),
            self.rng.gen(),
            match func.state_mutability {
                ethabi::StateMutability::Payable => self.random_call_value(),
                _ => 0,
            },
            input_bytes.len() as u16,
            1, // block advance
            0, // return count
        );
        Transaction {
            header: txdata,
            input: Rc::new(input_bytes),
            returns: vec![],
        }
    }

    /// Create a new transaction - randomly or according to ABI definition if it is available.
    fn create_new_tx(&mut self) -> Transaction {
        let cidx_u8: u8 = self.rng.gen();
        let cidx = if self.contracts.is_empty() {
            cidx_u8 as usize
        } else {
            (cidx_u8 as usize) % self.contracts.len()
        };
        if let Some(rc) = self.get_contract(cidx) {
            self.log(MutationStageLog::Abi);

            let functions = &rc.functions;
            // we select a function out of the ABI definition
            if !functions.is_empty() {
                let mut i = 0;
                let (tx_sig, func) = loop {
                    let func_index = self.rng.gen_range(0..functions.len());
                    match functions[func_index].1.state_mutability {
                        ethabi::StateMutability::Pure | ethabi::StateMutability::View => {
                            // with a very low chance we also add functions that are not supposed to
                            // modify the state (just in case)
                            if (self.allow_view_funcs && self.rng.gen_bool(0.05)) || i >= 1000 {
                                break &functions[func_index];
                            }
                        }
                        _ => {
                            break &functions[func_index];
                        }
                    }
                    i += 1;
                };
                return self.create_new_tx_for_abi_func(*tx_sig, func);
            }
        }

        // We know nothing about the contract, so we just generate random stuff.
        let mut input_bytes: Vec<u8> = Vec::with_capacity(128);

        input_bytes.extend(&self.create_tx_sig());

        for _ in 0..self.rng.gen_range(0..6) {
            self.add_random_parameter_to_input(&mut input_bytes);
        }

        let tx = TransactionHeader::new(
            self.rng.gen(),
            self.rng.gen(),
            self.random_call_value(),
            input_bytes.len() as u16,
            1,
            0,
        );

        Transaction {
            header: tx,
            input: Rc::new(input_bytes),
            returns: vec![],
        }
    }

    #[inline]
    fn have_abi_info(&self) -> bool {
        !self.contracts.is_empty()
    }

    /// decide whether a transaction should be dropped. This follows a rather complex decision tree;
    /// purely based on the original authors intuition. lol maybe ML is sometimes not so bad.
    /// Anyway. here goes the intuition:
    /// * If we do not know anything about the contract we just randomly drop 1/3 of the
    ///   transactions
    /// * If we know about the contract's ABI then we do the following:
    ///     * If the transaction starts with a known good 4byte sig; we drop with p(Drop) = 0.2
    ///     * If the transaction does not start with a known good 4byte sig we check
    ///         * if the contract has a fallback function; drop with p(Drop) = 0.4; there is a
    ///           chance that the fallback function will use inline evm-assembly or something to
    ///           process the remaining input.
    ///         * else drop with p(Drop) = 0.95 - little point in just triggering another revert due
    ///           to an invalid signature; but who knows, right?
    fn shall_drop_tx(&mut self, input: &[u8], cidx: usize) -> bool {
        // if let Some(real_tx_id) = tx_id {
        if self.have_abi_info() {
            if let Some(contract) = self.get_contract(cidx) {
                let txsig = sig_from_input(input);
                if txsig.is_some() && self.is_good_sig(txsig.unwrap()) {
                    let real_tx_id = txsig.unwrap();
                    let functions = &contract.functions;
                    if let Some(func) = find_function_for_sig(functions, real_tx_id) {
                        use ethabi::StateMutability::*;
                        let p = match func.state_mutability {
                            // very large chance if it is a non state-changing tx
                            Pure | View => 0.99,
                            // very small chance to drop the TX if it is a known function identifier
                            _ => 0.01,
                        };
                        self.rng.gen_bool(p)
                    } else {
                        // looks like a good sig, but it's corresponding cidx does not match the abi
                        // of the contract we loaded; so we drop the TX since it wil likely cause a
                        // revert.
                        self.rng.gen_bool(0.95)
                    }
                } else {
                    // rather high chance to drop TX to unknown function identifier
                    if contract.has_fallback_or_receive() {
                        // if we have a fallback function, it might make sense to call with
                        // some random data to see what happens.
                        self.rng.gen_bool(0.4)
                    } else {
                        // if not then there is little point in executing the branch, which
                        // just reverts due to invalid input data...
                        self.rng.gen_bool(0.95)
                    }
                }
            } else {
                self.rng.gen_bool(0.3)
            }
        } else {
            // TODO: does it make sense to drop some transaction, but not the other? e.g., drop
            // transactions with empty input? might be needed to receive some ether? IDK; let's just
            // drop ~1/3 of the transactions.
            //
            //if let Some(real_tx_id) = tx_id {
            //    if self
            //        .known_tx_sigs
            //        .iter()
            //        .find(|&&x| x == real_tx_id)
            //        .is_some()
            //    {
            //        self.rng.gen_bool(0.2)
            //    } else {
            //        self.rng.gen_bool(0.3)
            //    }
            //} else {
            //    self.rng.gen_bool(0.8)
            //}

            self.rng.gen_bool(0.3)
        }
    }

    fn get_receiver_for(&self, tx: &Transaction) -> usize {
        if self.contracts.is_empty() {
            tx.get_receiver()
        } else {
            tx.get_receiver() % self.contracts.len()
        }
    }

    /// identify and drop transactions that look like they might be not so useful
    fn drop_tx(&mut self, transactions: &mut TransactionList) {
        let tx_count = transactions.len();
        if tx_count > 3 {
            self.log(MutationStageLog::List(
                TxListStage::DropLikelyUselessTransactions,
            ));
            // first try to eliminate everything that seems mostly uselss.
            transactions.retain(|tx| !self.shall_drop_tx(&tx.input, self.get_receiver_for(&tx)));
            if transactions.len() >= tx_count && transactions.len() > 3 {
                // randomly drop a tx
                let idx = self.rng.gen_range(0..transactions.len());
                transactions.remove(idx);
            }
        } else {
            // on tx lists with <= 3 TXs, dropping doesn't seem so useful, so we
            // re-order instead.
            self.shuffle_transactions(transactions);
        }
    }

    fn drop_random_transaction(&mut self, transactions: &mut TransactionList) {
        let l = transactions.len();
        if l > 0 {
            self.log(MutationStageLog::List(TxListStage::DropRandomTransaction));
            if l == 1 {
                transactions.clear();
            } else {
                let i = self.rng.gen_range(0..transactions.len());
                transactions.remove(i);
            }
        }
    }

    fn drop_one_function(&mut self, transactions: &mut TransactionList) {
        if transactions.is_empty() {
            return;
        }
        let seen = self.get_funcid_set(transactions);
        match seen.len() {
            // nothing to do here...
            0 => {}
            1 => self.drop_random_transaction(transactions),
            _ => {
                let (target_receiver, target_txid) = seen.choose(&mut self.rng).unwrap();

                transactions.retain(|tx| {
                    if let Some(r) = sig_from_input(&tx.input) {
                        self.get_receiver_for(&tx) != target_receiver && r != target_txid
                    } else {
                        true
                    }
                });
                self.log(MutationStageLog::List(TxListStage::DropOneFunction));
            }
        }
    }

    /// check if we know that the signature is a good one (i.e., known according to the ABI)
    #[inline]
    pub fn is_good_sig(&self, sig: u32) -> bool {
        if !self.contract_funcsigs.is_empty() {
            //self.contract_funcsigs.contains(&sig)
            //search result, is Result::Ok if it is found
            let sr = self.contract_funcsigs.binary_search(&sig);
            sr.is_ok()
        } else {
            true
        }
    }

    /// deduplicate the transactions according to the first 4 bytes (the 4-byte shorthash function signature)
    /// The idea is that sometimes we duplicate a lot of transactions, which is sometimes useful,
    /// but sometimes also not. So it is good to counter this a bit, by deduplicating consecutive
    /// calls to the same function.
    fn dedup_by_sig(&mut self, transactions: &mut TransactionList) {
        self.log(MutationStageLog::List(
            TxListStage::DeduplicateByFunctionSig,
        ));

        // avoid operating on too long TX sequences.
        if transactions.len() > HARNESS_MAX_TX {
            self.log(MutationStageLog::List(
                TxListStage::DropLikelyUselessTransactions,
            ));
            if self.rng.gen_bool(0.75) {
                transactions.truncate(HARNESS_MAX_TX);
            } else if self.rng.gen_bool(0.75) {
                transactions.truncate(HARNESS_MAX_TX * 2);
            } else {
                transactions.truncate(HARNESS_MAX_TX * 4);
            }
        }

        transactions.dedup_by(|a, b| {
            let in_a = &a.input;
            let in_b = &b.input;
            let sig_a: Option<u32> = if let Some(r) = sig_from_input(in_a) {
                if self.is_good_sig(r) {
                    Some(r)
                } else {
                    None
                }
            } else {
                None
            };
            let sig_b: Option<u32> = if let Some(r) = sig_from_input(in_b) {
                if self.is_good_sig(r) {
                    Some(r)
                } else {
                    None
                }
            } else {
                None
            };
            sig_a == sig_b
        });
    }

    fn shuffle_transactions(&mut self, transactions: &mut TransactionList) {
        self.log(MutationStageLog::List(TxListStage::ShuffleTransactions));
        transactions.shuffle(&mut self.rng);
    }

    /// mutate the call value field, but taking the ABI of the function/contract into account.
    fn abi_mutate_call_value(&mut self, tx: &mut Transaction) {
        let cidx = self.get_receiver_for(&tx);
        if let Some(rc) = self.get_contract(cidx) {
            let functions = &rc.functions;
            let tx_data = &mut tx.header;
            let input = &tx.input;

            self.log(MutationStageLog::Abi);

            // if we have input
            if input.len() >= 4 {
                // extract tx signature and search for function with the same signature
                let tx_sig = sig_from_input(input).unwrap();
                if let Some(func) = find_function_for_sig(functions, tx_sig) {
                    // if it is a known function
                    if func.state_mutability == ethabi::StateMutability::Payable {
                        // and the function is payable, we flip/mutate the call value
                        self.flip_call_value(tx_data);
                    } else {
                        // if not, we ensure the call value is set to 0
                        if tx_data.call_value != 0 {
                            tx_data.call_value = 0;
                            self.log(MutationStageLog::Tx(TxStage::FlipCallValue));
                        }
                    }
                }
            } else {
                self.flip_call_value(tx_data);
            }
        } else {
            // unreachable
            panic!("no abi definition, but call to abi_mutate_* function")
        }
    }

    #[inline]
    fn log(&mut self, what: MutationStageLog) {
        self.stages.push(what);
        let (off, chr): (usize, u8) = match what {
            MutationStageLog::BlockHeader(what) => {
                const G: usize = 3;
                match what {
                    BlockHeaderMutationStage::Number => (G, b'N'),
                    BlockHeaderMutationStage::Difficulty => (G + 1, b'D'),
                    BlockHeaderMutationStage::GasLimit => (G + 2, b'G'),
                    BlockHeaderMutationStage::RandomTimeStamp => (G + 3, b't'),
                    BlockHeaderMutationStage::SensibleTimeStamp => (G + 3, b'T'),
                    BlockHeaderMutationStage::InitialEtherBalance => (G + 4, b'e'),
                }
            }
            MutationStageLog::List(what) => {
                const G: usize = 3 + 5 + 1;
                match what {
                    TxListStage::MutateBlockHeader => (0, b'\x00'),
                    TxListStage::GiveSomeInitialEther => (0, b'\x00'),
                    TxListStage::DeduplicateByFunctionSig => (G, b'D'),
                    TxListStage::DropLikelyUselessTransactions => (G + 1, b'U'),
                    TxListStage::DropRandomTransaction => (G + 2, b'd'),
                    TxListStage::MutateAllTx => (G + 3, b'M'),
                    TxListStage::MutateSingleTx => (G + 4, b'm'),
                    TxListStage::MutateLastTx => (G + 5, b'l'),
                    TxListStage::OnlyMutateManyTx => (G + 6, b'Z'),
                    TxListStage::PropagateValuesInTransactions => (G + 7, b'P'),
                    TxListStage::SpliceTxFromQueue => (G + 8, b's'),
                    TxListStage::SpliceTxFromQueueMulti => (G + 9, b'S'),
                    TxListStage::SpliceTxListFromQueue => (G + 10, b'L'),
                    TxListStage::AddTransaction => (G + 11, b'A'),
                    TxListStage::InsertTransaction => (G + 12, b'I'),
                    TxListStage::ReplaceLastTransaction => (G + 13, b'L'),
                    TxListStage::ReplaceRandomTransaction => (G + 14, b'R'),
                    TxListStage::DuplicateTransaction => (G + 15, b'd'),
                    TxListStage::DuplicateWithReentrancy => (G + 15, b'D'),
                    TxListStage::DropOneFunction => (G + 16, b'x'),
                    TxListStage::ShuffleTransactions => (G + 17, b'O'),
                    TxListStage::SwapTransactions => (G + 18, b'o'),
                    TxListStage::AddReturnMocks => (G + 19, b'R'),
                    TxListStage::PropagateSenderInTransactions => (G + 20, b'p'),
                    TxListStage::StackedHavocMany => (self.describe_string.len() - 1 - 2, b'H'),
                    TxListStage::ObtainCmpTrace => (self.describe_string.len() - 1 - 1, b'C'),
                }
            }
            MutationStageLog::Tx(txstage) => {
                const G: usize = 3 + 5 + 21 + 2;
                match txstage {
                    TxStage::MutateBlockAdvance => (G, b'b'),
                    TxStage::MutateCaller => (G + 1, b'C'),
                    TxStage::FlipCallValue => (G + 2, b'F'),
                    TxStage::FlipReenter => (G + 3, b'E'),
                    TxStage::MutateTransactionReturns => (G + 4, b'r'),
                    TxStage::MutateTransactionReturnData => (G + 4, b'R'),
                    // we can ignore here, because there is a separate log step for transaction input
                    // mutation.
                    TxStage::MutateTransactionInput => (0, b'\x00'),
                }
            }
            MutationStageLog::Input(what) => {
                const G: usize = 3 + 5 + 21 + 5 + 3;
                match what {
                    InputMutationStage::AddParameter => (G, b'a'),
                    InputMutationStage::ChangeParameter => (G + 1, b'c'),
                    InputMutationStage::RemoveParameter => (G + 2, b'r'),
                    InputMutationStage::ShuffleParameter => (G + 3, b's'),
                    InputMutationStage::HugeEmptyInput => (G + 4, b'E'),
                }
            }
            MutationStageLog::Abi => (self.describe_string.len() - 1 - 4, b'A'),
            MutationStageLog::Dictionary => (self.describe_string.len() - 1 - 3, b'D'),
        };

        debug_assert!(
            off < (self.describe_string.len() - 1),
            "offset to describe_string {:?} is too big for stage {:?}",
            off,
            what
        );
        self.describe_string[off] = chr;
    }

    #[inline]
    fn reset_log(&mut self) {
        if !self.stages.is_empty() {
            self.stages.clear();
            self.describe_string = *b"EM-_____-_____________________-_____-_____-____\x00";
        }
    }

    /// This functions will try to parse the given input according to the ABI definition and then
    /// apply mutation operations on that parsed input. For example, we will randomly replace one
    /// of the tokens in the parameter list with a new one of the same type.
    fn abi_mutate_tx(&mut self, tx: &mut Transaction) {
        if let Some(contract) = self.get_contract(self.get_receiver_for(tx)) {
            let functions = &contract.functions;
            let _tx_data = &mut tx.header;
            let input = &mut tx.input;
            let _returns = &mut tx.returns;

            let (tx_sig, func) = if input.len() >= 4 {
                let tx_sig = sig_from_input(input).unwrap();
                let func = find_function_for_sig(functions, tx_sig);
                (Some(tx_sig), func)
            } else {
                (None, None)
            };
            // COW semantics for the input
            let input = if let Some(x) = Rc::get_mut(input) {
                x
            } else {
                Rc::make_mut(input)
            };

            self.log(MutationStageLog::Abi);
            self.log(MutationStageLog::Input(InputMutationStage::ChangeParameter));

            if let Some(func) = func {
                // it is a known function and has input parameters
                // we need to put a max length here to avoid OOMs
                if !func.inputs.is_empty() && input.len() <= MAX_INPUT_TRY_DECODE {
                    if let Ok(mut decoded) = func.decode_input(&input[4..]) {
                        if decoded.len() == 1 {
                            self.mutate_token(&mut decoded[0]);
                        } else if decoded.len() >= 2 && self.rng.gen_bool(0.25) {
                            // mutate a random number of parameters, but avoid double-mutations

                            let mut mutated = vec![false; decoded.len()];
                            let mcount = self.rng.gen_range(1..=decoded.len());
                            for _count in 0..mcount {
                                let i = self.rng.gen_range(0..decoded.len());
                                if !mutated[i] {
                                    self.mutate_token(&mut decoded[i]);
                                    mutated[i] = true;
                                } else {
                                    // try to mutate the neighbor
                                    if i == 0 {
                                        if !mutated[1] {
                                            self.mutate_token(&mut decoded[1]);
                                            mutated[1] = true;
                                        }
                                    } else if mutated[i - 1] {
                                        self.mutate_token(&mut decoded[i - 1]);
                                        mutated[i - 1] = true;
                                    }
                                    // else give up
                                }
                            }
                        } else {
                            // select a random parameter to mutate
                            let i = self.rng.gen_range(0..decoded.len());
                            self.mutate_token(&mut decoded[i]);
                        }

                        #[cfg(debug_assertions)]
                        {
                            for (t, pt) in decoded.iter().zip(func.inputs.iter().map(|p| &p.kind)) {
                                debug_assert!(
                                    t.type_check(pt),
                                    "Token TypeCheck failed {:?} vs {:?}",
                                    t,
                                    *pt
                                );
                            }
                        }
                        let encoded = ethabi::encode(&decoded);
                        input.clear();
                        input.extend(tx_sig.unwrap().to_be_bytes().iter());

                        #[cfg(debug_assertions)]
                        {
                            input.extend(&encoded);
                            let encoded2 = func.encode_input(&decoded).unwrap();
                            debug_assert!(*input == encoded2, "ethabi::encode and ethabi::Function::encode_input did not produce the same output!\n{:?}\nvs\n{:?}\n", encoded, encoded2);
                        }
                        #[cfg(not(debug_assertions))]
                        {
                            input.extend(encoded);
                        }
                    } else {
                        // invalid inputs, we just create new ones
                        self.create_new_params_for_func(tx_sig.unwrap(), func, input);
                    }
                } else if func.inputs.is_empty() {
                    input.truncate(4);
                } else {
                    self.create_new_params_for_func(tx_sig.unwrap(), func, input);
                }
            } else if contract.has_fallback_or_receive() {
                // contract has a fallback function - in 80% of the cases we truncate the input;
                // very likely the fallback function does nothing useful with the input...
                if self.rng.gen_bool(0.8) {
                    // remove the input if it is a call to fallback
                    input.clear();
                } else {
                    // in 20% of the cases mutate it randomly
                    self.mutate_tx_input_randomly(input);
                    input.truncate(u16::MAX as usize);
                    tx.header.length = input.len() as u16;
                }
            } else {
                // we simply create new random transaction and replace the current one
                *tx = self.create_new_tx();
            }
        } else {
            // unreachable
            panic!("no abi definition, but call to abi_mutate_* function");
        }
    }

    /// if we want to create a new transaction, we will select with a high probability a 4byte
    /// signature from one of the previous transactions. In some cases we will just output a random
    /// 4-byte identifier. We rely on the fuzzer dictionary or some other comparison solver to find
    /// the right signature values.
    fn create_tx_sig(&mut self) -> [u8; 4] {
        if self.rng.gen_bool(0.9) && self.dict.has_4byte() {
            //let i: usize = self.rng.gen_range(0..(self.known_tx_sigs.len()));
            //self.known_tx_sigs[i].to_be_bytes()
            self.log(MutationStageLog::Dictionary);
            self.dict.sample_4byte(&mut self.rng).to_be_bytes()
        } else {
            let r: u32 = self.rng.gen();
            r.to_be_bytes()
        }
    }

    /// add a single random parameter to the input - this randomly select an ABI type and value and
    /// appends it to the input parameters
    fn add_random_parameter_to_input(&mut self, input: &mut Vec<u8>) {
        self.log(MutationStageLog::Input(InputMutationStage::AddParameter));
        let token = self.create_random_token();
        let x = vec![token];
        input.extend(&ethabi::encode(&x));
    }

    #[inline]
    fn mutate_structured_data<const DATA_OFFSET: usize>(&mut self, input: &mut Vec<u8>) {
        let mutation: InputMutationStage = self.rng.gen();

        match mutation {
            InputMutationStage::AddParameter => {
                if input.is_empty() {
                    input.reserve(EVM_WORD_SIZE + DATA_OFFSET);
                    if DATA_OFFSET == 4 {
                        input.extend(&self.create_tx_sig());
                    }
                } else {
                    input.reserve(EVM_WORD_SIZE);
                }

                self.add_random_parameter_to_input(input);
            }
            InputMutationStage::RemoveParameter => {
                // avoid removing a potential 4 byte signature
                if input.len() > (EVM_WORD_SIZE + DATA_OFFSET) {
                    input.truncate(input.len() - EVM_WORD_SIZE);
                }
                self.log(MutationStageLog::Input(InputMutationStage::RemoveParameter));
            }
            InputMutationStage::ChangeParameter => {
                if input.len() <= (EVM_WORD_SIZE + DATA_OFFSET) {
                    input.reserve(EVM_WORD_SIZE + DATA_OFFSET);
                    if DATA_OFFSET != 0 {
                        input.extend(&self.create_tx_sig());
                    }
                    input.resize(EVM_WORD_SIZE + DATA_OFFSET, 0);
                }
                let mut new_input_param: Vec<u8> = vec![];
                self.add_random_parameter_to_input(&mut new_input_param);

                let words = (input.len() - DATA_OFFSET) / EVM_WORD_SIZE;
                let o = self.rng.gen_range(0..words);
                let l = if self.rng.gen_bool(0.1) {
                    // replace a random range in the input words
                    self.rng.gen_range(o..words)
                } else {
                    // replace one word, or exactly the number of bytes needed for the generated input
                    let end = if self.rng.gen_bool(0.5) {
                        // no insertion/deletion of bytes, simply replace them
                        o + (new_input_param.len() / EVM_WORD_SIZE)
                    } else {
                        // remove only one word size and then insert everything else from the newly
                        // created input
                        o + 1
                    };
                    // for both we check if we went OOB and we provide something sane instead.
                    if end >= words {
                        words - 1
                    } else {
                        end
                    }
                };

                // splice the newly created parameter into the raw data
                *input = input
                    .splice(
                        ((o * EVM_WORD_SIZE) + DATA_OFFSET)..((l * EVM_WORD_SIZE) + DATA_OFFSET),
                        new_input_param.into_iter(),
                    )
                    .into_iter()
                    .collect();
                self.log(MutationStageLog::Input(InputMutationStage::ChangeParameter));
            }
            InputMutationStage::ShuffleParameter => {
                if input.len() >= ((EVM_WORD_SIZE * 2) + DATA_OFFSET) {
                    let params = (input.len() - DATA_OFFSET) / 32;
                    let first = self.rng.gen_range(0..params) * EVM_WORD_SIZE + DATA_OFFSET;
                    let second = {
                        let x = self.rng.gen_range(0..params) * EVM_WORD_SIZE + DATA_OFFSET;
                        if x != first {
                            x
                        } else {
                            // else simply choose the next neighbor
                            if x >= EVM_WORD_SIZE {
                                x - EVM_WORD_SIZE
                            } else {
                                x + EVM_WORD_SIZE
                            }
                        }
                    };

                    utils::vec_bswap::<32>(input, first, second);

                    //input.shuffle(&mut self.rng);
                    self.log(MutationStageLog::Input(
                        InputMutationStage::ShuffleParameter,
                    ));
                } else {
                    self.add_random_parameter_to_input(input);
                }
            }
            InputMutationStage::HugeEmptyInput => {
                // in general the idea of this mutation is to provide a bunch of zeroed data and
                // then let the base-fuzzer gradually discover the right values.
                //
                // Note that most contract ususually do not test for the exact input length, but
                // check if there is enough and ignore any remaining input data. So a huge empty
                // input should allow us to bypass the size check on the call or return data.
                //
                // However, sometimes we might want to hit the size spot on. So we sample a 16 bit
                // integer from the dictionary and assume it is the exact size that we need.
                //
                let input_set = if self.rng.gen_bool(0.05) {
                    let l = self.dict.sample_bitsize(16, &mut self.rng).as_u64() as usize;
                    // if the sampled "size" seems somewhat reasonable - try it.
                    if l > 0 && l <= MAX_INPUT_TRY_DECODE {
                        *input = vec![0; l + DATA_OFFSET];
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !input_set {
                    // here we use the DATA_OFFSET constant as a convenient way to scale the huge
                    // empty input: 256 * 5 bytes for input and 256 bytes for return data
                    *input = vec![0; 256 * (DATA_OFFSET + 1)];
                }

                self.log(MutationStageLog::Input(InputMutationStage::HugeEmptyInput));
            }
        }
    }

    /// Randomly do something to the input bytes - not very smart currently; except for adding new
    /// parameters, which is random but according to ABI required structure.
    fn mutate_tx_input_randomly(&mut self, input: &mut Vec<u8>) {
        self.mutate_structured_data::<4>(input)
    }

    /// currently this uses the same code as the random input mutation. The assumption is that both
    /// return data and input data is similarly formatted (i.e., according to the ABI), except for
    /// the 4 byte function signature.
    fn mutate_return_data_randomly(&mut self, data: &mut Vec<u8>) {
        self.mutate_structured_data::<0>(data)
    }

    fn create_return_data(&mut self) -> ReturnData {
        let mut ret = self.create_empty_return_data();
        let mut rawdata = if let Some(x) = Rc::get_mut(&mut ret.data) {
            x
        } else {
            Rc::make_mut(&mut ret.data)
        };

        self.mutate_return_data_randomly(&mut rawdata);
        rawdata.truncate(u16::MAX as usize);
        ret.header.data_length = ret.data.len() as u16;
        ret
    }

    fn create_empty_return_data(&mut self) -> ReturnData {
        ReturnData {
            header: ReturnHeader {
                value: 1,
                data_length: 32,
                reenter: 0,
            },
            data: self.bytes32_zero.clone(),
        }
    }

    fn add_return_data(&mut self, tx: &mut Transaction, ensure_reentrancy: bool) {
        loop {
            if tx.returns.len() < HARNESS_MAX_RETURNS {
                let mut returndata = if self.rng.gen_bool(0.8) {
                    let mut r = self.create_empty_return_data();
                    // sometimes return uint256(1), i.e., "true" in EVM semantics
                    if self.rng.gen_bool(0.3) {
                        r.data = self.bytes32_one.clone();
                    }
                    r
                } else {
                    self.create_return_data()
                };

                if ensure_reentrancy || self.rng.gen_bool(0.5) {
                    returndata.header.reenter = returndata.header.reenter.saturating_add(1);
                }
                tx.returns.push(returndata);
                tx.header.return_count = tx.returns.len() as u8;

                // every time we have a 50% chance to add another return data.
                if self.rng.gen_bool(0.5) {
                    break;
                }
            }
        }
    }

    fn flip_call_value(&mut self, tx_data: &mut TransactionHeader) {
        self.log(MutationStageLog::Tx(TxStage::FlipCallValue));
        if tx_data.call_value == 0 {
            tx_data.call_value = self.random_call_value();
        } else {
            tx_data.call_value = 0;
        }
    }

    fn mutate_tx(&mut self, tx: &mut Transaction, stage: Option<TxStage>) {
        let stage: TxStage = if let Some(stage) = stage {
            stage
        } else {
            self.rng.gen()
        };

        match stage {
            TxStage::MutateBlockAdvance => {
                let tx_data = &mut tx.header;
                match self.rng.gen_range(0..=5) {
                    0 => tx_data.block_advance = 0,
                    1 => tx_data.block_advance = 1,
                    2 => tx_data.block_advance = 128,
                    3 => tx_data.block_advance ^= 1,
                    _ => tx_data.block_advance = self.rng.gen(),
                }
                self.log(MutationStageLog::Tx(TxStage::MutateBlockAdvance));
            }
            TxStage::FlipCallValue => {
                if !self.contracts.is_empty() {
                    self.abi_mutate_call_value(tx);
                } else {
                    self.flip_call_value(&mut tx.header);
                }
            }
            TxStage::MutateCaller => {
                let tx_data = &mut tx.header;
                match self.rng.gen_range(0..=2) {
                    0 => {
                        tx_data.sender_select = self.rng.gen();
                    }
                    1 => {
                        tx_data.sender_select = tx_data.sender_select.overflowing_add(1).0;
                    }
                    2 => {
                        tx_data.sender_select = tx_data.sender_select.overflowing_sub(1).0;
                    }
                    _ => panic!("noooooo! invalid mode selector for TxStage::MutateCaller"),
                }
                self.log(MutationStageLog::Tx(TxStage::MutateCaller));
            }
            TxStage::MutateTransactionInput => {
                // currently we rely a lot on AFL's random mutations to mutate the transaction
                // input. However, this mutator still has value in  providing dictionary or
                // otherwise interesting values.
                // However, we also add a very tiny chance that the input is mutated without
                // considering the ABI.

                if (!self.contracts.is_empty()) && self.rng.gen_bool(0.999) {
                    self.abi_mutate_tx(tx);
                } else {
                    let input = &mut tx.input;
                    // COW - copy on write semantics with the help of the Rc type
                    let input = if let Some(x) = Rc::get_mut(input) {
                        x
                    } else {
                        Rc::make_mut(input)
                    };

                    self.mutate_tx_input_randomly(input);
                    input.truncate(u16::MAX as usize);
                    tx.header.length = input.len() as u16;
                }
            }
            TxStage::FlipReenter => {
                if !tx.returns.is_empty() {
                    self.log(MutationStageLog::Tx(TxStage::FlipReenter));
                    let rets = &mut tx.returns;
                    // flip all reenter flags
                    if self.rng.gen_bool(0.1) {
                        for r in rets.iter_mut() {
                            r.header.reenter = self.flip_reenter_number(r.header.reenter);
                        }
                    } else {
                        // we add some bias towards flipping the reenter flag for the last and
                        // second to last returns.
                        let idx = if self.rng.gen_bool(0.1) {
                            if rets.len() > 2 && self.rng.gen_bool(0.5) {
                                self.rng.gen_range(rets.len() - 2..rets.len())
                            } else {
                                rets.len() - 1
                            }
                        } else {
                            self.rng.gen_range(0..rets.len())
                        };
                        // flip reenter count for some
                        rets[idx].header.reenter =
                            self.flip_reenter_number(rets[idx].header.reenter);
                    }
                } else {
                    self.log(MutationStageLog::Tx(TxStage::MutateTransactionReturns));
                    self.add_return_data(tx, false);
                }
            }
            TxStage::MutateTransactionReturns => {
                self.log(MutationStageLog::Tx(TxStage::MutateTransactionReturns));
                let retcount = tx.returns.len();
                if retcount == 0 || (retcount <= 3 && self.rng.gen_bool(0.5)) {
                    self.add_return_data(tx, false);
                } else {
                    if self.rng.gen_bool(0.5) {
                        tx.returns.remove(self.rng.gen_range(0..retcount));
                    }

                    if retcount < HARNESS_MAX_RETURNS && self.rng.gen_bool(0.5) {
                        self.add_return_data(tx, false);
                    }
                }

                if self.rng.gen_bool(0.4) {
                    for ret in tx.returns.iter_mut() {
                        ret.header.value = 1u8;
                    }
                }
            }
            TxStage::MutateTransactionReturnData => {
                let retcount = tx.returns.len();
                if retcount == 0 {
                    self.log(MutationStageLog::Tx(TxStage::MutateTransactionReturns));
                    self.add_return_data(tx, false);
                } else {
                    self.log(MutationStageLog::Tx(TxStage::MutateTransactionReturnData));

                    let rets = &mut tx.returns;
                    let idx = self.rng.gen_range(0..rets.len());
                    let mut rawdata = Rc::make_mut(&mut rets[idx].data);
                    self.mutate_return_data_randomly(&mut rawdata);
                    rets[idx].header.data_length = rawdata.len() as u16;

                    // usually we want to have the call succeed, so we return 1 most of the time.
                    rets[idx].header.value = self.rng.gen_bool(0.95) as u8;

                    for r in rets.iter_mut() {
                        r.header.data_length = r.data.len() as u16;
                    }
                }
            }
        }

        // synchronize header length fields with actual lengths
        tx.header.return_count = tx.returns.len() as u8;
        tx.header.length = tx.input.len() as u16;
    }

    #[inline]
    fn mutate_all_tx(&mut self, transactions: &mut TransactionList) {
        if !transactions.is_empty() {
            for tx in transactions.iter_mut() {
                self.mutate_tx(tx, None);
            }
            self.log(MutationStageLog::List(TxListStage::MutateAllTx));
        } else {
            self.add_tx(transactions);
        }
    }

    #[inline]
    fn flip_reenter_number(&mut self, cur_val: u8) -> u8 {
        if cur_val == 0 {
            if self.rng.gen_bool(0.3) {
                if self.rng.gen_bool(0.75) {
                    255
                } else {
                    self.rng.gen()
                }
            } else {
                1
            }
        } else {
            0
        }
    }

    /// here we first gather all values that were passed as parameter to a function in the
    /// transaction sequences. For each ABI type we randomly select one of the gathered values and
    /// replace other values of the same ABI type with this chosen value.
    fn abi_mutate_tx_input_with_value_propagation(
        &mut self,
        transactions: &mut TransactionList,
        replace_all: bool,
        replace_only_one_type: bool,
    ) {
        if !self.contracts.is_empty() {
            return;
        }
        if transactions.is_empty() {
            // we add at least two transactions
            self.add_tx(transactions);
            self.add_tx(transactions);
        } else if transactions.len() < 5 {
            // we add another transaction, s.t., the value propagation is actually worthwhile
            // appending a new transaction shouldn't hurt. If it provokes a
            self.add_tx(transactions);
        }

        const VEC: Vec<Token> = Vec::new();
        const TOKEN_TYPE_COUNT: usize = 9 + 64;
        let mut tokens: [Vec<Token>; TOKEN_TYPE_COUNT] = [VEC; TOKEN_TYPE_COUNT];
        let mut decoded_inputs: Vec<Option<Vec<Token>>> = vec![];
        let mut identified_functions: Vec<Option<ethabi::Function>> = vec![];

        let mut args: usize = 0;

        for tx in transactions.iter() {
            let input = &tx.input;

            if input.len() > MAX_INPUT_TRY_DECODE || input.len() <= 4 {
                decoded_inputs.push(None);
                identified_functions.push(None);
                continue;
            }

            let contract = self.get_contract(self.get_receiver_for(tx)).unwrap();
            let functions = &contract.functions;

            let tx_sig = sig_from_input(input).unwrap();
            let func = find_function_for_sig(functions, tx_sig).cloned();

            decoded_inputs.push(if let Some(func) = &func {
                if func.inputs.is_empty() {
                    None
                } else if let Ok(decoded) = func.decode_input(&input[4..]) {
                    for token in decoded.iter() {
                        let idx = token_to_index(token);
                        if idx < tokens.len() {
                            tokens[idx].push(token.clone());
                        }
                    }

                    args = args.saturating_add(decoded.len());

                    Some(decoded)
                } else {
                    None
                }
            } else {
                None
            });

            identified_functions.push(func);
        }

        if args <= 1 {
            return;
        }

        #[cfg(debug_assertions)]
        {
            debug_assert!(
                transactions.len() == decoded_inputs.len(),
                "length mismatch between transactions {} and inputs {}",
                transactions.len(),
                decoded_inputs.len()
            );
            debug_assert!(
                identified_functions.len() == decoded_inputs.len(),
                "length mismatch between id'funcs {} and inputs {}",
                identified_functions.len(),
                decoded_inputs.len()
            );
        }

        // we shuffle the gathered tokens and we also check whether we have
        let mut some_tokens = 0;
        for token in tokens.iter_mut() {
            if token.len() > 1 {
                some_tokens += 1;
                token.shuffle(&mut self.rng);
            }
        }

        if some_tokens == 0 {
            return;
        }

        if replace_only_one_type {
            // we find one type, which has at least one token available.
            for type_index in
                rand::seq::index::sample(&mut self.rng, tokens.len(), tokens.len()).into_iter()
            {
                if tokens[type_index].is_empty() {
                    continue;
                }
                // we clear all other the other gathered tokens and stop our search
                for (i, token) in tokens.iter_mut().enumerate() {
                    if i != type_index {
                        token.clear()
                    }
                }
                break;
            }
        }

        #[cfg(debug_assertions)]
        {
            let mut some_tokens = 0;
            for t in tokens.iter() {
                if !t.is_empty() {
                    some_tokens += 1;
                }
            }
            debug_assert!(
                some_tokens != 0,
                "need at least some kind of token left. this must be a bug!"
            );
        }

        let mut replaced_something_at_all = false;
        for _ in 0..20 {
            for ((tx, decoded), func) in transactions
                .iter_mut()
                .zip(decoded_inputs.iter_mut())
                .zip(identified_functions.iter())
            {
                if let Some(decoded) = decoded.as_mut() {
                    let mut replaced_something = false;
                    for token in decoded.iter_mut() {
                        if replace_all || self.rng.gen_bool(0.3) {
                            let idx = token_to_index(token);
                            if idx >= tokens.len() || tokens[idx].is_empty() {
                                continue;
                            }
                            match token {
                                Token::Uint(_)
                                | Token::Int(_)
                                | Token::Bool(_)
                                | Token::Address(_)
                                | Token::Bytes(_)
                                | Token::FixedBytes(_)
                                | Token::String(_) => {
                                    *token = tokens[idx][0].clone();
                                    replaced_something = true;
                                    replaced_something_at_all = true;
                                }
                                Token::FixedArray(_) | Token::Array(_) | Token::Tuple(_) => {
                                    // TODO: for now we ignore this here... we would have to somehow
                                    // recurse into those datastructures, shall we replace compatible
                                    // types? shall we replace the contained tokens?
                                }
                            }
                        }
                    }

                    if replaced_something {
                        let input = &mut tx.input;
                        // COW semantics for the input
                        let input = if let Some(x) = Rc::get_mut(input) {
                            x
                        } else {
                            Rc::make_mut(input)
                        };

                        let func = func.as_ref().unwrap();

                        #[cfg(debug_assertions)]
                        {
                            for (t, pt) in decoded.iter().zip(func.inputs.iter().map(|p| &p.kind)) {
                                debug_assert!(
                                    t.type_check(pt),
                                    "Token TypeCheck failed {:?} vs {:?}",
                                    t,
                                    *pt
                                );
                            }
                        }
                        let encoded = func.encode_input(decoded).unwrap();
                        input.clear();
                        input.extend(encoded);
                    }
                }
            }

            if replaced_something_at_all {
                self.log(MutationStageLog::List(
                    TxListStage::PropagateValuesInTransactions,
                ));
                break;
            }
        }

        #[cfg(debug_assertions)]
        {
            if !replaced_something_at_all {
                eprintln!("[EthMutator] Warning replaced nothing during Value Propagation Mutation operation");
                // let mut fc = FuzzCase::zeroed();
                // fc.txs = transactions.clone();
                // if let Some(rc) = self.contract.clone() {
                //     let c = &*rc;
                //     let _ = print_fuzzcase(&fc, Some(c));
                // } else {
                //     let _ = print_fuzzcase(&fc, None);
                // }
            }
        }
    }

    /// the idea of this mutation is: if we see an address of a known sender in the transaction
    /// list, then this address was somehow "registerd" with the smart contract under test. Now this
    /// contract might be allowed to perform some actions after that. So we try to switch
    fn apply_sender_propagation(&mut self, transactions: &mut TransactionList) {
        //let mut last_sender : u8 = 0;
        let mut last_address_idx: usize = 256;
        for tx in transactions.iter_mut() {
            // we search for an address among the input parameters
            if tx.input.len() > 4 {
                for i in (4..tx.input.len()).step_by(32) {
                    if tx.input[i..].len() >= 32 && &tx.input[i..(i + 12)] == NULL_BYTES_12 {
                        for sender_idx in 0..(TX_SENDER.len() - 1) {
                            if &tx.input[(i + 12)..(i + 32)] == TX_SENDER[sender_idx].as_bytes() {
                                last_address_idx = sender_idx;
                                if self.rng.gen_bool(0.5) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // if we have seen an address in the input parameters, we replace the sender_select
            // field with the one corresponding to the last seen address.
            if last_address_idx < 256 && self.rng.gen_bool(0.3) {
                tx.header.sender_select = last_address_idx as u8;
            }
        }

        if last_address_idx != 256 {
            self.log(MutationStageLog::List(
                TxListStage::PropagateSenderInTransactions,
            ));
        }
    }

    fn add_all_abi_functions(&mut self, transactions: &mut TransactionList) {
        if !self.contracts.is_empty() {
            let contracts: Vec<Rc<Contract>> = self.contracts.iter().cloned().collect();
            for (cidx, contract) in contracts.into_iter().enumerate() {
                let functions = &contract.functions;
                for func in functions.iter() {
                    match func.1.state_mutability {
                        ethabi::StateMutability::Pure | ethabi::StateMutability::View => {
                            // do nothing; pure/view functions will probably not do anything useful
                            // so do not add them here.
                        }
                        _ => {
                            let mut tx = self.create_new_tx_for_abi_func(func.0, &func.1);
                            self.add_return_data(&mut tx, false);
                            tx.header.receiver_select = cidx as u8;
                            transactions.push(tx);
                        }
                    }
                }
                self.shuffle_transactions(transactions);
                self.log(MutationStageLog::Abi);
                self.log(MutationStageLog::List(TxListStage::AddTransaction));
            }
        }
    }

    fn get_funcid_set(&mut self, transactions: &TransactionList) -> SmallSet<(usize, u32)> {
        let mut seen: SmallSet<(usize, u32)> = SmallSet::new();
        for tx in transactions.iter() {
            let input = &tx.input;
            if input.len() >= 4 {
                let txid = sig_from_input(input).unwrap();
                seen.insert((self.get_receiver_for(tx), txid));
            }
        }
        seen
    }

    fn create_abi_unique_tx(&mut self, transactions: &TransactionList) -> Option<Transaction> {
        if self.contracts.is_empty() {
            None
        } else {
            let mut tx: Option<Transaction> = None;

            let seen = self.get_funcid_set(transactions);

            let contracts: Vec<Rc<Contract>> = self.contracts.iter().cloned().collect();
            for (cidx, contract) in contracts.into_iter().enumerate() {
                let functions = &contract.functions;

                // don't bother iterating if we have likely seen all the tx ids
                if seen.len() < functions.len() {
                    for func in functions.iter() {
                        if !seen.contains(&(cidx, func.0)) {
                            match func.1.state_mutability {
                                ethabi::StateMutability::Pure | ethabi::StateMutability::View => {
                                    // pure/view functions will probably not do anything useful
                                }
                                _ => {
                                    self.log(MutationStageLog::Abi);
                                    let mut newtx =
                                        self.create_new_tx_for_abi_func(func.0, &func.1);
                                    newtx.header.receiver_select = cidx as u8;
                                    tx = Some(newtx);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            tx
        }
    }

    fn replace_last_tx(&mut self, transactions: &mut TransactionList) {
        if transactions.is_empty() {
            self.add_tx(transactions);
        } else {
            let mut tx: Option<Transaction> = None;
            if !self.contracts.is_empty() && self.rng.gen_bool(0.8) {
                tx = self.create_abi_unique_tx(transactions);
            }
            let tx = if let Some(tx) = tx {
                tx
            } else {
                self.create_new_tx()
            };
            let lastidx = if self.rng.gen_bool(0.9) || transactions.len() == 1 {
                transactions.len() - 1
            } else {
                transactions.len() - 2
            };
            transactions[lastidx] = tx;
            self.log(MutationStageLog::List(TxListStage::ReplaceLastTransaction));
        }
    }

    fn replace_random_tx(&mut self, transactions: &mut TransactionList) {
        if transactions.is_empty() {
            self.add_tx(transactions);
        } else {
            self.log(MutationStageLog::List(
                TxListStage::ReplaceRandomTransaction,
            ));
            let idx = self.rng.gen_range(0..transactions.len());

            let mut tx: Option<Transaction> = None;
            if !self.contracts.is_empty() && self.rng.gen_bool(0.8) {
                tx = self.create_abi_unique_tx(transactions);
            }
            let tx = if let Some(tx) = tx {
                tx
            } else {
                self.create_new_tx()
            };

            transactions[idx] = tx;
        }
    }

    /// insert a new transaction at a random place in the transaction list
    fn insert_tx(&mut self, transactions: &mut TransactionList) {
        let mut tx: Option<Transaction> = None;
        if !self.contracts.is_empty() && self.rng.gen_bool(0.8) {
            tx = self.create_abi_unique_tx(transactions);
        }
        let tx = if let Some(tx) = tx {
            tx
        } else {
            self.create_new_tx()
        };

        if transactions.is_empty() {
            self.log(MutationStageLog::List(TxListStage::AddTransaction));
            transactions.push(tx);
        } else {
            self.log(MutationStageLog::List(TxListStage::InsertTransaction));
            let idx = if self.rng.gen_bool(0.1) {
                transactions.len() - 1
            } else {
                self.rng.gen_range(0..transactions.len())
            };
            transactions.insert(idx, tx);
            if idx > 0 && self.rng.gen_bool(0.2) {
                let lasttx = &mut transactions[idx - 1];
                if let Some(lastret) = lasttx.returns.last_mut() {
                    lastret.header.reenter = lastret.header.reenter.saturating_add(1);
                } else {
                    self.add_return_data(lasttx, true);
                    self.log(MutationStageLog::List(TxListStage::AddReturnMocks));
                }
                self.log(MutationStageLog::Tx(TxStage::FlipReenter));
            }
        }
    }

    /// more like `append_tx` as it adds at least one (and sometimes more) new transaction to the
    /// end of the transaction list
    fn add_tx(&mut self, transactions: &mut TransactionList) {
        let mut tx: Option<Transaction> = None;
        if self.rng.gen_bool(0.8) {
            tx = self.create_abi_unique_tx(transactions);
        }
        let tx = if let Some(tx) = tx {
            tx
        } else {
            self.create_new_tx()
        };

        self.log(MutationStageLog::List(TxListStage::AddTransaction));
        if let Some(lasttx) = transactions.last_mut() {
            if self.rng.gen_bool(0.3) {
                self.add_return_data(lasttx, true);
            }
        }
        transactions.push(tx);

        // if we add a transaction to a previously empty testcase, we also want to add a second
        // transaction sometimes.
        if transactions.len() == 1 && self.rng.gen_bool(0.5) {
            self.add_tx(transactions);
            if self.rng.gen_bool(0.125) {
                self.add_tx(transactions);
            }
        } else {
            // we would like to append mostly useful transactions, so sometimes we will perform
            // sender propagation directly after adding a transaction.
            if self.rng.gen_bool(0.3) {
                self.apply_sender_propagation(transactions);
            }
        }
    }

    /// Custom transaction list splicing - we randomly insert/overwrite transaction from the current
    /// transaction list with transactions from a previous fuzzcase.
    fn splice_txlist_from_queue(&mut self, transactions: &mut TransactionList) {
        // randomly select a fuzzcase from the queue and splice all transactions
        let queue_len = self.queue.len();
        let mut do_log = false;
        if queue_len > 0 {
            let (splice_at, splice_cnt) = if transactions.is_empty() {
                (0, 0)
            } else {
                let tlen = transactions.len();
                let splice_at = self.rng.gen_range(0..tlen);
                let splice_cnt = if tlen < 8 {
                    // bulk insert
                    0
                } else {
                    self.rng.gen_range(0..(tlen - splice_at))
                };
                (splice_at, splice_cnt)
            };

            // splice_at - starting index in the current transaction list
            // splice_cnt - number of transaction to remove in the current transaction list

            transactions.reserve(16);

            // choose random queue entry
            let i: usize = self.rng.gen_range(0..queue_len);
            let other = &self.queue[i];

            // check if queue entry contains transactions
            if !other.is_empty() {
                do_log = true;

                // choose random range from other TX list
                let i: usize = self.rng.gen_range(0..other.len());
                let j: usize = if i < (other.len() - 1) {
                    self.rng.gen_range(i..other.len())
                } else {
                    i
                };
                let c = j - i;
                transactions.splice(
                    // range, which will be removed, a range 0..0 would mean no removal, just
                    // insertion
                    splice_at..(splice_at + std::cmp::min(splice_cnt, c)),
                    // the range, which will be inserted
                    other[i..j].iter().cloned(),
                );
            }

            // with some probability we also deduplicate by function signature after splicing to
            // avoid creating too many overly long testcases
            if self.rng.gen_bool(0.1) {
                self.dedup_by_sig(transactions);
            }
        }

        if do_log {
            self.log(MutationStageLog::List(TxListStage::SpliceTxListFromQueue));
        }
    }

    fn splice_single_tx_from_queue(&mut self, transactions: &mut TransactionList) {
        let queue_len = self.queue.len();
        if queue_len > 0 {
            // five attempts to splice a non-empty TX sequence
            for _ in 0..5 {
                let i: usize = self.rng.gen_range(0..queue_len);
                let other = &self.queue[i];
                let other_len = other.len();
                // do not splice from other testcases, which consist of only one or far too many transactions.
                if 1 < other_len && other_len <= HARNESS_MAX_TX {
                    // select a random TX out of the selected queue entry
                    let j: usize = if other.len() <= 2 {
                        0
                    } else {
                        // we avoid splicing the last transaction in the sequence as this is
                        // very likely a reverting transaction.
                        self.rng.gen_range(0..(other.len() - 1))
                    };
                    let newtx = &other[j];

                    // avoid splicing "crap"; i.e., things that are probably useless.
                    if !self.contracts.is_empty() {
                        let cidx = self.get_receiver_for(newtx);
                        if let Some(contract) = self.get_contract(cidx) {
                            let functions = &contract.functions;
                            if let Some(tx_sig) = sig_from_input(&newtx.input) {
                                if let Some((_sig, func)) =
                                    functions.iter().find(|(x, _)| *x == tx_sig)
                                {
                                    match func.state_mutability {
                                        ethabi::StateMutability::Pure
                                        | ethabi::StateMutability::View => continue,
                                        _ => {}
                                    }
                                }
                            } else if !contract.has_fallback_or_receive() {
                                continue;
                            }
                        }
                    }

                    let newtx = newtx.clone();

                    if transactions.is_empty() {
                        transactions.push(newtx);
                        // splicing into an empty transaction sequence is mostly useless, so we
                        // also add another transaction.
                        self.add_tx(transactions);
                    } else {
                        // we always insert in small transaction sequences.
                        // for longer sequences: mostly insert, but sometimes replace.
                        if transactions.len() <= 3 || self.rng.gen_bool(0.75) {
                            let newidx = self.rng.gen_range(0..=transactions.len());
                            transactions.insert(newidx, newtx);
                        } else {
                            let newidx = self.rng.gen_range(0..transactions.len());
                            transactions[newidx] = newtx;
                        }
                    }

                    // we found a TX to splice -> break out of the loop
                    break;
                }
            }
        }
    }

    /// randomly select and mutate a field in the [`BlockHeader`] structure
    fn mutate_block_header(&mut self, bh: &mut BlockHeader) {
        let stage: BlockHeaderMutationStage = self.rng.gen();
        match stage {
            BlockHeaderMutationStage::Difficulty => {
                self.log(MutationStageLog::BlockHeader(
                    BlockHeaderMutationStage::Difficulty,
                ));
                if self.dict.has_8byte() && self.rng.gen_bool(0.5) {
                    bh.difficulty = self.dict.sample_8byte(&mut self.rng);
                    if bh.difficulty != 0 {
                        self.log(MutationStageLog::Dictionary);
                    }
                } else {
                    bh.difficulty = self.rng.gen();
                }
            }
            BlockHeaderMutationStage::Number => {
                self.log(MutationStageLog::BlockHeader(
                    BlockHeaderMutationStage::Number,
                ));
                match self.rng.gen_range(0..3) {
                    0 => bh.number = 0,
                    1 => {
                        // something that looks like a useful blocknumber
                        bh.number = self.rng.gen_range(1..=30_000_000);
                    }
                    _ => {
                        bh.number = self.dict.sample_8byte(&mut self.rng);
                        if bh.number != 0 {
                            self.log(MutationStageLog::Dictionary);
                        }
                    }
                }
            }
            BlockHeaderMutationStage::GasLimit => {
                self.log(MutationStageLog::BlockHeader(
                    BlockHeaderMutationStage::GasLimit,
                ));
                if self.dict.has_8byte() && self.rng.gen_bool(0.5) {
                    bh.gas_limit = self.dict.sample_8byte(&mut self.rng);
                    if bh.gas_limit != 0 {
                        self.log(MutationStageLog::Dictionary);
                    }
                } else {
                    bh.gas_limit = self.rng.gen();
                }
            }
            BlockHeaderMutationStage::RandomTimeStamp => {
                self.log(MutationStageLog::BlockHeader(
                    BlockHeaderMutationStage::RandomTimeStamp,
                ));
                if self.dict.has_8byte() && self.rng.gen_bool(0.5) {
                    bh.timestamp = self.dict.sample_8byte(&mut self.rng);
                    if bh.timestamp != 0 {
                        self.log(MutationStageLog::Dictionary);
                    }
                } else {
                    bh.timestamp = self.rng.gen();
                }
            }
            BlockHeaderMutationStage::SensibleTimeStamp => {
                self.log(MutationStageLog::BlockHeader(
                    BlockHeaderMutationStage::SensibleTimeStamp,
                ));
                // somewhere between July 30, 2015 (ethereum launch date)
                // and July 30, 2045.
                bh.timestamp = self.rng.gen_range(1438207200..2384978400);
            }
            BlockHeaderMutationStage::InitialEtherBalance => {
                self.log(MutationStageLog::BlockHeader(
                    BlockHeaderMutationStage::InitialEtherBalance,
                ));
                if bh.initial_ether == 0 {
                    bh.initial_ether = self.random_call_value();
                } else {
                    bh.initial_ether = 0;
                }
            }
        }
    }

    /// given a stage and a fuzzcase, mutate the fuzzcase
    fn mutate_one_stage(&mut self, fc: &mut FuzzCase, stage: TxListStage) {
        let block_header = &mut fc.header;
        let transactions = &mut fc.txs;
        let tx_len = transactions.len();
        match stage {
            TxListStage::OnlyMutateManyTx => {
                self.only_mutate_many_tx(transactions);
            }
            TxListStage::MutateBlockHeader => {
                self.mutate_block_header(block_header);
            }
            TxListStage::GiveSomeInitialEther => {
                self.log(MutationStageLog::BlockHeader(
                    BlockHeaderMutationStage::InitialEtherBalance,
                ));
                block_header.initial_ether =
                    call_value_add(block_header.initial_ether, self.random_call_value());
            }
            TxListStage::InsertTransaction => {
                if transactions.len() < HARNESS_MAX_TX {
                    self.insert_tx(transactions);
                } else {
                    self.mutate_one_stage(fc, TxListStage::SwapTransactions);
                }
            }
            TxListStage::ReplaceLastTransaction => {
                self.replace_last_tx(transactions);
            }
            TxListStage::ReplaceRandomTransaction => {
                self.replace_random_tx(transactions);
            }
            TxListStage::AddTransaction => {
                if transactions.len() < HARNESS_MAX_TX {
                    self.add_tx(transactions);
                } else {
                    self.mutate_one_stage(fc, TxListStage::SwapTransactions);
                }
            }
            TxListStage::DuplicateTransaction => {
                if transactions.is_empty() {
                    self.add_tx(transactions);
                } else {
                    let i = self.rng.gen_range(0..transactions.len());
                    let tx = transactions[i].clone();
                    if self.rng.gen_bool(0.1) {
                        let count = self.rng.gen_range(3..=6);
                        let arr = vec![tx; count];
                        transactions.splice((i + 1)..(i + 1), arr);
                    } else {
                        transactions.insert(i + 1, tx);
                    }
                    self.log(MutationStageLog::List(TxListStage::DuplicateTransaction));
                }
            }
            TxListStage::DropRandomTransaction => {
                if transactions.len() > 3 {
                    self.drop_random_transaction(transactions);
                } else {
                    self.add_tx(transactions);
                }
            }
            TxListStage::DropLikelyUselessTransactions => {
                self.drop_tx(transactions);
            }
            TxListStage::DropOneFunction => {
                if transactions.len() > 3 {
                    self.drop_one_function(transactions);
                } else {
                    self.shuffle_transactions(transactions);
                }
            }
            TxListStage::ShuffleTransactions => {
                if transactions.len() <= 2 {
                    self.add_tx(transactions);
                    self.add_tx(transactions);
                }
                self.shuffle_transactions(transactions);
            }
            TxListStage::SwapTransactions => {
                if transactions.len() <= 2 {
                    self.add_tx(transactions);
                    self.add_tx(transactions);
                } else {
                    let i1 = self.rng.gen_range(0..transactions.len());
                    let i2 = {
                        let x = self.rng.gen_range(0..transactions.len());
                        if x == i1 {
                            if x == 0 {
                                x + 1
                            } else {
                                x - 1
                            }
                        } else {
                            x
                        }
                    };
                    transactions.swap(i1, i2);

                    if self.rng.gen_bool(0.2) {
                        let r1 = transactions[i1].returns.clone();
                        let r2 = transactions[i2].returns.clone();
                        transactions[i1].returns = r2;
                        transactions[i2].returns = r1;
                    }

                    self.log(MutationStageLog::List(TxListStage::SwapTransactions));
                }
            }
            TxListStage::DeduplicateByFunctionSig => {
                self.dedup_by_sig(transactions);
            }
            TxListStage::MutateAllTx => {
                self.mutate_all_tx(transactions);
            }
            TxListStage::MutateLastTx => {
                if !transactions.is_empty() {
                    self.log(MutationStageLog::List(TxListStage::MutateLastTx));
                    if self.rng.gen_bool(0.9) || transactions.len() == 1 {
                        self.mutate_tx(transactions.last_mut().unwrap(), None);
                    } else {
                        // sometimes we also try to mutate the second to last transaction in the
                        // list.
                        let secondtolast = transactions.len() - 2;
                        self.mutate_tx(&mut transactions[secondtolast], None);
                    }
                } else {
                    self.add_tx(transactions);
                }
            }
            TxListStage::MutateSingleTx => {
                if !transactions.is_empty() {
                    self.log(MutationStageLog::List(TxListStage::MutateSingleTx));
                    let i: usize = self.rng.gen_range(0..transactions.len());
                    self.mutate_tx(&mut transactions[i], None);
                } else {
                    // can't mutate if there are no TX - so we add one
                    self.add_tx(transactions);
                }
            }
            TxListStage::PropagateValuesInTransactions => {
                if transactions.is_empty() {
                    // can't mutate if there are no TX - so we add a couple
                    self.add_tx(transactions);
                    self.add_tx(transactions);
                    self.add_tx(transactions);
                }

                if !self.contracts.is_empty() {
                    // 1. if replace_all is false we do probabilistic replacement
                    // 2. if only_one_type is true we restrict ourself to replacing one type
                    // the idea here is that if we replace only one type then the chance is pretty
                    // high that we do useful replacements, so we likely replace all the occurences.
                    // However, if we replace more than one type we do probabilistic replacements
                    // more likely.
                    let (replace_all, only_one_type) = if self.rng.gen_bool(0.8) {
                        (self.rng.gen_bool(0.3), true)
                    } else {
                        (self.rng.gen_bool(0.1), false)
                    };
                    self.abi_mutate_tx_input_with_value_propagation(
                        transactions,
                        replace_all,
                        only_one_type,
                    );
                } else {
                    self.mutate_one_stage(fc, TxListStage::OnlyMutateManyTx);
                }
            }
            TxListStage::PropagateSenderInTransactions => {
                if transactions.len() > 1 {
                    self.apply_sender_propagation(transactions);
                } else {
                    self.add_tx(transactions);
                }
            }
            TxListStage::SpliceTxFromQueue => {
                let queue_len = self.queue.len();
                if queue_len > 0 && tx_len > 0 {
                    self.log(MutationStageLog::List(TxListStage::SpliceTxFromQueue));
                    self.splice_single_tx_from_queue(transactions);
                }
            }
            TxListStage::SpliceTxFromQueueMulti => {
                let queue_len = self.queue.len();
                if queue_len > 0 && tx_len > 0 {
                    self.log(MutationStageLog::List(TxListStage::SpliceTxFromQueueMulti));
                    for _ in 2..5 {
                        self.splice_single_tx_from_queue(transactions);
                    }
                } else {
                    self.add_tx(transactions);
                }
            }
            TxListStage::SpliceTxListFromQueue => {
                self.splice_txlist_from_queue(transactions);
            }
            TxListStage::AddReturnMocks => {
                if transactions.is_empty() {
                    self.add_tx(transactions);
                    self.add_tx(transactions);
                }
                self.log(MutationStageLog::List(TxListStage::AddReturnMocks));

                let mut ret = self.create_empty_return_data();
                ret.header.reenter = 1;
                for tx in transactions.iter_mut() {
                    for _ in 0..10 {
                        if tx.returns.len() < HARNESS_MAX_RETURNS {
                            let rets = &mut tx.returns;
                            rets.push(ret.clone());
                        } else {
                            break;
                        }
                    }
                    tx.header.return_count = tx.returns.len() as u8;
                }
            }
            TxListStage::DuplicateWithReentrancy => {
                if !transactions.is_empty() {
                    let idx = if transactions.len() >= 3 && self.rng.gen_bool(0.8) {
                        self.rng.gen_range(1..(transactions.len() - 1))
                    } else {
                        self.rng.gen_range(0..transactions.len())
                    };
                    let new_tx = transactions[idx].clone();
                    let mut old_tx = transactions.get_mut(idx).unwrap();
                    if old_tx.returns.is_empty() {
                        self.add_return_data(&mut old_tx, true);
                    }
                    if let Some(ret) = old_tx.returns.last_mut() {
                        ret.header.reenter = ret.header.reenter.saturating_add(1);
                    }

                    if self.rng.gen_bool(0.01) {
                        let count = self.rng.gen_range(3..=6);
                        let arr = vec![new_tx; count];
                        transactions.splice((idx + 1)..(idx + 1), arr);
                    } else {
                        transactions.insert(idx + 1, new_tx);
                    }

                    self.log(MutationStageLog::List(TxListStage::DuplicateTransaction));
                } else {
                    let mut tx1 = self.create_new_tx();
                    let tx2 = tx1.clone();

                    self.add_return_data(&mut tx1, true);

                    transactions.push(tx1);
                    transactions.push(tx2);

                    self.log(MutationStageLog::List(TxListStage::AddTransaction));
                }
                self.log(MutationStageLog::Tx(TxStage::FlipReenter));
            }
            TxListStage::StackedHavocMany => {
                self.log(MutationStageLog::List(TxListStage::StackedHavocMany));
                // with a little higher bias, we sometimes deduplicate by function signature and
                // drop useless transactions before
                // applying the stacked mutations. The idea is that we reduce the testcase before
                // expanding it again.
                if fc.txs.len() > 16 {
                    if self.rng.gen_bool(0.05) {
                        self.mutate_one_stage(fc, TxListStage::DeduplicateByFunctionSig);
                    }
                    if self.rng.gen_bool(0.2) {
                        self.mutate_one_stage(fc, TxListStage::DropLikelyUselessTransactions);
                    }
                }
                let i: usize = self.rng.gen_range(2..8);
                for _ in 0..i {
                    let stage: TxListStage = self.rng.gen();
                    if stage != TxListStage::StackedHavocMany {
                        self.mutate_one_stage(fc, stage);
                    }
                }
                if fc.txs.len() > 5 && self.rng.gen_bool(0.1) {
                    self.mutate_one_stage(fc, TxListStage::DropOneFunction);
                }
            }
            TxListStage::ObtainCmpTrace => {
                use std::os::unix::ffi::OsStrExt;
                //if self.allow_prints {
                //    println!(
                //        "[EthMutator] trying custom cmptrace on input {:?} with binary {:?}",
                //        self.cur_filename,
                //        if let Some(p) = &self.cur_binary_path {
                //            let p_ostr = std::ffi::OsStr::from_bytes(p.to_bytes());
                //            let pb = std::path::PathBuf::from(p_ostr);
                //            Some(pb)
                //        } else {
                //            cmptrace::guess_target_binary_path()
                //        }
                //    );
                //}

                if self.allow_comptrace {
                    let now = std::time::Instant::now();
                    let traces = if let Some(cur_filename) = self.cur_filename.as_ref() {
                        let mut ti = self
                            .testcase_info
                            .entry(cur_filename.clone())
                            .or_insert_with(TestcaseStats::default);

                        if !ti.obtained_cmp_logs {
                            let inp_path_ostr =
                                std::ffi::OsStr::from_bytes(cur_filename.to_bytes());
                            let input_path = std::path::PathBuf::from(inp_path_ostr);

                            let cur_binary_path = if let Some(p) = &self.cur_binary_path {
                                let p_ostr = std::ffi::OsStr::from_bytes(p.to_bytes());
                                let pb = std::path::PathBuf::from(p_ostr);
                                Some(pb)
                            } else {
                                cmptrace::guess_target_binary_path()
                            };

                            if let Some(cur_binary_path) = cur_binary_path {
                                let program = cur_binary_path.as_os_str();

                                let traces = cmptrace::obtain_trace_for_input(
                                    program,
                                    &input_path,
                                    *TRACE_TIMEOUT,
                                );
                                ti.obtained_cmp_logs = true;
                                Some(traces)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let trace_time = now.elapsed();

                    let now = std::time::Instant::now();
                    let mut newvals = 0;
                    if let Some(traces) = traces {
                        use cmptrace::TraceEntry;
                        let tlen = traces.len();

                        // we just stupidly add the obtained values to the dictionary
                        for trace in traces.into_iter() {
                            match trace {
                                TraceEntry::Cmp(cmptrace) => {
                                    let b1 = self.dict.add_value_maybe(cmptrace.arg0);
                                    let b2 = self.dict.add_value_maybe(cmptrace.arg1);
                                    if b1 {
                                        newvals += 1;
                                    }
                                    if b2 {
                                        newvals += 1;
                                    }
                                    #[cfg(debug_assertions)]
                                    if self.allow_prints && (b1 || b2) {
                                        println!(
                                            "[EthMutator][CMPTRACE] obtained new value from {:?}",
                                            cmptrace
                                        );
                                    }
                                }
                                TraceEntry::Ret(rettrace) => {
                                    let x =
                                        self.process_output_for_sig(rettrace.sig, &rettrace.arg);
                                    #[cfg(debug_assertions)]
                                    if self.allow_prints && x > 0 {
                                        println!(
                                            "[EthMutator][CMPTRACE] obtained new values from {:?}",
                                            rettrace
                                        );
                                    }
                                    newvals += x;
                                }
                            }
                        }

                        self.log(MutationStageLog::List(TxListStage::ObtainCmpTrace));

                        let proctime = now.elapsed();
                        if self.allow_prints {
                            println!("[EthMutator][CMPTRACE] tracing => {} traces in {} μsec; processing => {} μsec; obtained {} new values => {}",
                                     tlen, trace_time.as_micros(), proctime.as_micros(), newvals, self.dict.stats());
                        }
                    }
                }

                // finally we do some havocs after obtaining the cmptrace dictionary
                self.mutate_one_stage(fc, TxListStage::StackedHavocMany);
            }
        }
    }

    pub fn mutate_one(&mut self, fc: &mut FuzzCase) {
        let stage: TxListStage = self.rng.gen();
        self.mutate_one_stage(fc, stage);
    }

    /// Instead of applying both structural (and possibly) input mutations, we sometimes
    /// limit ourselves to input mutations only for longer transaction sequences. The
    /// idea here is that we will want to try to mutate the inputs once we have
    /// discovered a somewhat useful transaction sequence and discover coverage within the
    /// transactions.
    fn only_mutate_many_tx(&mut self, transactions: &mut TransactionList) {
        if transactions.len() < 5 {
            self.mutate_all_tx(transactions);
            return;
        }

        self.log(MutationStageLog::List(TxListStage::OnlyMutateManyTx));

        // mutate transaction at the end with a higher probability
        // this is also scaled according to the transaction length.
        // here is a breakdown of the probabilities for certain indices:
        //
        // | l  | [0]  | [1]  | [2]  | [3]  | [4]  | [5]  | [6]  | [7]  | [8]  | [9]  |
        // | 5  | 0.02 | 0.18 | 0.34 | 0.50 | 0.66 |                                  |
        // | 10 | 0.01 | 0.09 | 0.17 | 0.25 | 0.33 | 0.41 | 0.49 | 0.57 | 0.65 | 0.73 |

        let mut mutated_one = false;
        for idx in (0..transactions.len()).into_iter().rev() {
            let idxf = idx as f64;
            let lenf = transactions.len() as f64;
            let p = (idxf + 0.1) / (lenf + (lenf / 4.0));
            let p = if p > 1.0 { 0.99 } else { p };
            let p = if p < 0.0 { 0.01 } else { p };
            if self.rng.gen_bool(p) {
                mutated_one = true;
                self.mutate_tx(&mut transactions[idx], None);
            }
        }

        // However, if for some odd chance, not a single tx was mutated. select one at random
        // and mutate it.
        if !mutated_one {
            // make sure we mutate at least one transaction
            let i: usize = self.rng.gen_range(0..transactions.len());
            self.mutate_tx(&mut transactions[i], None);
            // randomly mutate some transactions in the sequence, but with quite a bias
            // towards mutating only 1 or 2 transactions.
            let count = if self.rng.gen_bool(0.3) {
                self.rng.gen_range(1..=2)
            } else {
                self.rng.gen_range(3..transactions.len())
            };
            for _ in 0..count {
                let i: usize = self.rng.gen_range(0..transactions.len());
                self.mutate_tx(&mut transactions[i], None);
            }
        }
    }

    /// if we approach the maximum number of transactions performed by the harness, we start to
    /// force transaction drops or deduplication of tx.
    fn ensure_txs_length_is_reasonable(&mut self, transactions: &mut TransactionList) {
        // if we approach the maximum number of transactions performed by the harness, we start to
        // force transaction drops or deduplication
        if transactions.len() >= HARNESS_MAX_TX && self.rng.gen_bool(0.99) {
            let drop_txs = self.rng.gen_bool(0.8);
            if drop_txs {
                self.drop_tx(transactions);
            } else {
                self.dedup_by_sig(transactions);
            }
            while transactions.len() >= (HARNESS_MAX_TX - 3) {
                self.drop_random_transaction(transactions);
            }
        }
    }

    /// Mutate the given bytes. This will first attempt to parse the given bytes, which naturally
    /// applies a normalization routine - our parser never fails in the worst case returns an all
    /// empty/default [`FuzzCase`]. This means that any input that is append by the base fuzzer
    /// might simply be ignored by this... Not ideal but seems work pretty well anyway. Currently we
    /// randomly choose two mutations out of the [`TxListStage`] enum. However, we do have two
    /// special cases, that are applied first:
    /// * If the transaction list is empty we first create and insert a single transaction.
    /// * If the transaction list approaches the maximum length, we try to reduce the length of the
    ///   transaction list beforhand by applying the probabilistic drop or deduplication mutations.
    ///
    /// Also:
    /// * We do not drop transactions if the transaction list length is <= 3; instead we shuffle
    ///
    /// NOTE: This is a general mutation, which is not using the staged approach. It applies many
    /// stacked mutations and returns a single resulting fuzzcase. This works fine and is
    /// easier to integrate. However, it also results in a fuzzer with higher variance. In a staged
    /// approach we check the mutated [`FuzzCase`] after every small-scale mutation and only fall
    /// back to stacked mutations at the end (similar to AFL's design with deterministic, havoc and
    /// stacked havoc). Check out the [`start_round`] and [`mutate_round`] methods for this.
    pub fn mutate_fuzzcase(&mut self, fc: &mut FuzzCase) {
        let transactions = &mut fc.txs;
        self.reset_log();

        self.ensure_txs_length_is_reasonable(transactions);
        let transactions = &mut fc.txs;

        if transactions.is_empty() {
            if !self.contracts.is_empty() && self.rng.gen_bool(0.25) {
                // we know about all functions; so we add them in a random order;
                // basically this allows us to get started quickly even without a seed file
                self.add_all_abi_functions(transactions);
            } else {
                self.add_tx(transactions);
            }
        } else {
            // sometimes add all known abi functions to the the current testcase.
            if transactions.len() < 10 && (!self.contracts.is_empty()) && self.rng.gen_bool(0.01) {
                self.add_all_abi_functions(transactions);
            }

            // So currently the fuzzing harness aborts processing whenever a revert is encountered.
            // Typically the last transaction in the harness is the cuplrit here; so it makes sense
            // to mutate the last transaction in the list.
            if self.rng.gen_bool(0.8) {
                self.log(MutationStageLog::List(TxListStage::MutateLastTx));
                self.mutate_tx(transactions.last_mut().unwrap(), None);
            }
            // with a much smaller chance we also mutate the second to last.
            if transactions.len() > 2 && self.rng.gen_bool(0.2) {
                self.log(MutationStageLog::List(TxListStage::MutateSingleTx));
                let idx = transactions.len() - 2;
                self.mutate_tx(&mut transactions[idx], None);
            }

            if transactions.len() >= 5 && self.rng.gen_bool(0.4) {
                self.only_mutate_many_tx(transactions);
            } else {
                let i = self.rng.gen_range(0..5);
                // perform some mutation stages
                for _ in 0..i {
                    self.mutate_one(fc);
                }
            }
        }

        ensure_reasonable_fuzzcase(fc);
    }

    /// Parse bytes, mutate fuzzcase, pack back into [`buffer`]
    pub fn mutate(&mut self, bytes: &[u8]) {
        let mut fc = parse_bytes(bytes);
        self.mutate_fuzzcase(&mut fc);
        pack_into_bytes(&fc, &mut self.buffer);
    }

    /// Parse bytes, apply a single mutation operator on the fuzzcase, pack back into [`buffer`]
    pub fn mutate_bytes_one(&mut self, bytes: &[u8]) {
        self.reset_log();
        let mut fc = parse_bytes(bytes);
        let fclen = fc.txs.len();
        if fclen >= 5 && self.rng.gen_bool(0.4) {
            self.only_mutate_many_tx(&mut fc.txs);
        } else {
            self.mutate_one(&mut fc);
        }
        ensure_reasonable_fuzzcase(&mut fc);
        pack_into_bytes(&fc, &mut self.buffer);
    }

    /// Instead of mutating in-place, clone and then mutate
    pub fn mutate_to_new_fuzzcase(&mut self, fc: &FuzzCase) -> FuzzCase {
        let mut new = fc.clone();
        self.mutate_fuzzcase(&mut new);
        new
    }

    /// Called if we have a filename available for the current testcase. This allows the mutator to
    /// keep track of per-testcase statistics, which are then used to slightly tweak the fuzzing
    /// process.
    pub fn cache_filename(&mut self, filename: CString) {
        self.cur_filename = Some(filename)
    }

    /// Start a staged fuzzing round. Here the fuzzer will first parse the testcase and then select
    /// the number of mutation rounds it likes to perform and the kind of mutations based on the
    /// size/properties of the [`FuzzCase`] and also on the preferred rounds of the base fuzzer.
    ///
    /// This method will set up the internal state of the mutator. After each [`start_round`], one
    /// can call [`mutate_round`] to obtain the next mutation of the [`FuzzCase`] passed as the
    /// `bytes` argument to this method.
    pub fn start_round(&mut self, bytes: &[u8], fuzzer_preferred_rounds: usize) -> usize {
        self.reset_log();
        let mut fuzzed_count = 0;
        if let Some(cur_filename) = &self.cur_filename {
            let ti = self
                .testcase_info
                .entry(cur_filename.clone())
                .or_insert_with(TestcaseStats::default);
            fuzzed_count = ti.fuzzed_count;
            ti.fuzzed_count = ti.fuzzed_count.saturating_add(1);
        }

        let fc = parse_bytes(bytes);
        let len = fc.txs.len();

        // The empty testcase is only relevant for generating some initial seeds. Once we fuzzed it,
        // there is not a lot we gain by fuzzing it more.
        if len == 0 && fuzzed_count > 0 {
            return 0;
        }

        // we try to spend more time fuzzing diverse transaction sequences. The idea is that a
        // diverse transaction sequence is more likely to trigger interesting behavior.
        let mut seen_sigs: SmallSet<u32> = SmallSet::new();
        let mut tx_hashes: SmallSet<u64> = SmallSet::new();
        let mut duplicated_sigs: usize = 0;
        for tx in fc.txs.iter() {
            if let Some(tx_sig) = sig_from_input(&tx.input) {
                if self.is_good_sig(tx_sig) {
                    if !seen_sigs.insert(tx_sig) {
                        duplicated_sigs += 1;
                    }
                    //seen_sigs.insert(tx_sig);

                    if tx.input.len() > 4 {
                        let hash = calculate_hash(&tx.input);
                        tx_hashes.insert(hash);
                    }
                }
            }
        }

        // double the preferred rounds wrt to what the fuzzer asks us to do.
        let preferred_rounds = fuzzer_preferred_rounds * 2;

        // we adjust the rounds according to the given testcase.
        // more diverse -> more rounds
        // however, we bound this to a maximum
        let rounds = preferred_rounds;
        let rounds = rounds + (preferred_rounds * seen_sigs.len() / 5);
        let rounds = rounds + (preferred_rounds * tx_hashes.len() / 16);
        let rounds = if duplicated_sigs >= 5 {
            let sub = preferred_rounds * duplicated_sigs / 10;
            let (v, o) = rounds.overflowing_sub(sub);
            if o {
                // in case we have soooo many duplicated_sigs sigs, that we would provoke an
                // underflow, we handle it by going back to the originally preferred_rounds
                // value. this is a weird testcases anyway so better not to mutate too much...
                preferred_rounds
            } else {
                v
            }
        } else {
            rounds
        };

        // add a penalty for repetedly fuzzing small transaction sequences. At some point we want to
        // focus more on the longer TX sequences.
        let rounds = if len < 3 && fuzzed_count > 128 && self.queue.len() > 32 {
            rounds / 3
        } else if len < 5 && fuzzed_count > 1024 && self.queue.len() > 32 {
            rounds / 2
        } else {
            rounds
        };

        let rounds = if len > HARNESS_MAX_TX {
            fuzzer_preferred_rounds * 2
        } else {
            rounds
        };

        // don't go overboard
        let rounds = std::cmp::min(rounds, fuzzer_preferred_rounds * 10);

        // I hope this monstrosity is optimized away...
        let stagelist_max_len: usize = std::cmp::max(
            DEFAULT_STAGES_LARGE.len(),
            std::cmp::max(DEFAULT_STAGES_VERY_SMALL.len(), DEFAULT_STAGES_SMALL.len()),
        );
        // but don't go too low that we can't even go through all the default stages at least once.
        let rounds = std::cmp::max(rounds, stagelist_max_len);

        // run everyone of the deterministic transaction stages on every transaction three times.
        let det_rounds = len * DEFAULT_TX_STAGES_DET.len() * 3;

        let additional_havocs = if len == 0 || len > HARNESS_MAX_TX {
            0
        } else if len < 6 {
            std::cmp::min(fuzzer_preferred_rounds * 2, rounds / 7)
        } else {
            std::cmp::min(fuzzer_preferred_rounds, rounds / 7)
        };

        if len == 0 {
            // we are mutating the empty testcase -> essentially we will now generate seed files.
            let limit = if !self.contracts.is_empty() {
                self.contract_funcsigs.len() * 15
            } else {
                150
            };
            self.round_stages = DEFAULT_STAGES_EMPTY
                .iter()
                .cycle()
                .take(std::cmp::max(limit, rounds));
            self.tx_round_stages = DEFAULT_TX_STAGES_NONE.iter().cycle().take(0);
            self.cur_tx_idx = None;
        } else if len <= 3 {
            // 1..=3
            self.round_stages = DEFAULT_STAGES_VERY_SMALL.iter().cycle().take(rounds);
            self.tx_round_stages = DEFAULT_TX_STAGES_DET.iter().cycle().take(det_rounds);
            self.cur_tx_idx = Some(len - 1);
        } else if len <= 6 {
            // 4..=6
            self.round_stages = DEFAULT_STAGES_SMALL.iter().cycle().take(rounds);
            self.tx_round_stages = DEFAULT_TX_STAGES_DET.iter().cycle().take(det_rounds);
            self.cur_tx_idx = Some(len - 1);
        } else if len <= (HARNESS_MAX_TX / 2) {
            // 7..=32
            self.round_stages = DEFAULT_STAGES_LARGE.iter().cycle().take(rounds);
            self.tx_round_stages = DEFAULT_TX_STAGES_DET.iter().cycle().take(det_rounds);
            self.cur_tx_idx = Some(len - 1);
        } else if len <= HARNESS_MAX_TX {
            // 32..=64
            self.round_stages = DEFAULT_STAGES_LARGE.iter().cycle().take(rounds);

            if fuzzed_count != 0 {
                // large transaction list; so we skip the deterministic transaction mutations
                // if we have fuzzed this before.
                self.tx_round_stages = DEFAULT_TX_STAGES_NONE.iter().cycle().take(0);
                self.cur_tx_idx = None;
            } else {
                self.tx_round_stages = DEFAULT_TX_STAGES_DET.iter().cycle().take(det_rounds);
                self.cur_tx_idx = Some(len - 1);
            }
        } else {
            // 64..
            // very large transaction list; so we skip the deterministic transaction mutations
            self.tx_round_stages = DEFAULT_TX_STAGES_NONE.iter().cycle().take(0);
            self.cur_tx_idx = None;
            // we also only do stacked havocs in this case.
            self.round_stages = DEFAULT_STAGES_NONE.iter().cycle().take(0);
        };

        // the idea is the following:
        // 1. Smaller testcases might benefit from performing multiple mutation actions at once. The
        //    idea is that we get to some useful transaction sequence fast.
        // 2. Larger transaction sequences probably have some inter-dependencies that make it likely that two
        //    unrelated mutations actually break these inter-dependencies, therefore single
        //    incremental mutations are preferred. The same if we have tried to fuzz the testcase a
        //    lot before. We then try more lightweight mutations.
        //let combined_havoc_count = 20 * (HARNESS_MAX_TX.saturating_sub(len) + 2);
        //let single_havoc_count = 30 * (len + 3) + 2 * std::cmp::max(255, (*stats).fuzzed_count);

        // new idea: just let afl decide about how often to fuzz a testcase.
        //let combined_havoc_count = (preferred_rounds - self.round_stages.len()) * 1 / 3;
        //let combined_havoc_count = 0;

        //let oldlen = self.round_stages.len();
        //let newlen = oldlen + combined_havoc_count;
        //self.round_stages
        //    .resize(newlen, TxListStage::StackedHavocMany);

        //let single_havoc_count = preferred_rounds - self.round_stages.len();

        //if (*stats).fuzzed_count == 1 {

        //}

        //self.round_stages.truncate(preferred_rounds);

        if self.allow_prints {
            println!("[EthMutator] starting fuzzing round on FuzzCase with {} tx with {} rounds ({:?} base mutations, {:?} deterministic round, and {} additional havocs; fuzzer requested {} rounds; queue size {}; previously fuzzed {})",
                     fc.txs.len(), rounds, self.round_stages.size_hint().1, self.tx_round_stages.size_hint().1, additional_havocs, fuzzer_preferred_rounds, self.queue.len(), fuzzed_count);
            #[cfg(debug_assertions)]
            {
                // if let Some(rc) = self.contract.clone() {
                //     let c = &*rc;
                //     let _ = print_fuzzcase(&fc, Some(c));
                // } else {
                //     let _ = print_fuzzcase(&fc, None);
                // }

                let _ = print_fuzzcase(&fc, None);
            }
        }

        self.cur_fuzzcase = Some(fc);
        rounds + det_rounds + additional_havocs
    }

    /// Mutate a previously parsed [`FuzzCase`]. Must first call [`start_round`] to set up the
    /// [`FuzzCase`] and the fuzzing rounds.
    ///
    /// Typically, [`start_round`] will deterministically select certain mutation operators for each
    /// transaction in a test case (stored in [`self.tx_round_stages`] and [`self.cur_tx_idx`]). This method will
    /// first cycle through these stages. Once these are processed it will perform structural
    /// mutations on the transaction list using the [`mutate_round_fuzzcase`] method.
    pub fn mutate_round(&mut self) {
        self.reset_log();
        let mut fc = self.cur_fuzzcase.as_ref().unwrap().clone();
        if let Some(stage) = self.tx_round_stages.next() {
            let idx = if let Some(idx) = self.cur_tx_idx {
                idx
            } else {
                fc.txs.len() - 1
            };

            self.mutate_tx(&mut fc.txs[idx], Some(*stage));

            if stage == DEFAULT_TX_STAGES_DET.last().unwrap() {
                if idx > 0 {
                    let next_idx = idx - 1;
                    self.cur_tx_idx = Some(next_idx);
                } else {
                    self.cur_tx_idx = None;
                }
            }
        } else {
            self.mutate_round_fuzzcase(&mut fc);
        }

        ensure_reasonable_fuzzcase(&mut fc);
        pack_into_bytes(&fc, &mut self.buffer);
    }

    /// Perform mutation round on a fuzzcase, focusing on structural mutations. If there are stages
    /// set up by [`start_round`], this method follows those first. If those are done or not set up
    /// this function falls back to using stacked havoc mutations, i.e., it combines a bunch of
    /// mutation operators randomly.
    pub fn mutate_round_fuzzcase(&mut self, fc: &mut FuzzCase) {
        self.reset_log();

        let transactions = &mut fc.txs;
        self.ensure_txs_length_is_reasonable(transactions);

        let stage = if let Some(stage) = self.round_stages.next() {
            *stage
        } else {
            //let stage: TxListStage = self.rng.gen();
            //stage
            TxListStage::StackedHavocMany
        };
        self.mutate_one_stage(fc, stage);
    }

    pub fn describe_string(&self) -> &[u8] {
        &self.describe_string
    }

    pub fn format_stages_as_string(&mut self) {
        let mut s = String::new();
        s.push_str("[EthMutator Introspection] ");
        for stage in self.stages.iter() {
            s.push_str(&format!("{:?}-", stage));
        }
        let cs = CString::new(s.as_bytes()).unwrap();
        self.stages_as_string = Some(cs);
    }

    pub fn obtain_stages_string(&self) -> &std::ffi::CStr {
        self.stages_as_string.as_ref().unwrap()
    }

    /// parse the given raw bytes into a [`FuzzCase`] and then add the transaction list to the
    /// internal queue.
    pub fn push_to_queue(&mut self, bytes: &[u8]) {
        let mut fc = parse_bytes(bytes);
        ensure_reasonable_fuzzcase(&mut fc);
        self.push_parsed_to_queue(fc);
    }

    /// shuffle the internal queue. This is primarily useful for testing and not so much during
    /// regular fuzzing.
    pub fn shuffle_queue(&mut self) {
        let mut queue: Vec<TransactionList> = self.queue.drain(..).collect();
        queue.shuffle(&mut self.rng);
        self.queue.extend(queue);
    }

    /// Push an already parsed [`FuzzCase`] to the internal queue.
    pub fn push_parsed_to_queue(&mut self, fc: FuzzCase) {
        if fc.txs.is_empty() {
            return;
        }
        let txs_len = fc.txs.len();
        #[cfg(debug_assertions)]
        let is_new = self.queue.insert(fc.txs.clone());
        #[cfg(not(debug_assertions))]
        let is_new = self.queue.insert(fc.txs);

        if is_new && self.allow_prints {
            println!(
                "[EthMutator] new queue entry with {} bytes and {} tx - total queue len {}",
                self.trim_buffer.len(),
                txs_len,
                self.queue.len(),
            );

            #[cfg(debug_assertions)]
            {
                // if let Some(rc) = self.contract.clone() {
                //     let c = &*rc;
                //     let _ = print_fuzzcase(&fc, Some(c));
                // } else {
                //     let _ = print_fuzzcase(&fc, None);
                // }

                let _ = print_fuzzcase(&fc, None);
            }
        }
    }

    pub fn post_process(&mut self, bytes: &[u8]) {
        // not sure whether this is useful?
        let transactions = parse_bytes(bytes);
        self.buffer = pack_to_bytes(&transactions);
    }

    pub fn init_trim(&mut self, bytes: &[u8]) -> usize {
        let fuzzcase = parse_bytes(bytes);
        self.trim_buffer = pack_to_bytes(&fuzzcase);
        self.trimmer = Some(FuzzcaseTrimmer::from(fuzzcase));
        let expected_steps = self.trimmer.as_ref().unwrap().steps().0;
        if self.allow_prints {
            println!(
                "[EthMutator] init trim with {} bytes {} parsed bytes and {} expected steps",
                bytes.len(),
                self.trim_buffer.len(),
                expected_steps
            );
        }
        self.trim_start_time = std::time::Instant::now();
        expected_steps
    }

    pub fn trim_step(&mut self) -> usize {
        if let Some(trimmer) = self.trimmer.as_mut() {
            if let Some(fc) = trimmer.next() {
                pack_into_bytes(&fc, &mut self.trim_buffer);
                //println!(
                //    "[EthMutator] trim step {:?} with {} bytes",
                //    trimmer.current_stage(),
                //    self.trim_buffer.len()
                //);
            }
            self.trim_buffer.len()
        } else {
            panic!("trim_step called without calling init_trim first!");
        }
    }

    pub fn trim_status(&mut self, success: bool) -> usize {
        if let Some(trimmer) = self.trimmer.as_mut() {
            if !success {
                trimmer.rollback();
            }

            let (e, p) = trimmer.steps();
            if trimmer.is_done() {
                if self.allow_prints {
                    println!(
                        "[EthMutator] trim finish in {} μsec with {} bytes",
                        self.trim_start_time.elapsed().as_micros(),
                        self.trim_buffer.len()
                    );
                }

                let fc = trimmer.get_current();
                pack_into_bytes(&fc, &mut self.trim_buffer);
                self.push_parsed_to_queue(fc);

                e
            } else if p >= e {
                e - 1
            } else {
                p
            }
        } else {
            panic!("trim_status without init_trim first!");
        }
    }

    /// Given an ethabi token, add it to the fuzzer dictionary.
    pub fn add_token_to_dict(&mut self, token: Token) -> bool {
        match token {
            Token::Address(a) => {
                let mut v: Vec<u8> = Vec::with_capacity(32);
                v.resize(32 - 20, 0);
                v.extend(a.as_bytes());
                self.dict.add_value(U256::from_big_endian(&v))
            }
            Token::FixedBytes(b) | Token::Bytes(b) => {
                let mut r = false;
                match b.len() {
                    // in case the contract casts between bytes32 and uint256 or between bytes20 and
                    // address.
                    20 | 32 => {
                        let v = U256::from_big_endian(&b);
                        r |= self.dict.add_value_maybe(v);
                    }
                    _ => {}
                }
                r |= self.dict.add_bytes(b.into_boxed_slice());
                r
            }
            Token::Int(i) | Token::Uint(i) => self.dict.add_value_maybe(i),
            Token::Array(v) | Token::FixedArray(v) | Token::Tuple(v) => {
                let mut r = false;
                for t in v.into_iter() {
                    r |= self.add_token_to_dict(t);
                }
                r
            }
            Token::String(s) => self.dict.add_string(s),
            Token::Bool(_) => false,
        }
    }

    /// given the 4-byte sig from the respective input, attempt to decode the output according to
    /// the ABI, if available. Otherwise just attempt to add the first 32 bytes as a value to the
    /// dictionary.
    pub fn process_output_for_sig(&mut self, sig: u32, output: &[u8]) -> usize {
        let mut num = 0;
        if !output.is_empty() {
            let mut done = false;
            if self.is_good_sig(sig) {
                // TODO: we guess the contract based on the signature. If we have duplicated
                // signatures (which is actually quite common), then we try to decode with all the
                // contracts that have that signature. This is quite ineffective and adds some
                // pointless iterations here. This is not optimal. We would require the harness to
                // report the tx_receiver field along with the signature.
                for cidx in 0..(self.contracts.len()) {
                    if let Some(rc) = self.get_contract(cidx) {
                        let functions = &rc.functions;
                        if let Some(func) = find_function_for_sig(functions, sig) {
                            // it is a known function and has input parameters
                            // we need to put a max length here to avoid OOMs
                            if !func.outputs.is_empty() && output.len() < MAX_OUTPUT_TRY_DECODE {
                                if let Ok(decoded) = func.decode_output(output) {
                                    for t in decoded.into_iter() {
                                        #[cfg(debug_assertions)]
                                        let b = self.add_token_to_dict(t.clone());
                                        #[cfg(not(debug_assertions))]
                                        let b = self.add_token_to_dict(t);
                                        if b {
                                            num += 1;
                                            #[cfg(debug_assertions)]
                                            if self.allow_prints {
                                                println!(
                                                "[EthMutator][CMPTRACE] obtained new token {:?}",
                                                t
                                            );
                                            }
                                        }
                                    }
                                    done = true;
                                }
                            }
                        }
                    }
                }
            }

            if !done {
                if output.len() >= 32 {
                    let v = U256::from_big_endian(&output[0..32]);
                    if v > U256_ONE {
                        if self.dict.add_value(v) {
                            num += 1;
                        }
                    }
                }

                self.dict.add_bytes(output.to_vec().into_boxed_slice());
                num += 1;
            }
        }
        num
    }

    /// given the input for a transaction and the output data produced by the smart contract,
    /// process the output, if possible according to the ABI, properly decoding the output data.
    pub fn process_output(&mut self, input: &[u8], output: &[u8]) {
        if input.len() >= 4 {
            let tx_sig = sig_from_input(input).unwrap();
            self.dict.add_u32(tx_sig);
            self.process_output_for_sig(tx_sig, output);
        }
    }
}
