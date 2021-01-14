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

use sha3::Digest;
use std::convert::TryInto;

use crate::types::*;

/// swap b[x..x + l] and b[y..y + l]
pub fn vec_bswap<const L: usize>(b: &mut Vec<u8>, x: usize, y: usize) {
    if x != y {
        let xl = x + L;
        let yl = y + L;
        if xl <= b.len() && yl <= b.len() && (y >= (x + L) || y < x) {
            // fast (but unsafe) swapping; the stdlib is hopefully doing the fastest that is
            // possible here.
            unsafe {
                std::ptr::swap_nonoverlapping(
                    b[y..(y + L)].as_mut_ptr(),
                    b[x..(x + L)].as_mut_ptr(),
                    L,
                );
            }
        } else {
            if xl > b.len() {
                panic!(
                    "out-of-bounds via x access to b[{}] with b.len == {}",
                    xl - 1,
                    b.len()
                )
            }
            if yl > b.len() {
                panic!(
                    "out-of-bounds via y access to b[{}] with b.len == {}",
                    yl - 1,
                    b.len()
                )
            }
            // fall back to slooow stuff
            for i in 0..L {
                b.swap(x + i, y + i);
            }
        }
    }
}

/// Compute sha3 over function name and parameters to obtain signature
///
/// taken from ethabi internals, because they do not expose it as public:
/// https://github.com/rust-ethereum/ethabi/blob/v13.0.0/ethabi/src/signature.rs
fn fill_signature(name: &str, params: &[ethabi::param_type::ParamType], result: &mut [u8]) {
    let types = params
        .iter()
        .map(ethabi::param_type::Writer::write)
        .collect::<Vec<String>>()
        .join(",");

    let data: Vec<u8> = From::from(format!("{}({})", name, types).as_str());

    result.copy_from_slice(&sha3::Keccak256::digest(&data)[..result.len()])
}

// TODO: latest ethabi exposes the short_signature function publicly - so we can use it now.

/// Compute the 4-byte short signature for the function with name and params; short signature is
/// returned as u32 for easier processing. see also [`fill_signature`].
pub fn short_signature(name: &str, params: &[ethabi::param_type::ParamType]) -> u32 {
    let mut result = [0u8; 4];
    fill_signature(name, params, &mut result);
    u32::from_be_bytes(result)
}

/// if possible extract first four bytes as u32
#[inline]
pub fn sig_from_input(input: &[u8]) -> Option<u32> {
    if input.len() >= 4 {
        Some(u32::from_be_bytes(input[0..4].try_into().unwrap()))
    } else {
        None
    }
}

/// iterate through list of `(u32, ethabi::Function)` pairs and return a reference to the
/// [`ethabi::Function`] if `u32` matches the provided `tx_sig` parameter.
pub fn find_function_for_sig(
    functions: &[(u32, ethabi::Function)],
    tx_sig: u32,
) -> Option<&ethabi::Function> {
    if let Some((_, f)) = functions.iter().find(|(sig, _)| *sig == tx_sig) {
        Some(f)
    } else {
        None
    }
}

#[inline]
pub fn splitted_hex_string<const AFTER: usize>(input_bytes: &[u8]) -> String {
    let mut s = String::with_capacity(input_bytes.len() * 2 + 2 + input_bytes.len() / AFTER);
    // s.push_str("0x");
    for chunk in input_bytes.chunks(AFTER).map(|x| hexutil::to_hex(x)) {
        s.push_str(hexutil::clean_0x(&chunk));
        s.push(' ');
    }

    s
}

pub fn format_tokens(tokens: &[ethabi::Token], sep: &str) -> String {
    let mut resstr = String::new();
    for token in tokens {
        use ethabi::Token::*;
        let tstring = match token {
            FixedBytes(b) => {
                format!("bytes{}(0x{})", b.len(), token)
            }
            Bytes(b) => {
                format!("bytes[{}](0x{})", b.len(), token)
            }
            String(s) => {
                format!("string[{}]({:?})", s.len(), s)
            }
            FixedArray(v) => {
                let s = format_tokens(&v, sep);
                format!("array{}({})", v.len(), s)
            }
            Array(v) => {
                let s = format_tokens(&v, sep);
                format!("array[{}]({})", v.len(), s)
            }
            Tuple(v) => {
                let s = format_tokens(&v, sep);
                format!("tuple{}({})", v.len(), s)
            }
            _ => {
                let mut s = format!("{:?}", token);
                s.make_ascii_lowercase();
                s
            }
        };
        resstr.push_str(&tstring);
        resstr.push_str(sep);
    }
    resstr
}

pub fn format_function_input(
    input: &[u8],
    contractinfo: Option<&ContractInfo>,
) -> anyhow::Result<String> {
    let mut res = String::new();
    if let Some((contract, functions)) = contractinfo {
        if input.len() >= 4 {
            let tx_sig = u32::from_be_bytes(input[0..4].try_into()?);
            if let Some((_, f)) = functions.iter().find(|(sig, _)| *sig == tx_sig) {
                let token_string = if let Ok(tokens) = f.decode_input(&input[4..]) {
                    let mut s = String::new();
                    s.push_str("{ ");
                    s.push_str(&format_tokens(&tokens, ", "));
                    // for t in tokens.into_iter() {
                    //     s.push_str(&format!("{}, ", t));
                    // }
                    s.push_str(" }");
                    s
                } else {
                    let hex_input = splitted_hex_string::<32>(&input[4..]);
                    format!("{} [failed to decode]", hex_input)
                };
                res += &format!(
                    "  func: {} ({:#x})\n  input: {}\n",
                    f.signature(),
                    tx_sig,
                    token_string
                );
            } else if contract.fallback {
                let hex_input = splitted_hex_string::<32>(input);
                res += &format!("  func: fallback()\n  input: {}\n", hex_input);
            } else {
                let hex_input = splitted_hex_string::<32>(&input[4..]);
                res += &format!("  sig: {:#x} (unknown)\n  input: {}\n", tx_sig, hex_input);
            }
        } else {
            let hex_input = splitted_hex_string::<32>(input);
            res += &format!("  input: {}\n", hex_input);
        }
    } else if input.len() >= 4 {
        let tx_sig = u32::from_be_bytes(input[0..4].try_into()?);
        let hex_input = splitted_hex_string::<32>(&input[4..]);
        res += &format!("  sig: {:#x}\n  input: {}\n", tx_sig, hex_input)
    } else {
        let hex_input = splitted_hex_string::<32>(input);
        res += &format!("  input: {}\n", hex_input);
    }
    anyhow::Result::Ok(res)
}

pub fn print_fuzzcase(
    fuzzcase: &FuzzCase,
    contractinfo: Option<&ContractInfo>,
) -> anyhow::Result<()> {
    let bh = &fuzzcase.header;
    let txs = &fuzzcase.txs;

    let number = bh.number;
    let difficulty = bh.difficulty;
    let gas_limit = bh.gas_limit;
    let timestamp = bh.timestamp;
    let initial_ether = bh.initial_ether;

    println!(
        "Block header:\n  number: {}\n  difficulty: {}\n  gas_limit: {}\n  timestamp: {}\n  initial_ether: {}\n",
        number, difficulty, gas_limit, timestamp, initial_ether
    );
    for (txidx, tx) in txs.iter().enumerate() {
        let (header, input, returns) = (&tx.header, &tx.input, &tx.returns);
        let call_value_fmt = if header.call_value & crate::ETHER_SHIFT_BITMASK == 0 {
            let call_value = header.call_value;
            format!("{:#x}", call_value)
        } else {
            let cv = header.call_value & (!crate::ETHER_SHIFT_BITMASK);
            let postfix = "0".repeat(crate::HARNESS_CALL_VALUE_SHIFT_BITS);
            format!("{:#x}{}", cv, postfix)
        };

        let sender_select = header.sender_select;
        let length = header.length;
        let block_advance = header.block_advance;

        println!(
            "TX[{}] with tx_sender[{}]; tx_receiver[{}]; call_value: {}; length: {}; block+={}; #returns={}",
            txidx,
            sender_select,
            tx.header.get_receiver_select(),
            call_value_fmt,
            length,
            block_advance,
            returns.len()
        );

        print!("{}", format_function_input(input, contractinfo)?);

        if !returns.is_empty() {
            println!("  returns:");
            for ret in returns {
                println!(
                    "    return val: {}; allows reenter: {}; data: {}",
                    ret.header.value,
                    ret.header.reenter,
                    hexutil::to_hex(&ret.data)
                );
            }
        }
    }

    anyhow::Result::Ok(())
}
