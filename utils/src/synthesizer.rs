// Copyright 2022 Michael Rodler
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

#[macro_use]
extern crate anyhow;
extern crate clap;
extern crate ethmutator;

use anyhow::Context;
use askama::Template;
use clap::{arg, Arg, Command};
use ethmutator::serializer::fuzzcase_from_yaml;
use ethmutator::{load_abi_filepath, parse_bytes, print_fuzzcase, ContractInfo, FuzzCase, U256};
use std::fs;
use std::path::PathBuf;

#[derive(Debug)]
enum Formats {
    Yaml,
    EFuzzCase,
}

mod filters {
    use super::{find_subslice, ContractInfo, U256};

    pub fn from_call_value(v: u64) -> ::askama::Result<String> {
        let v = ethmutator::normalize_call_value(v);
        Ok(format!("{:#x}", v))
    }

    #[allow(dead_code)]
    pub fn to_sender_address(i: &u8) -> ::askama::Result<String> {
        let addr = &ethmutator::TX_SENDER[(*i as usize) % ethmutator::TX_SENDER.len()];
        Ok(format!("address(0x00{:x})", addr))
    }

    pub fn as_address<T: std::fmt::LowerHex>(addr: &T) -> ::askama::Result<String> {
        Ok(format!("address(0x00{:x})", addr))
    }

    #[allow(dead_code)]
    pub fn to_bytes(data: &[u8]) -> ::askama::Result<String> {
        Ok(format!("bytes(hex\"{}\")", hex::encode(data)))
    }

    #[allow(dead_code)]
    pub fn to_bytes_js(data: &[u8]) -> ::askama::Result<String> {
        let mut s = String::new();
        s.push_str("eval(\"");
        for bptr in data.iter() {
            let b = *bptr;
            s.push_str(&format!("\\x{:02x}", b));
        }
        s.push_str("\")");
        Ok(s)
    }

    pub fn to_hexstring_js(data: &[u8]) -> ::askama::Result<String> {
        Ok(format!("(\"0x{}\")", hex::encode(data)))
    }

    pub fn to_bytes_addrfixup_single(data: &[u8]) -> ::askama::Result<String> {
        if data.len() == 0 {
            return Ok("bytes(\"\")".to_string());
        }

        let mut repls: Vec<(usize, usize)> = vec![];
        for (id, addr) in ethmutator::TX_SENDER.iter().enumerate() {
            let addrbytes = addr.as_bytes();
            let offsets = find_subslice(data, addrbytes);
            for off in offsets.into_iter() {
                repls.push((off, id));
            }
        }

        if repls.len() == 0 {
            return Ok(format!("bytes(hex\"{}\")", hex::encode(data)));
        }

        let mut s = String::new();
        // s.push_str("bytes.concat(");
        s.push_str("abi.encodePacked(");
        let mut start = 0;
        let last_repl = repls.len() - 1;

        for (repl_i, (off, _)) in repls.iter().enumerate() {
            s.push_str(&format!(
                "hex\"{}\", address(this)",
                hex::encode(&data[start..*off])
            ));
            if repl_i != last_repl {
                s.push_str(", ");
            }
            start = off + 20;
        }
        s.push_str(")");
        Ok(s)
    }

    pub fn to_bytes_addrfixup(data: &[u8]) -> ::askama::Result<String> {
        if data.len() == 0 {
            return Ok("bytes(\"\")".to_string());
        }

        let mut repls: Vec<(usize, usize)> = vec![];
        for (id, addr) in ethmutator::TX_SENDER.iter().enumerate() {
            let addrbytes = addr.as_bytes();
            let offsets = find_subslice(data, addrbytes);
            for off in offsets.into_iter() {
                repls.push((off, id));
            }
        }

        if repls.len() == 0 {
            return Ok(format!("bytes(hex\"{}\")", hex::encode(data)));
        } else {
            repls.sort_by_key(|x| x.0);
        }

        let mut s = String::new();
        // s.push_str("bytes.concat(");
        s.push_str("abi.encodePacked(");
        let mut start = 0;
        let last_repl = repls.len() - 1;

        for (repl_i, (off, id)) in repls.iter().enumerate() {
            s.push_str(&format!(
                "hex\"{}\", (manager.__id_to_address({}))",
                hex::encode(&data[start..*off]),
                id
            ));
            if repl_i != last_repl {
                s.push_str(", ");
            }
            start = off + 20;
        }
        s.push_str(")");
        Ok(s)
    }

    pub fn as_hex<T: std::fmt::LowerHex>(v: &T) -> ::askama::Result<String> {
        Ok(format!("{:#x}", v))
    }

    pub fn wei_to_ether(v: &U256) -> ::askama::Result<String> {
        let (d, r) = v.div_mod(U256::from(1000000000000000000u64));
        Ok(format!("{} ether and {} wei", d, r))
    }

    pub fn advance_to_time(ba: &u8) -> ::askama::Result<String> {
        let ba = *ba;
        if ba < 128u8 {
            Ok(format!("{} seconds", (ba as usize) * 60))
        } else {
            Ok(format!("{} weeks", ba - 127))
        }
    }

    pub fn abi_format(
        data: &[u8],
        contractinfo: &Option<ContractInfo>,
    ) -> ::askama::Result<String> {
        match ethmutator::format_function_input(data, contractinfo.as_ref()) {
            anyhow::Result::Ok(v) => Ok(v),
            anyhow::Result::Err(e) => {
                eprintln!("encountered error during formatting: {}", e);
                Ok(String::new())
            }
        }
    }
}

#[derive(Template, Debug)]
#[template(path = "single_attack.sol", escape = "none")]
struct SingleAttackDesc {
    fc: FuzzCase,
    required_budget: U256,
    header: ethmutator::BlockHeader,
    original_addr: ethmutator::H160,
    contractinfo: Option<ContractInfo>,
}

fn fuzzcase_to_solidity_single(
    fc: &FuzzCase,
    contractinfo: Option<ContractInfo>,
) -> anyhow::Result<String> {
    let mut required_budget = ethmutator::normalize_call_value(fc.header.initial_ether);
    let sender = fc.txs.first().unwrap().header.get_sender_select();
    let receiver = fc.txs.first().unwrap().header.get_receiver_select();
    let mut sketchy_send = false;
    let mut sketchy_recv = false;
    for tx in &fc.txs {
        // sanity check!
        if sketchy_send == false && sender != tx.header.get_sender_select() {
            sketchy_send = true;
            eprintln!(
                "[WARNING] Test case contains multiple senders! ({} vs. {})",
                sender,
                tx.header.get_receiver_select()
            )
        }
        if sketchy_recv == false && receiver != tx.header.get_receiver_select() {
            sketchy_recv = true;
            eprintln!(
                "[WARNING] Test case contains multiple receivers! ({} vs. {})",
                receiver,
                tx.header.get_receiver_select()
            );
        }
        let cv = ethmutator::normalize_call_value(tx.header.call_value);
        required_budget += cv;
    }

    if sketchy_send || sketchy_recv {
        eprintln!(
            "[WARNING] sketchy synthesis - this input does not seem to suit the 'single' template"
        );
    }

    let tmpl = SingleAttackDesc {
        fc: fc.clone(),
        required_budget,
        header: fc.header.clone(),
        original_addr: ethmutator::TX_SENDER[(sender as usize) % ethmutator::TX_SENDER.len()]
            .clone(),
        contractinfo,
    };
    anyhow::Result::Ok(tmpl.render()?)
}

#[derive(Template, Debug)]
#[template(path = "js-attack.js", escape = "none")]
struct JsAttackDesc {
    fc: FuzzCase,
    required_budget: U256,
    header: ethmutator::BlockHeader,
    contractinfo: Option<ContractInfo>,
}

fn fuzzcase_to_js(fc: &FuzzCase, contractinfo: Option<ContractInfo>) -> anyhow::Result<String> {
    let mut required_budget = ethmutator::normalize_call_value(fc.header.initial_ether);
    for tx in &fc.txs {
        let cv = ethmutator::normalize_call_value(tx.header.call_value);
        required_budget += cv;
    }

    let tmpl = JsAttackDesc {
        fc: fc.clone(),
        required_budget,
        header: fc.header.clone(),
        contractinfo,
    };
    anyhow::Result::Ok(tmpl.render()?)
}

#[derive(Debug)]
struct ContractDesc {
    id: usize,
    budget: U256,
    calls: Vec<usize>,
}

#[derive(Template, Debug)]
#[template(path = "attack.sol", escape = "none")]
struct AttackDesc {
    fc: FuzzCase,
    required_budget: U256,
    contracts: Vec<ContractDesc>,
    header: ethmutator::BlockHeader,
    contractinfo: Option<ContractInfo>,
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut result: Vec<usize> = Vec::new();
    let mut i = 0;
    if haystack.len() < needle.len() {
        return result;
    }
    let needle_len = needle.len();
    while (i + needle_len) <= haystack.len() {
        if haystack[i..].starts_with(needle) {
            result.push(i);
            i += needle_len;
        } else {
            i += 1;
        }
    }
    result
}

fn fuzzcase_to_solidity(
    fc: &FuzzCase,
    contractinfo: Option<ContractInfo>,
) -> anyhow::Result<String> {
    let mut required_budget = ethmutator::normalize_call_value(fc.header.initial_ether);

    let mut contracts: Vec<ContractDesc> = Vec::with_capacity(ethmutator::TX_SENDER.len());
    for i in 0..ethmutator::TX_SENDER.len() {
        contracts.push(ContractDesc {
            id: i,
            calls: Vec::new(),
            budget: U256::zero(),
        });
    }

    for (i, tx) in fc.txs.iter().enumerate() {
        let idx = (tx.header.sender_select as usize) % contracts.len();
        contracts[idx].calls.push(i);
        let cv = ethmutator::normalize_call_value(tx.header.call_value);
        contracts[idx].budget += cv;
        required_budget += cv;
    }

    let tmpl = AttackDesc {
        fc: fc.clone(),
        required_budget,
        contracts,
        header: fc.header.clone(),
        contractinfo,
    };
    anyhow::Result::Ok(tmpl.render()?)
}

fn main() -> anyhow::Result<()> {
    let app = Command::new(env!("CARGO_BIN_NAME"))
        .about("transform fuzzcase format of eEVM Fuzzer and ethmutator")
        .version(ethmutator::VERSION)
        .arg(arg!(-v --verbose "increase verbosity"))
        .arg(
            Arg::new("input-format")
                .short('i')
                .help("input format")
                .possible_values(&["yaml", "efuzzcase"]),
        )
        .arg(
            Arg::new("exploit-style")
                .short('e')
                .takes_value(true)
                .ignore_case(true)
                .value_parser(["multi", "single", "js"])
                .default_value("multi")
                .help("'single' generates a single attacker contract for a single target (reentrancy supported; simpler code than multi). 'multi' generates multiple attacker accounts with multiple targets (reentrancy supported, complex code). 'js' a set of web3.js calls to send multiple transactions (ignores reentrancy and return data; dead simple code)."),
        )
        .arg(
            Arg::new("abi")
                .short('a')
                .long("abi")
                .value_name("ABI_FILE")
                .help("Path to contract ABI definition file")
                .takes_value(true)
                .value_parser(clap::value_parser!(PathBuf))
        )
        .arg(
            Arg::new("INPUT")
                .help("path to fuzzcase file")
                .value_parser(clap::value_parser!(PathBuf))
                .required(true),
        )
        .arg(
            Arg::new("OUTPUT")
                .help("output file")
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value("attack.sol"),
        );

    let matches = app.get_matches();

    let fuzzcase_path: &PathBuf = matches
        .get_one("INPUT")
        .ok_or_else(|| anyhow!("need to provide input file or directory"))?;

    let output_path: &PathBuf = matches
        .get_one("OUTPUT")
        .ok_or_else(|| anyhow!("need to provide output file or directory"))?;

    let informat: Formats = if let Some(x) = matches.value_of("input-format") {
        match x.to_ascii_lowercase().as_str() {
            "yaml" | "yml" => Formats::Yaml,
            _ => Formats::EFuzzCase,
        }
    } else if let Some(ext) = fuzzcase_path.extension() {
        if ext == "yaml" || ext == "yml" {
            Formats::Yaml
        } else {
            Formats::EFuzzCase
        }
    } else {
        Formats::EFuzzCase
    };

    let fc = match informat {
        Formats::EFuzzCase => {
            let raw_bytes = fs::read(fuzzcase_path)
                .with_context(|| format!("failed to read file {}", fuzzcase_path.display()))?;
            parse_bytes(&raw_bytes)
        }
        Formats::Yaml => {
            let stringy_thingy = fs::read_to_string(fuzzcase_path)
                .with_context(|| format!("failed to read file {}", fuzzcase_path.display()))?;
            fuzzcase_from_yaml(&stringy_thingy).with_context(|| {
                format!(
                    "failed to parse provided yaml from file {}",
                    fuzzcase_path.display()
                )
            })?
        }
    };

    if fc.txs.len() == 0 {
        bail!("The given test case does not contain transactions!");
    }

    let contractinfo: Option<ContractInfo> = if matches.is_present("abi") {
        let path: &PathBuf = matches
            .get_one("abi")
            .ok_or_else(|| anyhow!("need to provide valid --abi ABI_FILE flag"))?;
        let abi = load_abi_filepath(path)?;
        Some(abi)
    } else {
        None
    };
    if matches.is_present("verbose") {
        println!("================= Processing =====================");
        print_fuzzcase(&fc, contractinfo.as_ref())?;
        println!("==================================================");
    }

    // let sol = if matches.is_present("single-attacker") {
    //     fuzzcase_to_solidity_single(&fc, contractinfo)?
    // } else {
    //     fuzzcase_to_solidity(&fc, contractinfo)?
    // };

    let sol = match matches
        .value_of("exploit-style")
        .unwrap()
        .to_ascii_lowercase()
        .as_str()
    {
        "single" => fuzzcase_to_solidity_single(&fc, contractinfo)?,
        "multi" => fuzzcase_to_solidity(&fc, contractinfo)?,
        "js" => fuzzcase_to_js(&fc, contractinfo)?,
        _ => bail!("invalid exploit style!"),
    };

    if matches.is_present("verbose") {
        println!(
            "=================== Result =======================\n{}",
            sol
        );
    }

    fs::write(output_path, sol).with_context(|| {
        format!(
            "failed to write synthesized attack to file {}",
            output_path.display(),
        )
    })?;

    anyhow::Result::Ok(())
}
