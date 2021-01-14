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

#[macro_use]
extern crate anyhow;
extern crate clap;
extern crate ethmutator;

use anyhow::Context;
use clap::{Arg, Command};
use ethmutator::{
    find_function_for_sig, load_abi_filepath, parse_bytes, print_fuzzcase, sig_from_input,
    ContractInfo, FuzzCase,
};
use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Hash, Clone)]
struct FuzzCaseInfo {
    fuzzcase: FuzzCase,
    path: PathBuf,
}

impl Default for FuzzCaseInfo {
    fn default() -> Self {
        Self {
            fuzzcase: FuzzCase::zeroed(),
            path: PathBuf::new(),
        }
    }
}

fn summarize_fuzzcases(
    fuzzcases: &[FuzzCaseInfo],
    contractinfo: &Option<ContractInfo>,
    queries: Option<Vec<String>>,
) -> anyhow::Result<()> {
    if fuzzcases.is_empty() {
        bail!("no fuzzcases provided");
    }

    let mut txid_count = HashMap::<u32, u32>::new();

    let mut seen_txids = HashSet::<Vec<u32>>::new();
    let mut seen_txids_dedup = HashSet::<Vec<u32>>::new();

    let mut max_abi_coverage_count = 0;
    let mut fuzzcase_max_abi = FuzzCaseInfo::default();

    let mut average_tx_cnt = 0f64;

    for fc in fuzzcases.iter() {
        let mut txids: Vec<u32> = vec![];
        let mut txids_dedup: Vec<u32> = vec![];
        let mut txids_good_seen: HashSet<u32> = HashSet::new();
        let txs = &fc.fuzzcase.txs;

        average_tx_cnt += txs.len() as f64;

        for tx in txs {
            let input = &tx.input;
            let txid = sig_from_input(input).unwrap_or(0);
            txids.push(txid);
            if let Some(last) = txids_dedup.last() {
                if *last != txid {
                    txids_dedup.push(txid);
                }
            } else {
                txids_dedup.push(txid);
            }

            if let Some((_, functions)) = contractinfo.as_ref() {
                if find_function_for_sig(functions, txid).is_some() {
                    txids_good_seen.insert(txid);
                }
            } else if txid != 0 {
                txids_good_seen.insert(txid);
            }

            *txid_count.entry(txid).or_insert(0u32) += 1;
        }

        if txids_good_seen.len() > max_abi_coverage_count {
            max_abi_coverage_count = txids_good_seen.len();
            fuzzcase_max_abi = fc.clone();
        }

        seen_txids.insert(txids);
        seen_txids_dedup.insert(txids_dedup);
    }

    average_tx_cnt /= fuzzcases.len() as f64;

    println!("Transactions Sequences:");
    println!("--------------------------------------------------------------");
    let mut seen_txstrs = HashSet::<String>::new();
    for fci in fuzzcases.iter() {
        let fc = &fci.fuzzcase;
        let mut do_print = queries.is_none();
        let mut fc_str = "TX [".to_string();
        if fc.header.number != 0 {
            fc_str.push('#');
        }
        if fc.header.timestamp != 0 {
            fc_str.push('⏰');
        }
        if fc.header.initial_ether != 0 {
            fc_str.push('🪙');
        }
        fc_str.push_str("]\n");

        for tx in fc.txs.iter() {
            fc_str.push_str("    ");
            if let Some(txid) = sig_from_input(&tx.input) {
                if let Some((contract, functions)) = contractinfo.as_ref() {
                    if let Some(f) = find_function_for_sig(functions, txid) {
                        fc_str += &f.signature();

                        if let Some(queries) = queries.as_ref() {
                            for q in queries.iter() {
                                let sig_str = f.signature().to_ascii_lowercase();
                                if sig_str.contains(q) {
                                    do_print = true;
                                }
                            }
                        }
                    } else if txid == 0 && contract.fallback {
                        fc_str.push_str("fallback()");
                    } else {
                        fc_str += &format!("{:#x}()", txid);
                    }
                } else {
                    fc_str += &format!("{:#x}()", txid);
                }
            } else {
                fc_str.push_str("fallback()");
            }

            fc_str.push('[');
            if tx.header.call_value > 0 {
                fc_str.push('🪙');
            }
            if tx.header.return_count > 0 {
                fc_str.push_str("↕️ ");
                for ret in tx.returns.iter() {
                    if ret.header.reenter > 0 {
                        fc_str.push_str("↩️ ");
                    }
                }
            }
            fc_str.push_str("];\n");
        }

        if !seen_txstrs.contains(&fc_str) {
            seen_txstrs.insert(fc_str.clone());

            if do_print {
                print!("{}", fc_str);
            }
        }
    }
    println!("--------------------------------------------------------------");
    println!("== ABI coverage: ==");

    let mut txid_count_sorted: Vec<(u32, u32)> = txid_count.iter().map(|(&x, &y)| (y, x)).collect();
    txid_count_sorted.sort_unstable();

    for (count, txid) in txid_count_sorted.into_iter() {
        let mut print_id = String::new();
        if let Some((_, functions)) = contractinfo.as_ref() {
            if let Some(f) = find_function_for_sig(functions, txid) {
                print_id = f.signature();
            }
        }
        if print_id.is_empty() {
            print_id = format!("{:x}", txid);
        }
        println!("{} ==> {}", print_id, count);
    }

    if let Some((_, functions)) = contractinfo.as_ref() {
        for (funcid, f) in functions.iter() {
            if !txid_count.contains_key(funcid) {
                println!("{} ==> 0", f.signature());
            }
        }
    }

    if !fuzzcase_max_abi.path.as_os_str().is_empty() {
        println!(
            "\nMaximum ABI coverage with: {}",
            fuzzcase_max_abi.path.display()
        );
    }

    println!("--------------------------------------------------------------");
    println!("Number of fuzzcases: {}", fuzzcases.len());
    println!("Average number of TXs: {}", average_tx_cnt);
    println!("Number of unique TX sequences: {}", seen_txids.len());
    println!(
        "Number of unique TX sequences (consecutive deduplicated): {}",
        seen_txids_dedup.len()
    );
    //if let Some((contract, functions)) = contractinfo.as_ref() {}

    Ok(())
}

fn fuzzcase_to_string(fc: &FuzzCase, cinfo: &ContractInfo) -> String {
    let (_contract, functions) = cinfo;
    let v: Vec<String> = fc
        .txs
        .iter()
        .map(|tx| {
            if let Some(txid) = sig_from_input(&tx.input) {
                if let Some(f) = find_function_for_sig(functions, txid) {
                    f.signature()
                } else {
                    format!("{:#x}()", txid)
                }
            } else {
                "fallback()".to_string()
            }
        })
        .collect();
    v.join(" -> ")
}

fn concat_txids(fc: &FuzzCase) -> Vec<u8> {
    let mut v: Vec<u8> = vec![];
    v.reserve(fc.txs.len() * 4);
    for sig in fc
        .txs
        .iter()
        .map(|tx| sig_from_input(&tx.input).unwrap_or(0))
    {
        v.extend(u32::to_be_bytes(sig).iter());
    }
    v
}

fn sort_fuzzcases(
    fuzzcases: &mut Vec<FuzzCaseInfo>,
    contractinfo: &Option<ContractInfo>,
) -> anyhow::Result<()> {
    if let Some(cinfo) = contractinfo.as_ref() {
        fuzzcases.sort_by(|a, b| {
            let str_a = fuzzcase_to_string(&a.fuzzcase, cinfo);
            let str_b = fuzzcase_to_string(&b.fuzzcase, cinfo);
            str_a.partial_cmp(&str_b).unwrap()
        });
    } else {
        fuzzcases.sort_by(|a, b| {
            let va: Vec<u8> = concat_txids(&a.fuzzcase);
            let vb: Vec<u8> = concat_txids(&b.fuzzcase);

            va.partial_cmp(&vb).unwrap()
        });
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let app = Command::new(env!("CARGO_BIN_NAME"))
        .version(ethmutator::VERSION)
        .about("Analyze fuzzcase format of eEVM Fuzzer and ethmutator")
        .arg(
            Arg::new("abi")
                .short('a')
                .long("abi")
                .value_name("ABI_FILE")
                .help("Path to contract ABI definition file")
                .value_parser(clap::value_parser!(PathBuf))
                .takes_value(true),
        )
        .arg(
            Arg::new("print-abi")
                .short('p')
                .long("print-abi")
                .help("Also print the parsed ABI"),
        )
        .arg(
            Arg::new("summarize")
                .short('s')
                .long("summarize")
                .help("summarize a directory of fuzzcases"),
        )
        .arg(
            Arg::new("query")
                .short('q')
                .long("query")
                .help("print only if the given string matches one of the function in the fuzzcases")
                .multiple_occurrences(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("INPUT")
                .help("path to fuzzcase file or directory ")
                .required(true)
                .index(1)
                .value_parser(clap::value_parser!(PathBuf)),
        );
    //.arg(
    //    Arg::new("v")
    //        .short("v")
    //        .multiple(true)
    //        .help("Sets the level of verbosity"),
    //);
    let matches = app.get_matches();

    let fuzzcase_path: &PathBuf = matches
        .get_one("INPUT")
        .ok_or_else(|| anyhow!("need to provide input file or directory"))?;

    let contractinfo: Option<ContractInfo> = if matches.is_present("abi") {
        let path: &PathBuf = matches
            .get_one("abi")
            .ok_or_else(|| anyhow!("need to provide ABI_FILE --abi flag"))?;
        let abi = load_abi_filepath(path)?;
        if matches.is_present("print-abi") {
            println!("==============  ABI  ===============");
            ethmutator::print_contract_abi(&abi);
            println!("====================================");
        }
        Some(abi)
    } else {
        None
    };

    if matches.is_present("summarize") {
        let mut fuzzcases: Vec<FuzzCaseInfo> = Vec::new();
        for entry in fs::read_dir(fuzzcase_path).with_context(|| {
            format!(
                "failed to obtain directory listing for path {}",
                fuzzcase_path.display()
            )
        })? {
            let entry = entry?;
            let path = &entry.path();
            if !path.is_dir() {
                let raw_bytes = fs::read(path)
                    .with_context(|| format!("failed to read file {}", path.display()))?;
                let fc = parse_bytes(&raw_bytes);
                fuzzcases.push(FuzzCaseInfo {
                    fuzzcase: fc,
                    path: path.to_path_buf(),
                });
            }
        }

        sort_fuzzcases(&mut fuzzcases, &contractinfo)?;

        let queries = if matches.occurrences_of("query") > 0 {
            let q: Vec<String> = matches
                .values_of("query")
                .unwrap()
                .map(|s| s.to_string().to_ascii_lowercase())
                .collect();
            Some(q)
        } else {
            None
        };

        summarize_fuzzcases(&fuzzcases, &contractinfo, queries)?;
    } else {
        if matches.occurrences_of("query") > 0 {
            eprintln!("Warning the --query parameter is only supported with -s/--summarize");
        }
        let raw_bytes = fs::read(fuzzcase_path)
            .with_context(|| format!("failed to read file {}", fuzzcase_path.display()))?;
        let fc = parse_bytes(&raw_bytes);
        print_fuzzcase(&fc, contractinfo.as_ref())?;
    }

    anyhow::Result::Ok(())
}
