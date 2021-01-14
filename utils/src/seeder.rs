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
use clap::{Arg, Command, SubCommand};
use ethmutator::{
    find_function_for_sig, load_abi_file, parse_bytes, print_fuzzcase, sig_from_input,
    ContractInfo, Dictionary, FuzzCase,
};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;

fn main() -> anyhow::Result<()> {
    let app = Command::new(env!("CARGO_BIN_NAME"))
        .about("Generate seed files in fuzzcase format of eEVM Fuzzer and ethmutator")
        .version(ethmutator::VERSION)
        .arg(
            Arg::new("abi")
                .short('a')
                .long("abi")
                .value_name("ABI_FILE")
                .help("Path to contract ABI definition file")
                .takes_value(true),
        )
        .arg(
            Arg::new("print-abi")
                .short('p')
                .long("print-abi")
                .help("Also print the parsed ABI"),
        )
        .subcommand(
            SubCommand::with_name("dict")
                .about("generate a dictionary for fuzzing (or update it if possible)")
                .arg(
                    Arg::new("noupdate")
                        .long("--no-update")
                        .help("force overwriting the given file instead of updating it."),
                )
                .arg(
                    Arg::new("INPUT")
                        .help("path to output file for generated dictionary")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("seed")
                .about("generate fuzzing seeds")
                .arg(
                    Arg::new("INPUT")
                        .help("path to output directory for generated fuzzcases")
                        .required(true)
                        .index(1),
                ),
        );
    let matches = app.get_matches();

    let contractinfo: Option<ContractInfo> = if let Some(path) = matches.value_of_os("abi") {
        let abi = load_abi_file(path)?;
        if matches.is_present("print-abi") {
            println!("==============  ABI  ===============");
            ethmutator::print_contract_abi(&abi);
            println!("====================================");
        }
        Some(abi)
    } else {
        None
    };

    if let Some(matches) = matches.subcommand_matches("dict") {
        // TODO: generate / update a dictionary pass to AFL?

        let path: &OsStr = matches
            .value_of_os("INPUT")
            .ok_or(anyhow!("need to provide dict file!"))?;
        let path = std::path::Path::new(path);

        let mut d = if path.exists() {
            Dictionary::load_from_file(path)?
        } else {
            Dictionary::new()
        };
        // populating with interesting values
        d.populate_with_interesting_values();

        // write back to the file
        d.write_to_file(path)?;
    } else if let Some(matches) = matches.subcommand_matches("seed") {
        // generate seed files in a directory

        // TODO: generate seed files
    }

    anyhow::Result::Ok(())
}
