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
use ethmutator::serializer::{fuzzcase_from_yaml, fuzzcase_to_yaml};
use ethmutator::{pack_to_bytes, parse_bytes};
use std::fs;
use std::path::PathBuf;

#[derive(Debug)]
enum Formats {
    Yaml,
    EFuzzCase,
}

fn main() -> anyhow::Result<()> {
    let app = Command::new("efuzzcasetranscoder")
        .about("transform fuzzcase format of eEVM Fuzzer and ethmutator")
        .version(ethmutator::VERSION)
        .arg(
            Arg::new("input-format")
                .short('i')
                .help("input format")
                .possible_values(&["yaml", "efuzzcase"]),
        )
        .arg(
            Arg::new("output-format")
                .short('o')
                .help("output format")
                .possible_values(&["yaml", "efuzzcase"]),
        )
        .arg(
            // TODO: make use of the abi somehow?
            Arg::new("abi")
                .short('a')
                .long("abi")
                .value_name("ABI_FILE")
                .help("Path to contract ABI definition file")
                .value_parser(clap::value_parser!(PathBuf))
                .takes_value(true),
        )
        .arg(
            Arg::new("INPUT")
                .help("path to fuzzcase file or directory ")
                .value_parser(clap::value_parser!(PathBuf))
                .required(true),
        )
        .arg(
            Arg::new("OUTPUT")
                .help("path to fuzzcase file or directory ")
                .value_parser(clap::value_parser!(PathBuf))
                .required(true),
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

    let outformat: Formats = if let Some(x) = matches.value_of("output-format") {
        match x {
            "yaml" => Formats::Yaml,
            _ => Formats::EFuzzCase,
        }
    } else if let Some(ext) = output_path.extension() {
        if ext == "yaml" || ext == "yml" {
            Formats::Yaml
        } else {
            Formats::EFuzzCase
        }
    } else {
        Formats::EFuzzCase
    };

    let out_data = match outformat {
        Formats::EFuzzCase => pack_to_bytes(&fc),
        Formats::Yaml => {
            let s = fuzzcase_to_yaml(&fc);
            s.as_bytes().to_vec()
        }
    };

    fs::write(output_path, out_data).with_context(|| {
        format!(
            "failed to write fuzzcase to file {} with format {:?}",
            output_path.display(),
            outformat
        )
    })?;

    anyhow::Result::Ok(())
}
