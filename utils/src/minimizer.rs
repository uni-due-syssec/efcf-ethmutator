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

use anyhow::Context;
use clap::{Arg, Command};
use ethmutator::{
    load_abi_filepath, pack_to_bytes, parse_bytes, print_fuzzcase, sig_from_input, ContractInfo,
    FuzzCase, Transaction, TransactionHeader,
};
use std::ffi::OsStr;
use std::fs;
use std::io::prelude::*;
//use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
//use std::process::{Command, ExitStatus};
use std::time::Duration;
use subprocess::{ExitStatus, Popen, PopenConfig, Redirection};
use tempfile::NamedTempFile;

const TIMEOUT: Duration = Duration::from_secs(10);

type FeedbackFunction = fn(&Path, &FuzzCase, &FuzzCase) -> anyhow::Result<bool>;

// hamming distance if both strings are of equal length, otherwise also includes every reduced byte
fn edit_distance(b1: &[u8], b2: &[u8]) -> usize {
    let l = std::cmp::min(b1.len(), b2.len());
    let mut d: usize = 0;
    for i in 0..l {
        if b1[i] != b2[i] {
            d += 1;
        }
    }
    if b1.len() != b2.len() {
        d += ((b1.len() as isize) - (b2.len() as isize)).abs() as usize;
    }
    d
}

fn run_fuzzcase(prog: &Path, fuzzcase: &FuzzCase) -> anyhow::Result<Option<ExitStatus>> {
    let fc_bytes = pack_to_bytes(fuzzcase);
    // create a new tempfile and write the packed fuzzcase into the file
    let mut file = NamedTempFile::new()?;
    file.write_all(&fc_bytes)?;
    // Close the file, but keep the path to it around.
    let path = file.into_temp_path();

    // execute the binary with tempfile path as argv[1]
    // std::process::Command does not support timeouts...
    //let out = Command::new(prog).arg(&path).output()?;
    //Ok(out.status)
    // so we use the subprocess crate instead
    let mut proc = Popen::create(
        &[prog.as_os_str(), path.as_os_str()],
        PopenConfig {
            stdout: Redirection::Pipe,
            stderr: Redirection::Pipe,
            //detached: true,
            ..Default::default()
        },
    )?;
    let res = proc.wait_timeout(TIMEOUT);
    if let Err(e) = proc.kill() {
        // we make sure to attempt to kill the process, but if it doesn't work: ¯\_(ツ)_/¯
        println!("WARNING: failed to kill process ({})", e);
    };
    anyhow::Result::Ok(res?)
}

fn does_signal(status: &Option<ExitStatus>, signal: i32) -> bool {
    if let Some(status) = status {
        if status.success() {
            false
        } else if let ExitStatus::Signaled(signum) = *status {
            (signum as i32) == signal
        } else {
            false
        }
    } else {
        false
    }
}

fn still_aborts(prog: &Path, _old: &FuzzCase, new: &FuzzCase) -> anyhow::Result<bool> {
    let status = run_fuzzcase(prog, new)?;
    anyhow::Result::Ok(does_signal(&status, libc::SIGABRT) || does_signal(&status, libc::SIGSEGV))
}

fn afl_showmap(prog: &Path, fuzzcase: &FuzzCase) -> anyhow::Result<String> {
    let fc_bytes = pack_to_bytes(fuzzcase);
    // create a new tempfile and write the packed fuzzcase into the file
    let mut file = NamedTempFile::new()?;
    file.write_all(&fc_bytes)?;
    // Close the file, but keep the path to it around.
    let path = file.into_temp_path();

    let map_file = NamedTempFile::new()?;
    let map_path = map_file.into_temp_path();

    // so we use the subprocess crate instead
    let mut proc = Popen::create(
        &[
            OsStr::new("afl-showmap"),
            OsStr::new("-o"),
            map_path.as_os_str(),
            OsStr::new("--"),
            prog.as_os_str(),
            path.as_os_str(),
        ],
        PopenConfig {
            stdout: Redirection::Pipe,
            stderr: Redirection::Pipe,
            //detached: true,
            ..Default::default()
        },
    )?;
    let res = proc.wait_timeout(TIMEOUT)?;
    if let Err(e) = proc.kill() {
        // we make sure to attempt to kill the process, but if it doesn't work: ¯\_(ツ)_/¯
        println!("WARNING: failed to kill process ({})", e);
    };
    if let Some(res) = res {
        if let subprocess::ExitStatus::Exited(i) = res {
            if i != 0 {
                bail!("afl-showmap returned non-zero exit code {}", i);
            }
        } else {
            bail!("afl-showmap abnormal exit {:?}", res);
        }
    } else {
        bail!("process did not exit");
    }
    let map_content = fs::read_to_string(map_path)?;
    if map_content.is_empty() {
        bail!("empty map file produced by afl-showmap")
    }
    anyhow::Result::Ok(map_content)
}

fn same_coverage(prog: &Path, old: &FuzzCase, new: &FuzzCase) -> anyhow::Result<bool> {
    let old_map = afl_showmap(prog, old)?;
    let new_map = afl_showmap(prog, new)?;
    anyhow::Result::Ok(old_map == new_map)
}

fn minimize_fuzzcase(
    prog: &Path,
    fuzzcase: &FuzzCase,
    was_successful: FeedbackFunction,
    quiet: bool,
) -> anyhow::Result<FuzzCase> {
    let orig_fuzzcase_bytes = pack_to_bytes(fuzzcase);
    let orig_fuzzcase_len = orig_fuzzcase_bytes.len();

    if !was_successful(prog, fuzzcase, fuzzcase)? {
        bail!("Sorry the provided fuzzcase does not seem to match the minimization criteria! (i.e., it does not crash; or it does not output any code coverage");
    }

    let mut fc_min = fuzzcase.clone();

    if !quiet {
        println!("[using trimmer code]");
    }
    // we use the new trimming code to minimize a bit
    let mut trimmer = ethmutator::FuzzcaseTrimmer::from(fc_min.clone());
    if !quiet {
        println!("[Trimmer Stage: {:?}]", trimmer.current_stage());
    }
    while let Some(fc) = trimmer.next() {
        if !quiet {
            print!("[Trimmer Stage: {:?}]", trimmer.current_stage());
        }
        if was_successful(prog, &fc_min, &fc)? {
            fc_min = fc;
            if !quiet {
                println!(" ✔️");
            }
        } else {
            trimmer.rollback();
            if !quiet {
                println!(" ❌");
            }
        }
    }

    if !quiet {
        println!("[minimizing difficulty]");
    }
    // minimize difficulty
    for d in &[0u64, 1, 100, 100_000, 2 << 32] {
        let mut fc = fc_min.clone();
        fc.header.difficulty = *d;

        if was_successful(prog, &fc_min, &fc)? {
            fc_min = fc;
            break;
        }
    }

    // now we perfrom some other minimizer steps, which are not (yet) in the trimmer code.
    let min_txs_len = fc_min.txs.len();
    for i in 0..min_txs_len {
        if !quiet {
            println!("[ sender/receiver selector TX[{}] ]", i);
        }
        // we try some new sender selectors
        let original_selector = fc_min.txs[i].header.sender_select;
        for new_select in 0..original_selector {
            let mut fc = fc_min.clone();
            fc.txs[i].header.sender_select = new_select;

            if was_successful(prog, &fc_min, &fc)? {
                fc_min = fc;
                break;
            }

            let mut fc = fc_min.clone();
            for tx in fc.txs.iter_mut() {
                if tx.header.sender_select == original_selector {
                    tx.header.sender_select = new_select;
                }
            }
            if was_successful(prog, &fc_min, &fc)? {
                fc_min = fc;
                break;
            }
        }

        let original_selector = fc_min.txs[i].header.receiver_select;
        for new_select in 0..original_selector {
            let mut fc = fc_min.clone();
            fc.txs[i].header.receiver_select = new_select;

            if was_successful(prog, &fc_min, &fc)? {
                fc_min = fc;
                break;
            }

            let mut fc = fc_min.clone();
            for tx in fc.txs.iter_mut() {
                if tx.header.receiver_select == original_selector {
                    tx.header.receiver_select = new_select;
                }
            }
            if was_successful(prog, &fc_min, &fc)? {
                fc_min = fc;
                break;
            }
        }
    }

    // the last step is that we try to sort the transactions in the list.

    if !quiet {
        println!("[ we try sorting the transaction list ]");
    }
    use std::cmp::Ordering;
    fn txh_cmp(a: &TransactionHeader, b: &TransactionHeader) -> std::cmp::Ordering {
        if a.length == b.length {
            if a.call_value == b.call_value {
                let sender_b = b.sender_select;
                a.sender_select.cmp(&sender_b)
            } else {
                let cv_b = b.call_value;
                let cv_a = a.call_value;
                cv_a.cmp(&cv_b)
            }
        } else {
            let l_b = b.length;
            let l_a = a.length;
            l_a.cmp(&l_b)
        }
    }

    fn tx_cmp(a: &Transaction, b: &Transaction) -> std::cmp::Ordering {
        let sig_a = sig_from_input(&a.input);
        let sig_b = sig_from_input(&b.input);
        match (sig_a, sig_b) {
            (Some(sig_a), Some(sig_b)) => {
                if sig_a != sig_b {
                    sig_a.cmp(&sig_b)
                } else {
                    txh_cmp(&a.header, &b.header)
                }
            }
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (None, None) => txh_cmp(&a.header, &b.header),
        }
    }

    // O(n^2), but YOLO
    let bound = fc_min.txs.len();
    for i in 1..bound {
        for j in (0..(i - 1)).rev() {
            if tx_cmp(&fc_min.txs[i], &fc_min.txs[j]) == Ordering::Less {
                let mut fc = fc_min.clone();
                fc.txs.swap(i, j);
                if was_successful(prog, &fc_min, &fc)? {
                    fc_min.txs.swap(i, j);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    let fc_min_bytes = pack_to_bytes(&fc_min);
    let new_fuzzcase_len = fc_min_bytes.len();

    if !quiet {
        println!(
            "reduced testcases from {} to {} bytes (by {} %) edit distance {}",
            orig_fuzzcase_len,
            new_fuzzcase_len,
            100 - ((new_fuzzcase_len * 100) / orig_fuzzcase_len),
            edit_distance(&orig_fuzzcase_bytes, &fc_min_bytes)
        );
    }

    Ok(fc_min)
}

fn main() -> anyhow::Result<()> {
    let app = Command::new(env!("CARGO_BIN_NAME"))
        .about("Analyze fuzzcase format of eEVM Fuzzer and ethmutator")
        .version(ethmutator::VERSION)
        .arg(
            Arg::new("abi")
                .short('a')
                .long("abi")
                .value_name("ABI_FILE")
                .help("Path to contract ABI definition file")
                .takes_value(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("use-afl-map")
                .short('M')
                .long("use-afl-map")
                .help("utilizes afl-showmap to check whether code coverage changed"),
        )
        .arg(
            Arg::new("overwrite")
                .short('o')
                .long("overwrite")
                .help("overwrite the provided testcase with minimized version"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("suppress any output"),
        )
        .arg(
            Arg::new("BINARY")
                .help("path to executable")
                .required(true)
                .index(1)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("INPUT")
                .help("path to fuzzcase file or directory")
                .required(true)
                .index(2)
                .value_parser(clap::value_parser!(PathBuf)),
        );
    let matches = app.get_matches();

    let binary_path: &PathBuf = matches
        .get_one("BINARY")
        .ok_or_else(|| anyhow!("need to provide path to binary file"))?;
    let input_path: &PathBuf = matches
        .get_one("INPUT")
        .ok_or_else(|| anyhow!("need to provide input file or directory"))?;

    let contractinfo: Option<ContractInfo> = if matches.is_present("abi") {
        let pathbuf: &PathBuf = matches
            .get_one("abi")
            .ok_or_else(|| anyhow!("--abi cli flag requires valid ABI_FILE path as value"))?;
        Some(load_abi_filepath(&pathbuf)?)
    } else {
        None
    };

    let mut fuzzcases: Vec<std::path::PathBuf> = Vec::new();
    if input_path.is_dir() {
        for entry in fs::read_dir(input_path).with_context(|| {
            format!(
                "failed to obtain directory listing for path {}",
                input_path.display()
            )
        })? {
            let entry = entry?;
            let path = &entry.path();
            if !path.is_dir() {
                fuzzcases.push(path.clone());
            }
        }
    } else if input_path.is_file() {
        fuzzcases.push(input_path.to_path_buf());
    } else {
        bail!(
            "Path '{}' is neither a file nor a directory - can't handle this",
            input_path.display()
        );
    }

    for fuzzcase_path in fuzzcases.into_iter() {
        let raw_bytes = fs::read(&fuzzcase_path)
            .with_context(|| format!("failed to read file {}", fuzzcase_path.display()))?;
        let fc = parse_bytes(&raw_bytes);

        let fc_min = minimize_fuzzcase(
            binary_path,
            &fc,
            if matches.is_present("use-afl-map") {
                same_coverage
            } else {
                still_aborts
            },
            matches.is_present("quiet"),
        )
        .with_context(|| format!("failed to minimize file {}", fuzzcase_path.display()))?;

        if !matches.is_present("quiet") {
            println!("=== Before minimizing: ===");
            print_fuzzcase(&fc, contractinfo.as_ref())?;
        }

        if !matches.is_present("quiet") {
            println!("=== After minimizing: ===");
            print_fuzzcase(&fc_min, contractinfo.as_ref())?;
        }

        let fc_min_bytes = pack_to_bytes(&fc_min);
        let mut newpath = PathBuf::new();
        newpath.push(fuzzcase_path);
        if !matches.is_present("overwrite") {
            let mut fname = newpath
                .file_name()
                .ok_or_else(|| anyhow!("need file_name"))?
                .to_os_string();
            fname.push(".min");
            newpath.set_file_name(fname);
        }

        std::fs::write(&newpath, fc_min_bytes)?;
    }

    anyhow::Result::Ok(())
}
