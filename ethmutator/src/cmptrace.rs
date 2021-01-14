// Copyright 2021 Michael Rodler
// This file is part of evm2cpp.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

// TODO:
//
// obtain compare logs
// * [x] find the binary
// * [x] make fifo
// * [x] run the binary in background with dump to fifo
// * [x] read comparison logs from fifo
// * [x] populate dictionary based on these values
//
// support for per-input dictionary?
// * add hashmap input -> dictionary to mutator?
// * efficient dictionary cloning?
//
//
//

use ethereum_types::U256;
use nix::sys::stat;
use nix::unistd;
use std::ffi::OsStr;
use std::io::Read;
use std::time::Instant;
use subprocess::Exec;

use zerocopy::byteorder::{NativeEndian, U16, U64};

use crate::instructions::Instruction;

pub fn guess_target_binary_path() -> Option<std::path::PathBuf> {
    for try_path in &["./fuzz_multitx", "./build/fuzz_multitx"] {
        let p = std::path::PathBuf::from(try_path);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[derive(Clone, Debug)]
pub struct CmpTraceEntry {
    pub pc: u64,
    pub op: u8,
    pub arg0: U256,
    pub arg1: U256,
}

#[derive(Clone, Debug)]
pub struct RetTraceEntry {
    pub pc: u64,
    pub op: u8,
    // TODO: add receiver?
    // pub receiver: u8,
    pub sig: u32,
    pub arg: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum TraceEntry {
    Cmp(CmpTraceEntry),
    Ret(RetTraceEntry),
}

pub fn obtain_trace_for_input(
    program_path: &OsStr,
    input_path: &std::path::Path,
    read_timeout: u64,
) -> Vec<TraceEntry> {
    let mut v: Vec<TraceEntry> = vec![];

    let tmp_dir = tempfile::Builder::new()
        .prefix("efcf-cmptrace_")
        .rand_bytes(32)
        .tempdir()
        .unwrap();

    // first create the FIFO for communication
    let fifo_path = tmp_dir.path().join("cmp.pipe");
    unistd::mkfifo(&fifo_path, stat::Mode::S_IRWXU).expect("Error creating fifo");

    // then launch a process with the fuzzed binary
    let mut p = Exec::cmd("timeout")
        .arg("--kill-after=1s")
        .arg(&format!("{}s", 1 + read_timeout * 2))
        .arg(program_path)
        .arg(input_path)
        .env("EVM_CMP_LOG", &fifo_path)
        .env("EVM_DEBUG_PRINT", "0")
        .stdout(subprocess::NullFile)
        .detached()
        .popen()
        .unwrap();

    // opening this FIFO blocks until the other side has also opened it.
    let mut pipe = std::fs::File::open(&fifo_path).unwrap();

    // the first read_exact should block until the program writes something to the FIFO

    let start = Instant::now();

    loop {
        let mut pc_buf = [0u8; 8];
        let mut op_buf = [0u8; 1];
        let mut arg0_buf = [0u8; 32];
        let mut arg1_buf = [0u8; 32];
        let mut sig_buf = [0u8; 4];
        let mut len_buf = [0u8; 2];

        let since = start.elapsed();
        if since.as_secs() > read_timeout {
            eprintln!(
                "[EthMutator][CMPTRACE] timeout after {} seconds while reading trace; after reading {} traces",
                since.as_secs(),
                v.len()
            );
            break;
        }

        if let Err(e) = pipe.read_exact(&mut pc_buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            eprintln!(
                "[EthMutator][CMPTRACE] encountered err while reading fifo: {}",
                e
            );
            break;
        }

        let pc = U64::<NativeEndian>::from_bytes(pc_buf).get();

        if let Err(e) = pipe.read_exact(&mut op_buf) {
            eprintln!(
                "[EthMutator][CMPTRACE] encountered err while reading fifo: {}",
                e
            );
            break;
        }

        if let Some(inst) = Instruction::from_u8(op_buf[0]) {
            use Instruction::*;
            match inst {
                LT | GT | SLT | SGT | EQ => {
                    if let Err(e) = pipe.read_exact(&mut arg0_buf) {
                        eprintln!(
                            "[EthMutator][CMPTRACE] encountered err while reading fifo: {}",
                            e
                        );
                        break;
                    }
                    if let Err(e) = pipe.read_exact(&mut arg1_buf) {
                        eprintln!(
                            "[EthMutator][CMPTRACE] encountered err while reading fifo: {}",
                            e
                        );
                        break;
                    }

                    v.push(TraceEntry::Cmp(CmpTraceEntry {
                        pc,
                        op: op_buf[0],
                        arg0: U256::from_big_endian(&arg0_buf),
                        arg1: U256::from_big_endian(&arg1_buf),
                    }));
                }
                RETURN => {
                    if let Err(e) = pipe.read_exact(&mut sig_buf) {
                        eprintln!(
                            "[EthMutator][CMPTRACE] encountered err while reading fifo: {}",
                            e
                        );
                        break;
                    }
                    if let Err(e) = pipe.read_exact(&mut len_buf) {
                        eprintln!(
                            "[EthMutator][CMPTRACE] encountered err while reading fifo: {}",
                            e
                        );
                        break;
                    }
                    let size = U16::<NativeEndian>::from_bytes(len_buf).get() as usize;
                    let mut data: Vec<u8> = Vec::new();
                    data.resize(size, 0);
                    if let Err(e) = pipe.read_exact(data.as_mut_slice()) {
                        eprintln!(
                            "[EthMutator][CMPTRACE] encountered err while reading fifo: {}",
                            e
                        );
                        break;
                    }

                    v.push(TraceEntry::Ret(RetTraceEntry {
                        pc,
                        op: op_buf[0],
                        sig: u32::from_be_bytes(sig_buf),
                        arg: data,
                    }));
                }
                _ => {
                    // ignore others? no this breaks the read...
                    eprintln!(
                        "[EthMutator][CMPTRACE] encountered unknown instruction: {:?}",
                        inst
                    );
                    break;
                }
            }
        } else {
            eprintln!("[EthMutator][CMPTRACE] Invalid opcode received!");
            break;
        }
    }

    #[cfg(debug_assertions)]
    {
        assert!(p.wait().is_ok());
        let status = p.poll().unwrap();
        assert_eq!(status, subprocess::ExitStatus::Exited(0));
    }
    let _x = p.terminate();

    v
}

#[cfg(feature = "tests_with_fs")]
#[cfg(test)]
pub mod tests {
    pub const MOCK_TEST_SCRIPT: &str = r"#!/usr/bin/env bash

set -euo pipefail

# open fifo
exec 3<> $EVM_CMP_LOG

# first cmp trace
printf '\x37\x13\x00\x00\x00\x00\x00\x00' >&3
printf '\x10' >&3
printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' >&3
printf '\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42' >&3

# second cmp trace
printf '\x40\x20\x00\x00\x00\x00\x00\x00' >&3
printf '\x14' >&3
printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02' >&3
printf '\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42' >&3

# a return trace
printf '\x42\x31\x00\x00\x00\x00\x00\x00' >&3
printf '\xf3' >&3
printf '\x41\x42\x43\x44' >&3
printf '\x04\x00' >&3
printf '\x01\x02\x03\x04' >&3

exit 0
";

    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_fifo_read() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", MOCK_TEST_SCRIPT).unwrap();

        let file = file.into_temp_path();

        let v = obtain_trace_for_input(OsStr::new("bash"), &file, 100);

        assert_eq!(v.len(), 3);
        assert!(matches!(v[0], TraceEntry::Cmp(_)));
        assert!(matches!(v[1], TraceEntry::Cmp(_)));
        assert!(matches!(v[2], TraceEntry::Ret(_)));

        if let TraceEntry::Cmp(x) = &v[0] {
            if let TraceEntry::Cmp(y) = &v[1] {
                assert_eq!(x.op, 0x10);
                assert_eq!(x.pc, 0x1337);
                assert_eq!(x.arg0, crate::U256_ZERO);
                assert_eq!(x.arg1, y.arg1);
                assert_eq!(y.op, 0x14);
                assert_eq!(y.pc, 0x2040);
                assert_eq!(y.arg0, U256::from(0x0102));
                let data42 = [0x42u8; 32];
                assert_eq!(x.arg1, U256::from_big_endian(&data42));
            } else {
                panic!("Invalid entry: {:?}", v[1]);
            }
        } else {
            panic!("Invalid entry: {:?}", v[0]);
        }

        if let TraceEntry::Ret(x) = &v[2] {
            assert_eq!(x.op, 0xf3);
            assert_eq!(x.pc, 0x3142);
            assert_eq!(x.sig, 0x41424344);
            assert_eq!(x.arg, vec![1u8, 2, 3, 4]);
        } else {
            panic!("Invalid entry: {:?}", v[0]);
        }
    }

    #[test]
    fn test_fifo_read_fail() {
        pub const MOCK_TEST_SCRIPT: &str = r"#!/usr/bin/env bash

set -euo pipefail

# open fifo
exec 3<> $EVM_CMP_LOG

# first cmp trace
printf '\x37\x13\x00\x00\x00\x00\x00\x00' >&3
printf '\x10' >&3
printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' >&3
printf '\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42' >&3

# first cmp trace
printf '\x37\x13\x00\x00\x00\x00\x00\x00' >&3
printf '\x10' >&3
printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' >&3
printf '\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42' >&3

exit 0
";

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", MOCK_TEST_SCRIPT).unwrap();

        let file = file.into_temp_path();

        let v = obtain_trace_for_input(OsStr::new("bash"), &file, 100);

        assert_eq!(v.len(), 1);
        assert!(matches!(v[0], TraceEntry::Cmp(_)));

        if let TraceEntry::Cmp(x) = &v[0] {
            assert_eq!(x.op, 0x10);
            assert_eq!(x.pc, 0x1337);
            assert_eq!(x.arg0, crate::U256_ZERO);
            let data42 = [0x42u8; 32];
            assert_eq!(x.arg1, U256::from_big_endian(&data42));
        }
    }
}
