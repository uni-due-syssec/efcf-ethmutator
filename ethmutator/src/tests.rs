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

use super::*;
use crate::test_helpers::*;

use std::convert::TryInto;

use hex_literal::hex;

fn test_round_stages(abi: Option<&str>) {
    let initial_fc = FuzzCase::zeroed();
    let initial_bytes = pack_to_bytes(&initial_fc);
    let mut mutator = init_mutator(abi, true);

    let c = mutator.start_round(&initial_bytes, 256);
    // go a bit overboard with the mutation rounds
    for _ in 0..(c + 10) {
        mutator.mutate_round();
    }
    let _c = mutator.start_round(&initial_bytes, 128);
    // start round but don't mutate based on it

    // start round based on mutated testcase
    let b = mutator.current_buffer().to_vec();
    let c = mutator.start_round(&b, 512);
    for _ in 0..c {
        mutator.mutate_round();
    }

    // start round based on mutated testcase
    let b = mutator.current_buffer().to_vec();
    // again but very small number of rounds
    let c = mutator.start_round(&b, 10);
    for _ in 0..(c + 5) {
        mutator.mutate_round();
    }
}

/// https://github.com/rust-ethereum/ethabi/blob/v14.0.0/ethabi/src/signature.rs
#[test]
fn signature_computation() {
    assert_eq!(
        u32::from_be_bytes(hex!("cdcd77c0")),
        short_signature(
            "baz",
            &[ethabi::ParamType::Uint(32), ethabi::ParamType::Bool]
        )
    );
}

#[test]
fn byteswap_in_vec() {
    let mut v = vec![0; 128];
    v[0] = 1;
    v[31] = 1;
    v[32] = 2;
    v[63] = 2;
    utils::vec_bswap::<32>(&mut v, 0, 32);
    assert_eq!(v[0], 2);
    assert_eq!(v[1..=30], [0u8; 30]);
    assert_eq!(v[31], 2);
    assert_eq!(v[32], 1);
    assert_eq!(v[33..=62], [0u8; 30]);
    assert_eq!(v[63], 1);

    let mut v = vec![1, 2, 3, 4, 5, 6];
    utils::vec_bswap::<4>(&mut v, 0, 2);
    assert_eq!(v, vec![3, 4, 5, 6, 1, 2]);
}

mod ethabi_regression {
    use super::*;

    /// this testcase and the [`ethabi_regression_decoding_panic_on_bigabi`] testcases are regression
    /// tests that make sure the ethabi library includes our patches that increase the robustness when
    /// parsing bad input with certain ABI types.
    #[test]
    fn decode_corrupted_dynamic_array() {
        use ethabi::{decode, ParamType};

        // line 1 at 0x00 =   0: tail offset of array
        // line 2 at 0x20 =  32: length of array
        // line 3 at 0x40 =  64: first word
        // line 4 at 0x60 =  96: second word
        let encoded = hex!(
            "
		0000000000000000000000000000000000000000000000000000000000000020
		00000000000000000000000000000000000000000000000000000000ffffffff
		0000000000000000000000000000000000000000000000000000000000000001
		0000000000000000000000000000000000000000000000000000000000000002
        "
        );

        let result = decode(&[ParamType::Array(Box::new(ParamType::Uint(32)))], &encoded);
        assert!(result.is_err());
    }

    /// see [`ethabi_decode_corrupted_dynamic_array`]
    #[test]
    fn decoding_panic_on_bigabi() {
        let input = hex!(
            "
0000000000000000000000000000000000000000000000000000000000000040

00000000000000000000000000000000000000000000000000000000000002a0
0000000000000000000000000000000000000000000000000000000000000009

00000000000000000000000000000000fffffffffffffffffffffffffffffffe
0000000000000000000000000000000000000000000000000000000000000000

0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000

0000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000ffffffffffffffff

0008000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000020000000000000000

0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000001000000000000000000000000000000000000

000000000000000000000000000000000000000000000000000000000000053a
0100000000000000000000000000000000000000000000000000000000000000

0000000000000010000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000

0000000000000000000000000000000000000000000000000000000002000000
0000000000000000000000000000000000000000000000000000000000100000

0000000000000000000000000000000000000000000000000000000000000000
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

0000000000000000000000000000000000000000000000000000000000000006
00000000000000000000000000000000000000000000000000000000000000c0

0000000000000000000000000000000000000000000000000000000000002ce0
0000000000000000000000000000000000000000000000000000000000005880

0000000000000000000000000000000000000000000000000000000000008280
000000000000000000000000000000000000000000000000000000000000acc0

000000000000000000000000000000000000000000000000000000000000d6e0
0000000000000000000000000000000000000000020000000000000000000000

0000000000000000000000000000000000000000000000000000000000000040
0000000000000000000000000000000000000000000000000000000000000009

0000000000000000000000000000000000000000000000000000000000000120
0000000000000000000000000000000000000000000000000000000000000720

0000000000000000000000000000000000000000000000000000000000000b80
0000000000000000000000000000000000000000000000000000000000000fe0

"
        );

        /* Encoding of the testcase:
         *
         * 0: enc(length) => 64
         * 1: tuple[0]
         * 2: tuple[1]
         */

        let func = {
            use ethabi::Param;
            use ethabi::ParamType;
            use ParamType::*;
            #[allow(deprecated)]
            ethabi::Function {
                name: "f_tuple".to_string(),
                inputs: vec![
                    Param {
                        name: "c".to_string(),
                        kind: Array(Box::new(Tuple(vec![Uint(256), Uint(256)]))),
                        internal_type: None,
                    },
                    Param {
                        name: "d".to_string(),
                        kind: Array(Box::new(Tuple(vec![
                            Uint(256),
                            Array(Box::new(Tuple(vec![
                                Uint(256),
                                Array(Box::new(ParamType::String)),
                            ]))),
                        ]))),
                        internal_type: None,
                    },
                ],
                outputs: vec![],
                constant: Some(false),
                state_mutability: ethabi::StateMutability::default(),
            }
        };
        assert!(func.decode_input(&input).is_err());
    }
}

#[test]
fn test_mutate_empty() {
    let testcase = [0u8];
    let mut mutator = EthMutator::new();
    mutator.mutate(&testcase);
    println!("stages: {:?}", mutator.stages);
    println!("output: {:?}", hexutil::to_hex(&mutator.buffer));

    assert_ne!(mutator.stages.len(), 0);

    let output = mutator.buffer.clone();
    assert_ne!(output.len(), 0);

    let fc = parse_bytes(&output);
    println!(
        "len parsed = {}\nbh = {:?}\ntxs = {:?}",
        fc.txs.len(),
        fc.header,
        fc.txs
    );
    assert_ne!(fc.txs.len(), 0);
}

#[test]
fn test_cow_thingy() {
    let tx_input = [0u8; 32 + 4].to_vec();
    let mut tx_header = TransactionHeader::default();
    tx_header.length = tx_input.len().try_into().unwrap();
    let original_length = tx_input.len();
    let tx: Transaction = Transaction {
        header: tx_header,
        input: Rc::new(tx_input.clone()),
        returns: vec![],
    };
    let mut mutator = EthMutator::new();
    mutator.queue.insert(vec![tx]);
    let testcase = [0u8];
    loop {
        mutator.mutate(&testcase);
        println!("{:?}", mutator.stages);
        if mutator
            .stages
            .iter()
            .any(|x| matches!(x, MutationStageLog::Input(_)))
        {
            break;
        }
    }

    assert_eq!(tx_input.len(), original_length);
    assert_eq!(*(*mutator.queue[0])[0].input, tx_input);
}

#[test]
fn test_parsing_packing_on_mutations() {
    let initial_fc = FuzzCase::zeroed();
    let mut fc = initial_fc.clone();
    let mut mutator = EthMutator::new();

    // we run the mutator a bunch of times. On every iteration we unpack and pack the resulting
    // bytes and check whether packing/unpacking results in the same fuzzcase.
    for repetition in 0..1_000 {
        println!("Repetition: {}", repetition);
        fc = mutator.mutate_to_new_fuzzcase(&fc);
        println!("mutations: {:?}", mutator.stages);
        //println!("New Fuzzcase: {:#?}", fc);
        let fc_bytes = pack_to_bytes(&fc);
        let fc_parsed = parse_bytes(&fc_bytes);
        //if fc != fc_parsed {}
        for (tx1, tx2) in fc.txs.iter().zip(fc_parsed.txs.iter()) {
            assert_eq!(tx1.input.len(), tx2.input.len());
            println!("TX1: {:?} - {} returns", tx1.header, tx1.returns.len());
            println!("TX2: {:?} - {} returns", tx2.header, tx2.returns.len());
            assert_eq!(tx1.header, tx2.header);
            assert_eq!(tx1.header.return_count as usize, tx1.returns.len());
            assert_eq!(tx2.header.return_count as usize, tx2.returns.len());
            assert_eq!(tx1.returns, tx2.returns);
        }
        assert_eq!(fc.header, fc_parsed.header);
        assert_eq!(fc, fc_parsed);
        let fc_bytes2 = pack_to_bytes(&fc);
        if fc_bytes2 != fc_bytes {
            println!(
                "length for testcase: {} and parsed+packed testcase: {}",
                fc_bytes.len(),
                fc_bytes2.len()
            );
            let non_matching: Vec<usize> = fc_bytes
                .iter()
                .zip(fc_bytes2.iter())
                .enumerate()
                .filter_map(|(i, (&a, &b))| if a != b { Some(i) } else { None })
                .collect();
            println!(
                "difference at {} bytes: {:?}",
                non_matching.len(),
                non_matching
            );
            for idx in non_matching.into_iter() {
                println!("[{}] => {} != {}", idx, fc_bytes[idx], fc_bytes2[idx]);
            }
        }
        assert_eq!(fc_bytes, fc_bytes2);
        mutator.push_parsed_to_queue(fc_parsed);
    }
}

mod mutationops {
    use super::*;

    #[test]
    fn add_tx() {
        let (mut mutator, mut fcqueue) =
            init_mutator_and_fuzzcases(Some(REALLY_BIG_ABI_STRING), true, 64, false);

        for fc in fcqueue.iter_mut() {
            let len_prev = fc.txs.len();
            mutator.mutate_one_stage(fc, TxListStage::AddTransaction);
            let len_now = fc.txs.len();
            assert_ne!(len_now, 0);
            assert!(len_now > len_prev);
        }
    }

    #[test]
    fn drop_useless_count() {
        for abi in &[
            None,
            Some(CROWDSALE_ABI),
            Some(SPANKCHAIN_LEDGERCHANNEL_ABI),
            Some(REALLY_BIG_ABI_STRING),
        ] {
            let (mut mutator, mut fcqueue) = init_mutator_and_fuzzcases(*abi, true, 64, true);
            let mut got_dropped = 0;

            for fc in fcqueue.iter_mut() {
                // mutate the fuzzcase, s.t., it contains some duplicated transactions that can be
                // dropped later on.
                mutator.mutate_one_stage(fc, TxListStage::DuplicateTransaction);
                mutator.mutate_one_stage(fc, TxListStage::DuplicateTransaction);

                let len_prev = fc.txs.len();
                mutator.mutate_one_stage(fc, TxListStage::DropLikelyUselessTransactions);
                let len_now = fc.txs.len();
                assert_ne!(len_now, 0);

                if len_now < len_prev {
                    got_dropped += 1;
                }
            }

            assert_ne!(got_dropped, 0);
        }
    }

    #[test]
    fn drop_useless_viewfuncs() {
        let (mut mutator, mut fcqueue) =
            init_mutator_and_fuzzcases(Some(SPANKCHAIN_LEDGERCHANNEL_ABI), true, 256, true);
        let mut has_view_count = 0;

        let rc = mutator.contracts.get(0).unwrap().clone();
        let contract = &*rc;
        let functions = &contract.functions;

        let count_view_mut = |txs: &TransactionList| {
            let mut num_view = 0;
            let mut num_mut = 0;
            for tx in txs.iter() {
                let input = &tx.input;

                // if we have input
                if input.len() >= 4 {
                    // extract tx signature and search for function with the same signature
                    let tx_sig = sig_from_input(input).unwrap();
                    if let Some(func) = find_function_for_sig(functions, tx_sig) {
                        use ethabi::StateMutability::*;
                        match func.state_mutability {
                            Pure | View => {
                                num_view += 1;
                            }
                            _ => num_mut += 1,
                        }
                    }
                }
            }
            (num_view, num_mut)
        };

        let has_view_count_before: usize = fcqueue.iter().map(|fc| count_view_mut(&fc.txs).0).sum();
        let mut num_view = 0;
        let mut num_mut = 0;

        for fc in fcqueue.iter_mut() {
            let (view_before, _mut_before) = count_view_mut(&fc.txs);

            if view_before == 0 {
                continue;
            }

            let len_prev = fc.txs.len();
            for _ in 0..10 {
                mutator.mutate_one_stage(fc, TxListStage::DropLikelyUselessTransactions);
            }
            let len_now = fc.txs.len();
            assert!(len_prev <= 3 || len_now < len_prev);

            if len_prev <= 3 {
                continue;
            }

            let (view_after, mut_after) = count_view_mut(&fc.txs);

            num_view += view_after;
            num_mut += mut_after;

            if view_after == 0 {
                has_view_count += 1;
            }
        }

        println!(
            "FCs with view/pure (before): {}\nFCs with view/pure (after): {}\nnum_mut: {}\nnum_view: {}",
            has_view_count_before, has_view_count, num_mut, num_view
        );

        assert!(has_view_count < fcqueue.len());
        assert!(num_mut > num_view);
    }
}

#[cfg(all(test, feature = "stresstests"))]
mod stresstests {
    use super::*;

    #[test]
    fn stresstest_trimming_code() {
        run_n_mutations(
            2500,
            Some(REALLY_BIG_ABI_STRING),
            false,
            Some(|idx, _mutator, input| {
                // we want to trim some really hard mutated testcases, but trimming is quite expensive
                // so we cannot do it for every mutated testcase. So only trim about 15 of the 15k
                // testcases that we generate.

                if idx > 1000 && idx % 100 == 0 {
                    let fc = parse_bytes(input);
                    let mut trimmer = FuzzcaseTrimmer::from(fc);
                    let mut last_len = input.len();
                    while let Some(fc) = trimmer.next() {
                        let new_fc = pack_to_bytes(&fc);
                        assert!(new_fc.len() <= last_len);
                        last_len = new_fc.len();
                    }

                    let fc = parse_bytes(input);
                    let mut trimmer = FuzzcaseTrimmer::from(fc);
                    while let Some(fc) = trimmer.next() {
                        let new_fc = pack_to_bytes(&fc);
                        assert!(new_fc.len() <= input.len());
                        trimmer.rollback();
                        let current = trimmer.get_current();
                        let new_fc = pack_to_bytes(&current);
                        assert_eq!(new_fc.len(), input.len());
                    }
                    trimmer.rollback();

                    let fc = parse_bytes(input);
                    assert_eq!(trimmer.get_current(), fc);
                }
            }),
        );
    }

    #[cfg(feature = "tests_with_fs")]
    #[test]
    fn round_stages_with_abi_and_fake_cmptrace() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let initial_fc = FuzzCase::zeroed();
        let initial_bytes = pack_to_bytes(&initial_fc);
        let mut mutator = init_mutator(Some(CROWDSALE_ABI), true);

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", crate::cmptrace::tests::MOCK_TEST_SCRIPT).unwrap();
        let file = file.into_temp_path();
        let file_cstr = CString::new(file.as_os_str().to_str().unwrap()).unwrap();
        mutator.cache_filename(file_cstr);
        mutator.cur_binary_path = Some(CString::new("bash").unwrap());

        let c = mutator.start_round(&initial_bytes, 1024);
        for _ in 0..c {
            mutator.mutate_round();
        }
        let _c = mutator.start_round(&initial_bytes, 1024);

        let b = mutator.current_buffer().to_vec();
        let c = mutator.start_round(&b, 1024);
        for _ in 0..c {
            mutator.mutate_round();
        }

        let b = mutator.current_buffer().to_vec();
        let c = mutator.start_round(&b, 1024);
        for _ in 0..(c + 5) {
            mutator.mutate_round();
        }
    }

    #[test]
    fn test_2k_mutations_noabi() {
        const K: usize = 2_000;
        run_n_mutations(K, None, false, None);
    }
    #[test]
    fn test_1k_abi_mutations_crowdsale() {
        run_n_mutations(1_000, Some(CROWDSALE_ABI), false, None);
    }

    #[test]
    fn test_2k_abi_mutations() {
        const K: usize = 2_000;
        run_n_mutations(K, Some(REALLY_BIG_ABI_STRING), false, None);
    }

    #[test]
    fn round_stages() {
        test_round_stages(None);
    }

    #[test]
    fn round_stages_with_abi() {
        test_round_stages(Some(REALLY_BIG_ABI_STRING));
    }

    #[test]
    fn run_100_fuzzer_rounds_noabi() {
        const K: usize = 100;
        run_n_mutations_rounds(K, None, false, None);
    }

    #[test]
    fn run_100_fuzzer_rounds_crowdsale() {
        const K: usize = 100;
        run_n_mutations_rounds(K, Some(CROWDSALE_ABI), false, None);
    }

    #[test]
    fn run_50_fuzzer_rounds_ledgerchannel() {
        const K: usize = 50;
        run_n_mutations_rounds(K, Some(SPANKCHAIN_LEDGERCHANNEL_ABI), false, None);
    }

    #[test]
    fn run_50_fuzzer_rounds_bigabi() {
        const K: usize = 50;
        run_n_mutations_rounds(K, Some(REALLY_BIG_ABI_STRING), false, None);
    }

    #[test]
    #[ignore]
    fn run_sooooo_many_mutations() {
        const K: usize = 10_000;
        run_n_mutations_rounds(K, Some(CROWDSALE_ABI), false, None);
        run_n_mutations_rounds(K, Some(REALLY_BIG_ABI_STRING), false, None);
        run_n_mutations_rounds(K, Some(SPANKCHAIN_LEDGERCHANNEL_ABI), false, None);
    }
}
