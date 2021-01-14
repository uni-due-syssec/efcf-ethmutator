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

#![feature(test)]

extern crate test;

use ethmutator::{pack_to_bytes, FuzzCase};
use rand::prelude::*;
use std::{thread, time};
use test::{black_box, Bencher};

const INIT_K: usize = 10_000;
const K: usize = 10_000;
//const BIG_K: usize = K * 10;

// NOTE: this is essentially the old "unstaged" mode of operation for the ethmutator
fn bench_k_abi_mutations_overall_unstaged(bencher: &mut Bencher, abi: Option<&str>) {
    let mutator_base = ethmutator::test_helpers::init_mutator(abi, true);

    let fc = FuzzCase::zeroed();
    let initial_testcase = pack_to_bytes(&fc);

    bencher.iter(|| {
        let mut mutator = mutator_base.clone();
        let mut testcase = initial_testcase.clone();

        for _ in 0..K {
            mutator.mutate(&testcase);
            testcase = mutator.current_buffer().to_vec();
            mutator.push_to_queue(&testcase);
        }
        black_box(testcase)
    });
}

#[ignore]
#[bench]
fn bench_k_abi_mutations_crowdsale_overall_unstaged(bencher: &mut Bencher) {
    bench_k_abi_mutations_overall_unstaged(bencher, Some(ethmutator::test_helpers::CROWDSALE_ABI));
}

#[ignore]
#[bench]
fn bench_k_abi_mutations_bigabi_overall_unstaged(bencher: &mut Bencher) {
    bench_k_abi_mutations_overall_unstaged(
        bencher,
        Some(ethmutator::test_helpers::REALLY_BIG_ABI_STRING),
    );
}

#[ignore]
#[bench]
fn bench_k_mutations_unstaged(bencher: &mut Bencher) {
    bench_k_abi_mutations_overall_unstaged(bencher, None);
}

/// Simulate/benchmark the usage of ethmutator in AFL++
#[inline(always)]
fn bench_k_abi_mutations_overall_staged(bencher: &mut Bencher, abi: Option<&str>) {
    let mutator_base = ethmutator::test_helpers::init_mutator(abi, true);
    let initial_fc = FuzzCase::zeroed();
    let initial_testcase = pack_to_bytes(&initial_fc);
    let mut queue: Vec<Vec<u8>> = vec![initial_testcase.clone()];
    let exec_time = time::Duration::from_micros(1);

    bencher.iter(|| {
        // test prng with fixed seed
        let mut rng = rand_pcg::Pcg64Mcg::new(42);
        let mut mutator = mutator_base.clone();
        mutator.seed(1337);
        let mut i: usize = 0;

        // simulate the fuzzer loop
        while i < K {
            // we select a random testcase from the queue
            let qidx = rng.gen_range(0..queue.len());

            // AFL++ select the number of rounds according to a performance score. Here we just used
            // the rng to select a somewhat reasonable value.
            let rounds = mutator.start_round(&queue[qidx], rng.gen_range(256..512));
            // the custom mutator returns the number of mutations it wants to perform back to AFL++.
            for c in 0..rounds {
                // perform the mutation round
                mutator.mutate_round();

                // at this point AFL would execute the generated testcase and act according to the
                // gathered coverage feedback.
                thread::sleep(exec_time);

                // half of the first 60 generated testcases are always pushed to the queue.
                // Afterwards we only push with a low probability. This is kind of similar to what
                // we expect from a real fuzzing run.
                if (i == 0 && c < 60 && (c & 1) == 0) || rng.gen_bool(0.01) {
                    let fcb = mutator.current_buffer().to_owned();

                    // AFL++ actually performs the trimming only when the testcase is selected from
                    // the queue and was not trimmed before. However, since we don't keep track of
                    // what testcases in the queue have been minimized, we just do this here. This
                    // should somewhat approximate the trimming behavior in AFL++.
                    let expected_steps = mutator.init_trim(&fcb);
                    if expected_steps > 0 {
                        loop {
                            mutator.trim_step();
                            thread::sleep(exec_time);
                            // most of the trimming stages do not succeed
                            let success = rng.gen_bool(0.95);
                            if mutator.trim_status(success) >= expected_steps {
                                break;
                            }
                        }
                    }

                    let tc = mutator.current_trim_buffer().to_owned();
                    queue.push(tc);
                }
            }

            i = i.saturating_add(rounds);
        }
    });
}

#[bench]
fn bench_k_mutations(bencher: &mut Bencher) {
    bench_k_abi_mutations_overall_staged(bencher, None);
}

#[bench]
fn bench_k_abi_mutations_crowdsale_overall(bencher: &mut Bencher) {
    bench_k_abi_mutations_overall_staged(bencher, Some(ethmutator::test_helpers::CROWDSALE_ABI));
}

#[bench]
fn bench_k_abi_mutations_ledgerchannel_overall(bencher: &mut Bencher) {
    bench_k_abi_mutations_overall_staged(
        bencher,
        Some(ethmutator::test_helpers::SPANKCHAIN_LEDGERCHANNEL_ABI),
    );
}

#[bench]
fn bench_k_abi_mutations_bigabi_overall(bencher: &mut Bencher) {
    bench_k_abi_mutations_overall_staged(
        bencher,
        Some(ethmutator::test_helpers::REALLY_BIG_ABI_STRING),
    );
}

fn get_n_mutations(n: usize) -> (Vec<Vec<u8>>, Vec<ethmutator::FuzzCase>) {
    let mut mutations: Vec<Vec<u8>> = Vec::new();
    let mut parsed_mutations: Vec<ethmutator::FuzzCase> = Vec::new();

    let mut fc = ethmutator::FuzzCase::zeroed();
    let mut mutator = ethmutator::test_helpers::init_mutator(
        Some(ethmutator::test_helpers::REALLY_BIG_ABI_STRING),
        true,
    );

    for _i in 0..n {
        mutator.mutate_one(&mut fc);
        parsed_mutations.push(fc.clone());
        mutations.push(ethmutator::pack_to_bytes(&fc));
    }

    (mutations, parsed_mutations)
}

#[bench]
fn bench_fuzzer_1sec_deserializer_abi_mutations(bencher: &mut Bencher) {
    let (mutations, _) = get_n_mutations(K);
    bencher.iter(|| {
        for testcase in mutations.iter() {
            let fc = ethmutator::parse_bytes(testcase);
            black_box(fc);
        }
    });
}

#[bench]
fn bench_fuzzer_1sec_serializer_abi_mutations(bencher: &mut Bencher) {
    let mut buffer: Vec<u8> = Vec::with_capacity(4096);
    let (_, mutations) = get_n_mutations(K);
    bencher.iter(|| {
        for fc in mutations.iter() {
            ethmutator::pack_into_bytes(fc, &mut buffer);
            black_box(fc);
        }
    });
}

#[bench]
fn bench_fuzzer_1sec_queue_update(bencher: &mut Bencher) {
    let mut mutator = ethmutator::test_helpers::init_mutator(
        Some(ethmutator::test_helpers::REALLY_BIG_ABI_STRING),
        true,
    );
    let (mutations, _) = get_n_mutations(100);

    bencher.iter(|| {
        for input in mutations.iter() {
            mutator.push_to_queue(input);
        }
    });
}

#[bench]
fn bench_fuzzer_1sec_mutator_abi_rand_stages(bencher: &mut Bencher) {
    let mut mutator = ethmutator::test_helpers::init_mutator(
        Some(ethmutator::test_helpers::REALLY_BIG_ABI_STRING),
        true,
    );
    let fc = FuzzCase::zeroed();
    let initial_testcase = pack_to_bytes(&fc);
    let mut testcase = initial_testcase.clone();
    for _ in 0..INIT_K {
        mutator.mutate(&testcase);
        testcase = mutator.current_buffer().to_vec();
        mutator.push_to_queue(&testcase);
    }

    let mut fc = FuzzCase::zeroed();

    bencher.iter(|| {
        for _i in 0..K {
            mutator.mutate_one(&mut fc);
        }
    });
}
