use ethmutator::test_helpers::*;
use ethmutator::*;
use rand::prelude::*;

const ITERATIONS: usize = 10_000;
const ROUNDS: usize = 128;
const SEED: u64 = 0xdeadb33f133742;

fn main() {
    let initial_fc = FuzzCase::zeroed();
    let initial_bytes = pack_to_bytes(&initial_fc);

    // we uise a constant seed to provide determinism
    let mut rng: rand_pcg::Pcg64Mcg = rand::SeedableRng::seed_from_u64(SEED);

    for abi in (&[
        CROWDSALE_ABI,
        REALLY_BIG_ABI_STRING,
        SPANKCHAIN_LEDGERCHANNEL_ABI,
    ])
        .iter()
    {
        let mut mutator = init_mutator(Some(abi), true);
        let mut fuzzcase_queue: Vec<Vec<u8>> = vec![initial_bytes.clone()];

        for _iteration in 0..ITERATIONS {
            let b = fuzzcase_queue.pop().unwrap();
            let c = mutator.start_round(&b, ROUNDS);
            for round in 0..c {
                mutator.mutate_round();

                let b = match round {
                    33 | 76 | 80 | 128 => true,
                    r => r == (c - 3) || rng.gen_bool(0.001),
                };
                if b {
                    fuzzcase_queue.push(mutator.current_buffer().to_vec())
                }
            }

            fuzzcase_queue.shuffle(&mut rng);
        }
    }
}
