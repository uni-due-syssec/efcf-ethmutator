use super::*;
use std::io::Write;
use tempfile::NamedTempFile;

pub fn init_mutator(abi: Option<&str>, with_dict: bool) -> EthMutator {
    let mut mutator = if let Some(abi) = abi {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", &abi).unwrap();
        // Close the file, but keep the path to it around.
        let path = file.into_temp_path();

        EthMutator::from_abi_file(path.as_os_str()).unwrap()
    } else {
        EthMutator::new()
    };

    if with_dict {
        mutator.add_token_to_dict(ethabi::Token::String("what the 🦐 ?".to_string()));
        mutator.add_token_to_dict(ethabi::Token::Bytes(b"\x00\x01\x02\x03\x04".to_vec()));
        mutator.add_token_to_dict(ethabi::Token::Uint(U256_ONE));
        mutator.add_token_to_dict(ethabi::Token::Int(U256_ZERO));
        mutator.add_token_to_dict(ethabi::Token::Int(U256::from(1338)));
        mutator.add_token_to_dict(ethabi::Token::Uint(U256_ONE << 20));
        let a_raw = [
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8,
            0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8, 0xADu8,
        ];
        let a = U256::from(a_raw);
        mutator.dict.add_value(a);
    }

    mutator
}

pub fn init_mutator_and_fuzzcases(
    abi: Option<&str>,
    with_dict: bool,
    num_fuzzcases: usize,
    allow_viewpure: bool,
) -> (EthMutator, Vec<FuzzCase>) {
    let mut res: Vec<FuzzCase> = Vec::with_capacity(num_fuzzcases);
    res.push(FuzzCase::zeroed());
    let mut mutator = init_mutator(abi, with_dict);
    mutator.allow_view_funcs = allow_viewpure;

    for _c in 0..num_fuzzcases {
        let mut fc = res.last().unwrap().clone();
        mutator.mutate_fuzzcase(&mut fc);
        res.push(fc);
    }

    (mutator, res)
}

#[inline(always)]
pub fn run_n_mutations(
    n: usize,
    abi: Option<&str>,
    bench_mode: bool,
    on_every: Option<fn(usize, &EthMutator, &Vec<u8>)>,
) {
    let mut mutator = init_mutator(abi, true);
    let initial_fc = FuzzCase::zeroed();
    let initial_testcase = pack_to_bytes(&initial_fc);

    {
        if !bench_mode && abi.is_some() {
            let contract = mutator.contracts[0].clone();
            println!(
                "ethabi::contract fallback: {} receive: {} #functions: {} #events: {}",
                contract.abi.fallback,
                contract.abi.receive,
                contract.functions.len(),
                contract.abi.events.len()
            );
            for f in contract.abi.functions() {
                if let Some((sig, _)) = contract.functions.iter().find(|(_, func)| func == f) {
                    println!("{:#x} => {:?}", sig, f.signature());
                } else {
                    println!("None => {:?}", f.signature());
                }
            }
        }
    }

    let mut testcase = initial_testcase;

    // with a rather high probability this should cover most of the mutations that we do.
    let mut mutations: usize = 0; // this roughly counts the mutation we performed
    for i in 0..n {
        //println!("{} => {}", i, hexutil::to_hex(&testcase));
        mutator.mutate(&testcase);
        testcase = mutator.current_buffer().to_vec();
        if let Some(f) = on_every {
            f(i, &mutator, &testcase);
        }
        let qlen = mutator.queue.len();
        if qlen >= 300 {
            //let i = mutator.rng.gen_range(0..(qlen - 10));
            let i = 0;
            // mutator.queue.swap_remove(i);
            mutator.queue.swap_remove_index(i);
        }
        mutator.push_to_queue(&testcase);
        mutations += mutator.stages.len();
    }

    if !bench_mode {
        println!("total mutation stage log count: {}", mutations);

        assert_ne!(mutations, 0);
        assert_ne!(mutator.current_buffer().len(), 0);
    }
}

#[inline(always)]
pub fn run_n_mutations_rounds(
    n: usize,
    abi: Option<&str>,
    bench_mode: bool,
    on_every: Option<fn(usize, &EthMutator, &[u8])>,
) {
    // test prng with fixed seed
    let mut rng = rand_pcg::Pcg64Mcg::new(42);
    let mut mutator = init_mutator(abi, true);
    let initial_fc = FuzzCase::zeroed();
    let initial_testcase = pack_to_bytes(&initial_fc);

    {
        if !bench_mode && abi.is_some() {
            let contract = mutator.contracts[0].clone();
            println!(
                "ethabi::contract fallback: {} receive: {} #functions: {} #events: {}",
                contract.abi.fallback,
                contract.abi.receive,
                contract.functions.len(),
                contract.abi.events.len()
            );
            for f in contract.abi.functions() {
                if let Some((sig, _)) = contract.functions.iter().find(|(_, func)| func == f) {
                    println!("{:#x} => {:?}", sig, f.signature());
                } else {
                    println!("None => {:?}", f.signature());
                }
            }
        }
    }

    let mut testcase = initial_testcase;
    let mut mutations: usize = 0;
    let mut round_stages: usize = 0;

    for i in 0..n {
        let rounds = mutator.start_round(&testcase, rng.gen_range(100..600));
        for c in 0..rounds {
            mutator.mutate_round();
            if let Some(f) = on_every {
                f(i, &mutator, mutator.current_buffer());
            }
            if (i == 0 && c < 30) || rng.gen_bool(0.1) {
                mutator.push_to_queue(&testcase);
                testcase = mutator.current_buffer().to_vec();
            }
        }

        round_stages = round_stages.saturating_add(rounds);
        mutations += mutator.stages.len();

        // avoid generating a too big and unrealistic queue while performing testcases
        if mutator.queue.len() >= 8192 {
            mutator.shuffle_queue();
            mutator.queue.truncate(4096);
        }
    }

    if !bench_mode {
        println!("total mutation stage-log count: {}", mutations);
        println!("total mutation round stages: {}", round_stages);
        println!("final queue length: {}", mutator.queue.len());

        assert_ne!(mutations, 0);
        assert_ne!(mutator.current_buffer().len(), 0);
    }
}

pub const CROWDSALE_ABI: &str = "
[
  {
    \"inputs\": [],
    \"stateMutability\": \"nonpayable\",
    \"type\": \"constructor\"
  },
  {
    \"inputs\": [],
    \"name\": \"echidna_alwaystrue\",
    \"outputs\": [
      {
        \"internalType\": \"bool\",
        \"name\": \"\",
        \"type\": \"bool\"
      }
    ],
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [],
    \"name\": \"invest\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [],
    \"name\": \"refund\",
    \"outputs\": [],
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"internalType\": \"address payable\",
        \"name\": \"newOwner\",
        \"type\": \"address\"
      }
    ],
    \"name\": \"setOwner\",
    \"outputs\": [],
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"internalType\": \"uint256\",
        \"name\": \"newPhase\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"setPhase\",
    \"outputs\": [],
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [],
    \"name\": \"withdraw\",
    \"outputs\": [],
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"type\": \"fallback\"
  }
]
";

pub const REALLY_BIG_ABI_STRING: &str = "
[
  {
    \"type\": \"fallback\"
  },
  {
    \"inputs\": [],
    \"name\": \"f1\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"internalType\": \"address payable\",
        \"name\": \"newOwner\",
        \"type\": \"address\"
      },
      {
        \"internalType\": \"bool\",
        \"name\": \"booool\",
        \"type\": \"bool\"
      }
    ],
    \"name\": \"setOwner\",
    \"outputs\": [],
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"internalType\": \"uint256\",
        \"name\": \"newPhase\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"setPhase\",
    \"outputs\": [],
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"internalType\": \"uint8\",
        \"name\": \"i1\",
        \"type\": \"uint8\"
      },
      {
        \"internalType\": \"uint16\",
        \"name\": \"i2\",
        \"type\": \"uint16\"
      },
      {
        \"internalType\": \"uint32\",
        \"name\": \"i3\",
        \"type\": \"uint32\"
      },
      {
        \"internalType\": \"uint64\",
        \"name\": \"i4\",
        \"type\": \"uint64\"
      },
      {
        \"internalType\": \"uint128\",
        \"name\": \"i5\",
        \"type\": \"uint128\"
      },
      {
        \"internalType\": \"uint256\",
        \"name\": \"i6\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"f_uints\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"internalType\": \"int8\",
        \"name\": \"i1\",
        \"type\": \"int8\"
      },
      {
        \"internalType\": \"int16\",
        \"name\": \"i2\",
        \"type\": \"int16\"
      },
      {
        \"internalType\": \"int32\",
        \"name\": \"i3\",
        \"type\": \"int32\"
      },
      {
        \"internalType\": \"int64\",
        \"name\": \"i4\",
        \"type\": \"int64\"
      },
      {
        \"internalType\": \"int128\",
        \"name\": \"i5\",
        \"type\": \"int128\"
      },
      {
        \"internalType\": \"int256\",
        \"name\": \"i6\",
        \"type\": \"int256\"
      }
    ],
    \"name\": \"f_ints\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"internalType\": \"bytes32\",
        \"name\": \"i1\",
        \"type\": \"bytes32\"
      },
      {
        \"internalType\": \"bytes\",
        \"name\": \"i2\",
        \"type\": \"bytes\"
      },
      {
        \"internalType\": \"string\",
        \"name\": \"i3\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"f_bytesandso\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"internalType\": \"uint[10]\",
        \"name\": \"i1\",
        \"type\": \"uint[10]\"
      },
      {
        \"internalType\": \"string[5]\",
        \"name\": \"i2\",
        \"type\": \"string[5]\"
      },
      {
        \"internalType\": \"uint[]\",
        \"name\": \"i3\",
        \"type\": \"uint[]\"
      },
      {
        \"internalType\": \"address[][]\",
        \"name\": \"i4\",
        \"type\": \"address[][]\"
      }
    ],
    \"name\": \"f_arrays\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"name\": \"c\",
        \"type\": \"tuple[]\",
        \"components\": [
          {
            \"name\": \"x\",
            \"type\": \"uint256\"
          },
          {
            \"name\": \"y\",
            \"type\": \"uint256\"
          }
        ]
      },
      {
        \"name\": \"d\",
        \"type\": \"tuple[]\",
        \"components\": [
          {
            \"name\": \"x\",
            \"type\": \"uint256\"
          },
          {
            \"name\": \"y\",
            \"type\": \"tuple[]\",
            \"components\": [
              {
                \"name\": \"x\",
                \"type\": \"uint256\"
              },
              {
                \"name\": \"y\",
                \"type\": \"string[]\"
              }
            ]
          }
        ]
      }
    ],
    \"name\": \"f_tuple\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"name\": \"a\",
        \"type\": \"bytes7\"
      },
      {
        \"name\": \"b\",
        \"type\": \"bytes8\"
      },
      {
        \"name\": \"c\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"d\",
        \"type\": \"bytes15\"
      },
      {
        \"name\": \"e\",
        \"type\": \"bytes31\"
      },
      {
        \"name\": \"f\",
        \"type\": \"bytes31\"
      },
      {
        \"name\": \"g\",
        \"type\": \"bytes23\"
      }
    ],
    \"name\": \"f_fixedbytes\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"inputs\": [
      {
        \"name\": \"a\",
        \"type\": \"bytes7\"
      },
      {
        \"name\": \"b\",
        \"type\": \"bytes8[]\"
      },
      {
        \"name\": \"c\",
        \"type\": \"bytes32[][]\"
      },
      {
        \"name\": \"d\",
        \"type\": \"bytes3\"
      },
      {
        \"name\": \"e\",
        \"type\": \"bytes31\"
      },
      {
        \"name\": \"f\",
        \"type\": \"bytes31\"
      },
      {
        \"name\": \"g\",
        \"type\": \"bytes23\"
      },
      {
        \"name\": \"h\",
        \"type\": \"tuple[]\",
        \"components\": [
          {
            \"name\": \"x\",
            \"type\": \"bytes7\"
          },
          {
            \"name\": \"y\",
            \"type\": \"uint256[]\"
          }
        ]
      }
    ],
    \"name\": \"f_weirdo\",
    \"outputs\": [],
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  }
]
";

pub const SPANKCHAIN_LEDGERCHANNEL_ABI: &str = "
[
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      }
    ],
    \"name\": \"LCOpenTimeout\",
    \"outputs\": [],
    \"payable\": false,
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"_hashedMsg\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_sig\",
        \"type\": \"string\"
      },
      {
        \"name\": \"_addr\",
        \"type\": \"address\"
      }
    ],
    \"name\": \"isSignedBy\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"bool\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"pure\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"_hexstr\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"hexstrToBytes\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"bytes\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"pure\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"\",
        \"type\": \"bytes32\"
      }
    ],
    \"name\": \"virtualChannels\",
    \"outputs\": [
      {
        \"name\": \"isClose\",
        \"type\": \"bool\"
      },
      {
        \"name\": \"isInSettlementState\",
        \"type\": \"bool\"
      },
      {
        \"name\": \"sequence\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"challenger\",
        \"type\": \"address\"
      },
      {
        \"name\": \"updateVCtimeout\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"partyA\",
        \"type\": \"address\"
      },
      {
        \"name\": \"partyB\",
        \"type\": \"address\"
      },
      {
        \"name\": \"partyI\",
        \"type\": \"address\"
      },
      {
        \"name\": \"token\",
        \"type\": \"address\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"view\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"_str\",
        \"type\": \"string\"
      },
      {
        \"name\": \"_startIndex\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"_endIndex\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"substring\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"string\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"pure\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_balances\",
        \"type\": \"uint256[2]\"
      }
    ],
    \"name\": \"joinChannel\",
    \"outputs\": [],
    \"payable\": true,
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"_char\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"parseInt16Char\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"pure\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_sequence\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"_balances\",
        \"type\": \"uint256[4]\"
      },
      {
        \"name\": \"_sigA\",
        \"type\": \"string\"
      },
      {
        \"name\": \"_sigI\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"consensusCloseChannel\",
    \"outputs\": [],
    \"payable\": false,
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [],
    \"name\": \"numChannels\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"view\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"id\",
        \"type\": \"bytes32\"
      }
    ],
    \"name\": \"getChannel\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"address[2]\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256[4]\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256[4]\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256[2]\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"\",
        \"type\": \"bool\"
      },
      {
        \"name\": \"\",
        \"type\": \"bool\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"view\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"_uint\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"uintToBytes32\",
    \"outputs\": [
      {
        \"name\": \"b\",
        \"type\": \"bytes\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"pure\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [],
    \"name\": \"NAME\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"string\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"view\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_partyI\",
        \"type\": \"address\"
      },
      {
        \"name\": \"_confirmTime\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"_token\",
        \"type\": \"address\"
      },
      {
        \"name\": \"_balances\",
        \"type\": \"uint256[2]\"
      }
    ],
    \"name\": \"createChannel\",
    \"outputs\": [],
    \"payable\": true,
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_vcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_proof\",
        \"type\": \"bytes\"
      },
      {
        \"name\": \"_partyA\",
        \"type\": \"address\"
      },
      {
        \"name\": \"_partyB\",
        \"type\": \"address\"
      },
      {
        \"name\": \"_bond\",
        \"type\": \"uint256[2]\"
      },
      {
        \"name\": \"_balances\",
        \"type\": \"uint256[4]\"
      },
      {
        \"name\": \"sigA\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"initVCstate\",
    \"outputs\": [],
    \"payable\": false,
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"recipient\",
        \"type\": \"address\"
      },
      {
        \"name\": \"_balance\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"isToken\",
        \"type\": \"bool\"
      }
    ],
    \"name\": \"deposit\",
    \"outputs\": [],
    \"payable\": true,
    \"stateMutability\": \"payable\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      }
    ],
    \"name\": \"byzantineCloseChannel\",
    \"outputs\": [],
    \"payable\": false,
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"\",
        \"type\": \"bytes32\"
      }
    ],
    \"name\": \"Channels\",
    \"outputs\": [
      {
        \"name\": \"sequence\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"confirmTime\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"VCrootHash\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"LCopenTimeout\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"updateLCtimeout\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"isOpen\",
        \"type\": \"bool\"
      },
      {
        \"name\": \"isUpdateLCSettling\",
        \"type\": \"bool\"
      },
      {
        \"name\": \"numOpenVC\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"token\",
        \"type\": \"address\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"view\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_vcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"updateSeq\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"_partyA\",
        \"type\": \"address\"
      },
      {
        \"name\": \"_partyB\",
        \"type\": \"address\"
      },
      {
        \"name\": \"updateBal\",
        \"type\": \"uint256[4]\"
      },
      {
        \"name\": \"sigA\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"settleVC\",
    \"outputs\": [],
    \"payable\": false,
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"_msg\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"toEthereumSignedMessage\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"bytes32\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"pure\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"_hashedMsg\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_sig\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"recoverSigner\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"address\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"pure\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"updateParams\",
        \"type\": \"uint256[6]\"
      },
      {
        \"name\": \"_VCroot\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_sigA\",
        \"type\": \"string\"
      },
      {
        \"name\": \"_sigI\",
        \"type\": \"string\"
      }
    ],
    \"name\": \"updateLCstate\",
    \"outputs\": [],
    \"payable\": false,
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"_uint\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"uintToString\",
    \"outputs\": [
      {
        \"name\": \"str\",
        \"type\": \"string\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"pure\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [
      {
        \"name\": \"id\",
        \"type\": \"bytes32\"
      }
    ],
    \"name\": \"getVirtualChannel\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"bool\"
      },
      {
        \"name\": \"\",
        \"type\": \"bool\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"\",
        \"type\": \"address\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256\"
      },
      {
        \"name\": \"\",
        \"type\": \"address\"
      },
      {
        \"name\": \"\",
        \"type\": \"address\"
      },
      {
        \"name\": \"\",
        \"type\": \"address\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256[2]\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256[2]\"
      },
      {
        \"name\": \"\",
        \"type\": \"uint256[2]\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"view\",
    \"type\": \"function\"
  },
  {
    \"constant\": false,
    \"inputs\": [
      {
        \"name\": \"_lcID\",
        \"type\": \"bytes32\"
      },
      {
        \"name\": \"_vcID\",
        \"type\": \"bytes32\"
      }
    ],
    \"name\": \"closeVirtualChannel\",
    \"outputs\": [],
    \"payable\": false,
    \"stateMutability\": \"nonpayable\",
    \"type\": \"function\"
  },
  {
    \"constant\": true,
    \"inputs\": [],
    \"name\": \"VERSION\",
    \"outputs\": [
      {
        \"name\": \"\",
        \"type\": \"string\"
      }
    ],
    \"payable\": false,
    \"stateMutability\": \"view\",
    \"type\": \"function\"
  },
  {
    \"anonymous\": false,
    \"inputs\": [
      {
        \"indexed\": true,
        \"name\": \"channelId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": true,
        \"name\": \"partyA\",
        \"type\": \"address\"
      },
      {
        \"indexed\": true,
        \"name\": \"partyI\",
        \"type\": \"address\"
      },
      {
        \"indexed\": false,
        \"name\": \"ethBalanceA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"token\",
        \"type\": \"address\"
      },
      {
        \"indexed\": false,
        \"name\": \"tokenBalanceA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"LCopenTimeout\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"DidLCOpen\",
    \"type\": \"event\"
  },
  {
    \"anonymous\": false,
    \"inputs\": [
      {
        \"indexed\": true,
        \"name\": \"channelId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": false,
        \"name\": \"ethBalanceI\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"tokenBalanceI\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"DidLCJoin\",
    \"type\": \"event\"
  },
  {
    \"anonymous\": false,
    \"inputs\": [
      {
        \"indexed\": true,
        \"name\": \"channelId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": true,
        \"name\": \"recipient\",
        \"type\": \"address\"
      },
      {
        \"indexed\": false,
        \"name\": \"deposit\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"isToken\",
        \"type\": \"bool\"
      }
    ],
    \"name\": \"DidLCDeposit\",
    \"type\": \"event\"
  },
  {
    \"anonymous\": false,
    \"inputs\": [
      {
        \"indexed\": true,
        \"name\": \"channelId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": false,
        \"name\": \"sequence\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"numOpenVc\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"ethBalanceA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"tokenBalanceA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"ethBalanceI\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"tokenBalanceI\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"vcRoot\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": false,
        \"name\": \"updateLCtimeout\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"DidLCUpdateState\",
    \"type\": \"event\"
  },
  {
    \"anonymous\": false,
    \"inputs\": [
      {
        \"indexed\": true,
        \"name\": \"channelId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": false,
        \"name\": \"sequence\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"ethBalanceA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"tokenBalanceA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"ethBalanceI\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"tokenBalanceI\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"DidLCClose\",
    \"type\": \"event\"
  },
  {
    \"anonymous\": false,
    \"inputs\": [
      {
        \"indexed\": true,
        \"name\": \"lcId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": true,
        \"name\": \"vcId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": false,
        \"name\": \"proof\",
        \"type\": \"bytes\"
      },
      {
        \"indexed\": false,
        \"name\": \"sequence\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"partyA\",
        \"type\": \"address\"
      },
      {
        \"indexed\": false,
        \"name\": \"partyB\",
        \"type\": \"address\"
      },
      {
        \"indexed\": false,
        \"name\": \"balanceA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"balanceB\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"DidVCInit\",
    \"type\": \"event\"
  },
  {
    \"anonymous\": false,
    \"inputs\": [
      {
        \"indexed\": true,
        \"name\": \"lcId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": true,
        \"name\": \"vcId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": false,
        \"name\": \"updateSeq\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"updateBalA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"updateBalB\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"challenger\",
        \"type\": \"address\"
      },
      {
        \"indexed\": false,
        \"name\": \"updateVCtimeout\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"DidVCSettle\",
    \"type\": \"event\"
  },
  {
    \"anonymous\": false,
    \"inputs\": [
      {
        \"indexed\": true,
        \"name\": \"lcId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": true,
        \"name\": \"vcId\",
        \"type\": \"bytes32\"
      },
      {
        \"indexed\": false,
        \"name\": \"balanceA\",
        \"type\": \"uint256\"
      },
      {
        \"indexed\": false,
        \"name\": \"balanceB\",
        \"type\": \"uint256\"
      }
    ],
    \"name\": \"DidVCClose\",
    \"type\": \"event\"
  }
]
";
