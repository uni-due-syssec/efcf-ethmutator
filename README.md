# Etherum ABI Mutator

A mutator library for fuzzing Ethereum/EVM smart contracts, which require a
input structured according to their Ethereum ABI. The mutator operates on a
list of transactions and mutates both the order of transactions and the
transactions themselves.

**Operations on Transaction Lists:**

* Changing the order of the transactions
* Adding and dropping transactions
* Deduplicating according to first 4 bytes (function signature short hash)
* Splicing with other transaction lists
* Duplicating transactions and setting the reentrancy flag
* ...

**Transaction Operations:**

* Change the caller
* Change the call value (i.e., transferred ether)
* Mutate the transaction input
* Add return values and data (used when the target calls back into the
  attacker)
* Allow or disallow further reentrant transactions.
* ...

**Input Operations:**

* Structured random mutation of the input without ABI definition (i.e., random
  ABI parameters)
* Structured mutation according to ABI definition
* Replacing parameters
* ...

**Dictionary:**

* Dictionary per ABI data type / bit-width for fast access
* For all ABI data types we also support inserting potentially interesting values from the dictionary
* The dictionary uses the same format as AFL++, but the raw data is parsed into
  ethereum big integers.
    * Currently all entries with length `<= 32` are treated as integer types
      and all other entries are considered bytes/strings.
    * Also we have some simple heuristics to identify 4-byte signatures, ethereum 
      addresses, and 64-bit values as consumed by the fuzzing harness.
      
**Custom Compare Tracing:**

* Run the target in a custom compare tracing mode to obtain:
    * Parameters of comparison operators such as `EQ` or `GT`
    * The data returned by the contract (using the `RETURN` opcode)


**Multi Contract**:

The library supports multi-abi fuzzing. However, it is a relatively recent
addition, so beware of potential issues and inefficiencies.


## Runtime Configuration

Some parts of the mutator can be configured via environment variables, which
must be set before the mutator is loaded.

* `EM_ADD_VIEW_FUNCS` - Whether the mutator adds function calls to the
  transaction list, which are not supposed to mutate state. These are usually
  not really interesting. However, some view functions are useful for the
  mutator to obtain a special return value.
* `EM_ALLOW_COMPTRACE` - Whether the mutator is allowed to perform the custom
  compare tracing.
* `EM_COMPTRACE_TIMEOUT` - Timeout in seconds for the compare tracing step of
  the custom mutator.
* `CONTRACT_ABI` - the AFL custom mutator reads the contract's ABI from this
  file.

## Building

As almost any rust project:

```
cargo build --release
```

...the `--release` flag is highly recommended when fuzzing to enable all the
nice compiler optimizations.


## AFL++ Custom Mutator

`afl_ethmutator` is currently the primary user of the ethmutator library and is
a wrapper that makes the *ethmutator* available to AFL as a custom mutator by
implementing the right C API.

Usage:

```
$ cargo build --release
$ env AFL_CUSTOM_MUTATOR_LIBRARY=$(realpath ./target/release/libafl_ethmutator.so) \
    afl-fuzz \
        -i /path/to/seeds \
        -o /path/to/queue -- /path/to/eEVM/build/[...]/fuzz_multitx

```

## Utils

This projects contains also several helpful utility programs to deal with the
custom fuzzcase format.

### Fuzzcase Minimizer

The fuzzcases often contain a lot of random garbage, e.g., additional bytes of
input, unrelated transactions, a certain random block timestamp etc. The
`efuzzcaseminimizer` tool will take an input and the fuzz target and minimize
the fuzzcase based on whether the fuzzed binary will still `SIGABRT`. This
means that we will have the smallest possible crash reproducer. This is
particularly interesting in combination with the `efuzzcaseanalyzer` tool with
the `--summarize` flag to get a sense of how many distinct bugs have been
found.

*Example:*

```
$ efuzzcaseminimizer --abi ./contract.abi ./build/fuzz_multitx ./default/crashes/id:000000,sig:06,src:000078+000056,time:13954,EM-________SA________A_
=== Before minimizing: ===
Block header:
  number: 0
  difficulty: 68121342813143040
  gas_limit: 0
  timestamp: 321
TX with tx_sender: 209 (selector); call_value: 0x0; length: 36
  func: setOwner(address)
  input: { Address(0x0000000000000000000000000000000000000000),  }
TX with tx_sender: 183 (selector); call_value: 0x0; length: 36
  func: setOwner(address)
  input: { Address(0xffffffffffffffffffffffffffffffffffffffff),  }
TX with tx_sender: 0 (selector); call_value: 0x7fcf5f0ccccccc00; length: 18
  func: invest()
  input: 0x000000000000ef0400015fcf9fce [failed to decode]
TX with tx_sender: 200 (selector); call_value: 0x0; length: 36
  func: setPhase(uint256)
  input: { Uint(1),  }
TX with tx_sender: 52 (selector); call_value: 0x0; length: 4
  func: withdraw()
  input: {  }
=== After minimizing: ===
Block header:
  number: 0
  difficulty: 0
  gas_limit: 0
  timestamp: 0
TX with tx_sender: 0 (selector); call_value: 0x0; length: 36
  func: setOwner(address)
  input: { Address(0xffffffffffffffffffffffffffffffffffffffff),  }
TX with tx_sender: 0 (selector); call_value: 0x7fcf5f0ccccccc00; length: 4
  func: invest()
  input: {  }
TX with tx_sender: 0 (selector); call_value: 0x0; length: 36
  func: setPhase(uint256)
  input: { Uint(1),  }
TX with tx_sender: 0 (selector); call_value: 0x0; length: 4
  func: withdraw()
  input: {  }
```


### Fuzzcase Analyzer

Allows for pretty printing and analysis of the provided fuzzcase, e.g.,

```
$ efuzzcaseanalyzer --abi ../../../../contracts/Grid.abi ../crashes/id:000000,sig:06,src:000142+000215,time:87003,EVM-a_____S____
TX with tx_sender: 209 (selector); call_value: 0x0; length: 36
  func: setFeeRatio(uint256)
  input: { Uint(58),  }
TX with tx_sender: 113 (selector); call_value: 0x0; length: 36
  func: setFeeRatio(uint256)
  input: { Uint(145),  }
TX with tx_sender: 185 (selector); call_value: 0x0; length: 36
  func: setAdmin(address)
  input: { Address(0x0fe18c3f08417e77b94fb541fed2bf1e09093edd),  }
TX with tx_sender: 121 (selector); call_value: 0x2ddeee5e376f9a68; length: 100
  func: buyPixel(uint16,uint16,uint24)
  input: { Uint(0), Uint(0), Uint(73),  }
TX with tx_sender: 52 (selector); call_value: 0x9a583d189fb4a101; length: 100
  func: buyPixel(uint16,uint16,uint24)
  input: { Uint(99), Uint(218), Uint(8192),  }
TX with tx_sender: 218 (selector); call_value: 0x0; length: 4
  func: withdraw()
  input: {  }
```

The analyzer can also `--summarize` a whole directory of fuzzcases.


### Fuzzcase Transcoder

This allows you to convert a binary fuzzcase to a readable yaml version and
back again. The idea here is that sometimes you want to manually modify or
create a new fuzzcase from scratch. For this task a readable yaml file is
pretty nice. Note that the yaml just represents the structure of the
transactions, but not the structure of the transaction inputs. If you want to
change individual transaction inputs or return data then it is best to use the
`ethabi` cli tool to encode/decode the input or return data.

```
$ efuzzcasetranscoder ../crashes/id:000000,sig:06,src:000142+000215,time:87003,EVM-a_____S____ ./some-crashing.yml
$ $EDITOR ./some-crashing.yml
$ efuzzcasetranscoder ./some-crashing.yml ./some-crashing.bin
$ env EVM_DEBUG_PRINT=1 ./path/to/build/fuzz_multitx ./some-crashing.bin
```


### Exploit Synthesizer

This tool converts a fuzzcase into a set of solidity attack contracts, i.e.,
something that can be deployed on a blockchain to debug the contract, verify
the generated attack, or to gain some retirement money.

It is highly recommended to minimize the testcase before running the
synthesizer.

```
$ efuzzcasesynthesizer ./crashes_min/something attack.sol
```
