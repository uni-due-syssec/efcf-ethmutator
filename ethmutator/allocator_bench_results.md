# Allocator Performance Showdown

## Server/VM Usecase

model name	: Intel(R) Xeon(R) CPU E5-1630 v4 @ 3.70GHz
cpu MHz         : 3691.450
GNU C Library (GNU libc) release release version 2.33.

### Default Allocator

```
test bench_fuzzer_1sec_deserializer_abi_mutations     ... bench: 1,736,043,403 ns/iter (+/- 23,572,976)
test bench_fuzzer_1sec_mutator_abi_rand_stages        ... bench: 193,978,703 ns/iter (+/- 280,028,107)
test bench_fuzzer_1sec_queue_update                   ... bench:     744,853 ns/iter (+/- 38,004)
test bench_fuzzer_1sec_serializer_abi_mutations       ... bench: 150,408,256 ns/iter (+/- 187,310,351)
test bench_k_abi_mutations_bigabi_overall             ... bench:  89,129,597 ns/iter (+/- 2,619,719)
test bench_k_abi_mutations_crowdsale_overall          ... bench:  10,554,900 ns/iter (+/- 1,066,508)
test bench_k_abi_mutations_ledgerchannel_overall      ... bench:  33,673,346 ns/iter (+/- 1,179,202)
test bench_k_mutations                                ... bench:  17,313,890 ns/iter (+/- 1,258,270)
```

### jemalloc

```
test bench_fuzzer_1sec_deserializer_abi_mutations     ... bench: 1,312,670,424 ns/iter (+/- 60,904,125)
test bench_fuzzer_1sec_mutator_abi_rand_stages        ... bench: 139,612,627 ns/iter (+/- 189,868,405)
test bench_fuzzer_1sec_queue_update                   ... bench:     604,146 ns/iter (+/- 40,551)
test bench_fuzzer_1sec_serializer_abi_mutations       ... bench: 156,588,441 ns/iter (+/- 1,717,162)
test bench_k_abi_mutations_bigabi_overall             ... bench:  77,489,311 ns/iter (+/- 3,893,101)
test bench_k_abi_mutations_crowdsale_overall          ... bench:   9,889,009 ns/iter (+/- 1,051,333)
test bench_k_abi_mutations_ledgerchannel_overall      ... bench:  29,118,273 ns/iter (+/- 1,619,201)
test bench_k_mutations                                ... bench:  15,573,050 ns/iter (+/- 922,720)
```

### mimalloc

```
test bench_fuzzer_1sec_deserializer_abi_mutations     ... bench: 556,690,274 ns/iter (+/- 7,357,383)
test bench_fuzzer_1sec_mutator_abi_rand_stages        ... bench: 117,702,919 ns/iter (+/- 148,696,094)
test bench_fuzzer_1sec_queue_update                   ... bench:     513,259 ns/iter (+/- 22,706)
test bench_fuzzer_1sec_serializer_abi_mutations       ... bench: 150,479,675 ns/iter (+/- 2,950,779)
test bench_k_abi_mutations_bigabi_overall             ... bench:  67,432,642 ns/iter (+/- 2,756,374)
test bench_k_abi_mutations_crowdsale_overall          ... bench:   9,450,708 ns/iter (+/- 384,547)
test bench_k_abi_mutations_ledgerchannel_overall      ... bench:  26,942,554 ns/iter (+/- 866,414)
test bench_k_mutations                                ... bench:  14,075,478 ns/iter (+/- 399,360)
```

### snmalloc

```
test bench_fuzzer_1sec_deserializer_abi_mutations     ... bench: 466,197,768 ns/iter (+/- 11,209,568)
test bench_fuzzer_1sec_mutator_abi_rand_stages        ... bench: 114,813,016 ns/iter (+/- 141,047,025)
test bench_fuzzer_1sec_queue_update                   ... bench:     511,945 ns/iter (+/- 26,828)
test bench_fuzzer_1sec_serializer_abi_mutations       ... bench: 224,521,943 ns/iter (+/- 174,684,708)
test bench_k_abi_mutations_bigabi_overall             ... bench:  64,965,022 ns/iter (+/- 84,570,928)
test bench_k_abi_mutations_crowdsale_overall          ... bench:   8,599,992 ns/iter (+/- 12,347,783)
test bench_k_abi_mutations_ledgerchannel_overall      ... bench:  25,432,094 ns/iter (+/- 29,963,158)
test bench_k_mutations                                ... bench:  30,338,634 ns/iter (+/- 2,877,206)
```


## Laptop Usecase

model name	: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
cpu MHz		: 800.006
GNU C Library (GNU libc) stable release version 2.34.

### Default Allocator

```
test bench_fuzzer_1sec_deserializer_abi_mutations     ... bench: 2,397,435,440 ns/iter (+/- 1,634,830,547)
test bench_fuzzer_1sec_mutator_abi_rand_stages        ... bench: 216,933,622 ns/iter (+/- 45,429,046)
test bench_fuzzer_1sec_queue_update                   ... bench:     963,848 ns/iter (+/- 149,085)
test bench_fuzzer_1sec_serializer_abi_mutations       ... bench: 151,095,770 ns/iter (+/- 144,278,657)
test bench_k_abi_mutations_bigabi_overall             ... bench: 114,758,963 ns/iter (+/- 8,620,476)
test bench_k_abi_mutations_crowdsale_overall          ... bench:  13,285,355 ns/iter (+/- 1,850,175)
test bench_k_abi_mutations_ledgerchannel_overall      ... bench:  43,335,131 ns/iter (+/- 7,220,879)
test bench_k_mutations                                ... bench:  24,777,121 ns/iter (+/- 7,504,671)
```

### jemalloc

```
test bench_fuzzer_1sec_deserializer_abi_mutations     ... bench: 2,149,485,351 ns/iter (+/- 1,849,881,229)
test bench_fuzzer_1sec_mutator_abi_rand_stages        ... bench: 172,495,611 ns/iter (+/- 207,993,210)
test bench_fuzzer_1sec_queue_update                   ... bench:     812,803 ns/iter (+/- 293,689)
test bench_fuzzer_1sec_serializer_abi_mutations       ... bench: 173,760,967 ns/iter (+/- 171,774,433)
test bench_k_abi_mutations_bigabi_overall             ... bench: 185,185,893 ns/iter (+/- 180,886,600)
test bench_k_abi_mutations_crowdsale_overall          ... bench:  12,873,761 ns/iter (+/- 617,672)
test bench_k_abi_mutations_ledgerchannel_overall      ... bench:  69,373,372 ns/iter (+/- 64,772,150)
test bench_k_mutations                                ... bench:  41,549,512 ns/iter (+/- 46,399,606)
```

### mimalloc

```
test bench_fuzzer_1sec_deserializer_abi_mutations     ... bench: 550,168,011 ns/iter (+/- 477,704,003)
test bench_fuzzer_1sec_mutator_abi_rand_stages        ... bench: 135,280,066 ns/iter (+/- 163,959,687)
test bench_fuzzer_1sec_queue_update                   ... bench:     636,752 ns/iter (+/- 41,498)
test bench_fuzzer_1sec_serializer_abi_mutations       ... bench: 153,598,396 ns/iter (+/- 148,282,664)
test bench_k_abi_mutations_bigabi_overall             ... bench:  78,589,260 ns/iter (+/- 6,501,527)
test bench_k_abi_mutations_crowdsale_overall          ... bench:  13,687,954 ns/iter (+/- 13,186,698)
test bench_k_abi_mutations_ledgerchannel_overall      ... bench:  68,696,615 ns/iter (+/- 79,063,767)
test bench_k_mutations                                ... bench:  16,852,692 ns/iter (+/- 1,342,218)
```

### snmalloc

```
test bench_fuzzer_1sec_deserializer_abi_mutations     ... bench: 529,028,109 ns/iter (+/- 588,254,539)
test bench_fuzzer_1sec_mutator_abi_rand_stages        ... bench: 133,625,970 ns/iter (+/- 137,669,214)
test bench_fuzzer_1sec_queue_update                   ... bench:     641,358 ns/iter (+/- 68,354)
test bench_fuzzer_1sec_serializer_abi_mutations       ... bench: 139,303,437 ns/iter (+/- 229,899,604)
test bench_k_abi_mutations_bigabi_overall             ... bench: 146,455,187 ns/iter (+/- 121,761,710)
test bench_k_abi_mutations_crowdsale_overall          ... bench:  10,910,151 ns/iter (+/- 863,852)
test bench_k_abi_mutations_ledgerchannel_overall      ... bench:  38,073,238 ns/iter (+/- 30,655,967)
test bench_k_mutations                                ... bench:  16,367,818 ns/iter (+/- 3,939,593)
```
