# LEMUR-Fuzz

LEMUR-Fuzz is a protocol fuzzer that enhances AFLNet with **LLM-generated, semantic-aware mutation components**.  
It is implemented **on top of AFLNet** and preserves the original fuzzing workflow, while extending it with protocol-specific parsers, reassemblers, mutators, and constraint fixers generated from protocol specifications.

LEMUR-Fuzz aims to generate **protocol-valid and semantically consistent messages** more effectively, enabling deeper protocol execution and improved bug discovery.

---

## Overview

Traditional mutation-based protocol fuzzers operate primarily at the byte level, which often leads to malformed or semantically invalid messages.  
LEMUR-Fuzz introduces a **semantic-aware stage** into the standard AFLNet mutation pipeline.

Rather than replacing classic byte-level mutation, LEMUR-Fuzz integrates semantic-aware mutation with the original AFLNet mechanisms to balance semantic validity and mutation diversity. In semantic-aware mutation:

- Raw bytes are parsed into structured **message templates**
- Mutations are applied at the **field level**, guided by protocol semantics
- Cross-field inconsistencies are repaired by **constraint fixers**
- Modified messages are reassembled into byte streams and sent to the target server

All semantic-aware components are generated once before fuzzing and reused during fuzzing without invoking the LLM again.

---

## Code Structure

```text
lemur-fuzz/
├── llm/ # LLM-generated protocol-specific components
│ ├── protocol1/
│ │ ├── protocol1_packets.h        # Message templates for each protocol/message type
│ │ ├── protocol1_parser.c         # Generated parsers (bytes → message templates)
│ │ ├── protocol1_reassembler.c    # Generated reassemblers (templates → bytes)
│ │ ├── protocol1_mutators.c       # Semantic-aware field-level mutators
│ │ └── protocol1_fixers.c         # Constraint fixers for cross-field consistency
│ ├── protocol2/
│ ├── ...
│
├── tests/ # Automated quality-checking scripts for generated components
│ ├── PR_mr/          # metamorphic relation tests for parsers and reassemblers
│ ├── mutator_sanity/ # post-mutation parseability tests for mutators
│ └── fixer_sanity/   # constraint-violation tests for constraint fixers
│
├── afl-fuzz.c # AFLNet-based fuzzing engine (extended)
└── README.md
```

---

## Building and Running

LEMUR-Fuzz follows the same build and execution workflow as AFLNet.

Please refer to the original AFLNet documentation (`README-AFLNet.md`) for:

- Build dependencies
- Target server instrumentation
- Network configuration
- Fuzzing command-line options

In most cases, existing AFLNet experiment scripts can be reused directly.

---

## Supported Protocols

LEMUR-Fuzz currently provides protocol-specific semantic-aware components for the following protocols:

- **MQTT 5.0** (e.g., Mosquitto, NanoMQ)
- **RTSP** (e.g., live555)
- **SIP** (e.g., Kamailio)
- **FTP** (e.g., ProFTPD, Pure-FTPd)
- **SMTP** (e.g., Exim)
- **DTLS 1.2** (e.g., TinyDTLS)

---



## Example: Running a Fuzzing Experiment (Mosquitto / MQTT)

Below is a minimal example that follows the same command-line style as AFLNet.  
Please adjust paths, seeds, and server command to your setup.

```bash
# (1) Compile LEMUR-Fuzz and set the environment variables 
cd lemur-fuzz && make clean all && cd llvm_mode && make clean
cd ../..
export LEMUR=$(pwd)/lemur-fuzz
export WORKDIR=$(pwd)
export PATH=$PATH:$LEMUR
export AFL_PATH=$LEMUR

# (2) Compile mosquitto
cd $WORKDIR  
git clone https://github.com/eclipse/mosquitto.git  
cd mosquitto  
git checkout 2665705  
export AFL_USE_ASAN=1  
CFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer"  CC=afl-gcc make clean all WITH_TLS=no WITH_TLS_PSK:=no WITH_STATIC_LIBRARIES=yes WITH_DOCS=no WITH_CJSON=no WITH_EPOLL:=no  

# (3) Run LEMUR-Fuzz (AFLNet-style command)
cd $WORKDIR/mosquitto
$WORKDIR/lemur-fuzz/afl-fuzz -d -i $LEMUR/tutorials/mosquitto/in-mqtt-v5 -o out-mosquitto-lemur-fuzz -N tcp://127.0.0.1/1883 -t 3000+ -m none -P MQTT -D 10000 -q 3 -s 3 -E -K -R ./src/mosquitto
```


## Environment Variables For Ablation Study

LEMUR-Fuzz exposes three environment variables to selectively enable/disable parts of the mutation pipeline for ablation studies and debugging.

### 1) Disable constraint fixers

```bash
export FIXER_OFF=1
```

When `FIXER_OFF=1`, LEMUR-Fuzz **skips the constraint-fixing stage** after semantic-aware mutation. The generated inputs are still produced via the parser → (semantic-aware) mutator → reassembler pipeline, but cross-field dependencies may no longer be repaired.

Unset it (or set to `0`) to enable fixers:

```bash
unset FIXER_OFF
# or: export FIXER_OFF=0
```

### 2) Disable semantic-aware mutators

```bash
export SEM_OFF=1
```

When `SEM_OFF=1`, LEMUR-Fuzz **skips the semantic-aware field-level mutation stage** (`dispatch_*_multiple_mutations`). The constraint fixer still runs, so inputs go through parser → (skipped mutator) → **fixer** → reassembler. This corresponds to the **LEMUR-Fuzz Fix** ablation variant in the paper's RQ3 (constraint fixers enabled on top of the original AFLNet mutation, without the semantic-aware mutator).

Unset it (or set to `0`) to re-enable semantic-aware mutators:

```bash
unset SEM_OFF
# or: export SEM_OFF=0
```

### 3) Disable AFLNet byte-level mutation (havoc + splicing)

```bash
export HAVOC_OFF=1
```

When `HAVOC_OFF=1`, LEMUR-Fuzz **disables AFLNet’s original structure-agnostic byte-level mutation operators** (havoc and splicing), so fuzzing relies primarily on the semantic-aware mutation stage.

Unset it (or set to `0`) to enable AFLNet’s original mutation operators:

```bash
unset HAVOC_OFF
# or: export HAVOC_OFF=0
```

**Common ablation settings** (mapping to the paper's RQ3 variants)

- **LEMUR-Fuzz (default)**: semantic-aware mutators + constraint fixers + original AFLNet mutation
- **LEMUR-Fuzz Mut** (mutators only): `export FIXER_OFF=1`
- **LEMUR-Fuzz Fix** (fixers only): `export SEM_OFF=1`
- **Base** (≈ AFLNet): `export FIXER_OFF=1` and `export SEM_OFF=1`
- **Semantic-only**: `export HAVOC_OFF=1`

---


## Detailed Experimental Setup

For the 12-implementation evaluation and the availability of its Docker
artifacts, see the [repository reproduction guide](../README.md#reproducible-experiments).
