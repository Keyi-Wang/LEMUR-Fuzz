# LEMUR-Fuzz Artifact

LEMUR-Fuzz extends AFLNet with **LLM-generated, semantic-aware, protocol-specific components** (message templates, parser/reassembler, semantic-aware mutators, constraint fixers), inserting one new stage:

```
parse seed → semantic-aware field-level mutate → constraint fix → reassemble → send to server
```

> **For Reproduction:** the 12-implementation evaluation uses pre-built Docker images and RQ scripts distributed separately from this source repository; see [Reproducible experiments](#reproducible-experiments).

---

## Repository layout

| Path | What | Details |
|------|------|---------|
| `lemur-fuzz/` | LEMUR-Fuzz fuzzer (AFLNet + semantic-aware mutation stage) | [`lemur-fuzz/README.md`](lemur-fuzz/README.md) |
| `components-generation/` | Pipeline to generate & check the LLM-generated components | [`components-generation/README.md`](components-generation/README.md) |
| 12-implementation reproduction (external) | Pre-built images + RQ/analysis scripts | [Docker artifacts](#docker-artifacts) |

This checkout covers 12 implementations of 10 protocols: MQTT (Mosquitto,
NanoMQ), RTSP (live555), SIP (Kamailio), FTP (ProFTPD, Pure-FTPd), SMTP
(Exim), DTLS 1.2 (TinyDTLS), DNS (dnsmasq), DICOM (DCMTK), TLS (OpenSSL), and
SSH (OpenSSH). Source components for all 12 implementations are included here.
Their Docker images and experiment scripts are distributed separately from
this source repository. The existing Zenodo bundles cover the implementations
listed below; the DNSmasq, DCMTK, OpenSSL, and OpenSSH images will be provided
as separate archives.

```text
lemur-fuzz-artifacts/
├── README.md                          # this file
├── lemur-fuzz/                        # → §1 LEMUR-Fuzz 
└── components-generation/             # → §2 Component generation 
```


---

## Reproducible experiments

The 12-implementation evaluation uses pre-built Docker environments rather
than requiring targets to be rebuilt. The linked Zenodo record currently
contains the image bundles and scripts listed below. Separate archives for
DNSmasq, DCMTK, OpenSSL, and OpenSSH will complete the 12-implementation
reproduction package.

The package includes: (1) README, (2) Two pre-built Docker image archive bundles containing all environments required to reproduce the experiments in the paper, including the targets, fuzzers, harnesses, and dependencies: **`Docker_Images_1.zip`** for `NanoMQ`, `ProFTPD`, `Pure-FTPd`, and `TinyDTLS`; and **`Docker_Images_2.zip`** for `Exim`, `Kamailio`, `Live555`, and `Mosquitto`, (3) `Execution_Scripts.tar.gz` (launch containers, run fuzzing, export `.tar.gz` artifacts), (4) `Analysis_Scripts.tar.gz` (regenerate plots/tables).

We evaluate 4 RQs; RQ1 has two endpoints (coverage + crashes), so there are 5 scripts: `RQ1_Coverage.sh`, `RQ1_Crash.sh` (RQ1); `RQ2_Venn_Diagram.sh` (RQ2 Design Choice); `RQ3_Ablation_Studies.sh` (RQ3 Ablation); `RQ4_Success_Ratio.sh` (RQ4 Message Validity).

The workflow has two parts: **Run Experiments** (`run_experiments`): launch containers, run fuzzing, export `.tar.gz`; **Output Analysis** (`output_analysis`): extract results from each `.tar.gz` and compute/plot the paper's figures and tables.

### Docker artifacts
- [Existing image bundles and scripts](https://zenodo.org/records/18375204)
- DNSmasq, DCMTK, OpenSSL, and OpenSSH image archives: to be provided separately.

### Preparation
- Docker installed and running.
- At least 100 GB of storage.
- All experiment images already loaded locally (e.g., `lemur-fuzz-artifact-<protocol>`).

### Part 0 — Load the images
The provided Docker images must be loaded into Docker before running any experiments:
```bash
docker load -i lemur-fuzz-artifact-[protocol].tar
```

### Part 1 — Run Experiments (`run_experiments`)

**Common arguments** (each script takes some subset of):
- `fuzzers`: comma-separated fuzzers or `all` (e.g., `aflnet,lemur-fuzz,chatafl`)
- `protocols`: comma-separated protocols or `all` (e.g., `Exim,Live555`)
- `containers_count`: repeated runs per configuration (e.g., `10`)
- `timeout`: per-run timeout in seconds (e.g., `3600`)
- `outdir`: host directory to store results (e.g., `./out`)
- `skipcount`: integer passed through for coverage scripts
- `apikey`: only required if `chatafl` is selected in RQ1

**Output naming** — each run produces a tarball like `RQ1_Coverage_<Fuzzer>_<Protocol>_<RunID>.tar.gz`, `RQ1_Crash_...`, `RQ2_...`, `RQ3_...`, `RQ4_...`.

#### RQ1 — Coverage (`RQ1_Coverage.sh`)
Collects branch coverage results. Supported fuzzers: `aflnet`, `lemur-fuzz`, `chatafl` *(requires apikey)*, `all`.
```bash
./RQ1_Coverage.sh <fuzzers> <protocols> <containers_count> <timeout> <outdir> <skipcount> [apikey]

# Run all fuzzers on all protocols, 10 runs each, 1 hour
./RQ1_Coverage.sh all all 10 3600 ./RQ1_Cov_Out 1 YOUR_API_KEY
# Only aflnet + lemur-fuzz on Exim and Live555, 3 runs each, 20 minutes
./RQ1_Coverage.sh aflnet,lemur-fuzz Exim,Live555 3 1200 ./RQ1_Cov_Out 1
```

#### RQ1 — Crash (`RQ1_Crash.sh`)
Collects crash results. Supported fuzzers: `aflnet`, `lemur-fuzz`, `chatafl` *(requires apikey)*, `all`.
```bash
./RQ1_Crash.sh <fuzzers> <protocols> <containers_count> <timeout> <outdir> <skipcount> [apikey]

# Crash experiments with all supported fuzzers
./RQ1_Crash.sh all all 10 3600 ./RQ1_Crash_Out 1 YOUR_API_KEY
# Only lemur-fuzz crash on Exim, 5 runs
./RQ1_Crash.sh lemur-fuzz Exim 5 3600 ./RQ1_Crash_Out 1
```

#### RQ2 — Design Choice (`RQ2_Venn_Diagram.sh`)
Collects branch-coverage sets per fuzzer for computing overlap (Venn diagram); each run stores the covered branches into `branch.info`. Supported fuzzers: `aflnet`, `lemur-fuzz`, `semantic-only` *(lemur-fuzz without AFLNet's original mutation stage)*, `all`.
```bash
./RQ2_Venn_Diagram.sh <fuzzers> <protocols> <containers_count> <timeout> <outdir> <skipcount>

./RQ2_Venn_Diagram.sh all all 10 3600 ./RQ2_Out 1
```

#### RQ3 — Ablation Study (`RQ3_Ablation_Studies.sh`)
Evaluates ablations of LEMUR-Fuzz. Supported fuzzers: `aflnet`, `lemur-fuzz`, `lemur-fuzz-nofixer`, `all`.
```bash
./RQ3_Ablation_Studies.sh <fuzzers> <protocols> <containers_count> <timeout> <outdir> <skipcount>

./RQ3_Ablation_Studies.sh all all 10 3600 ./RQ3_Out 1
```

#### RQ4 — Message Validity (`RQ4_Success_Ratio.sh`)
Measures valid-execution / success rate; key results stored under `plot_data` in each tarball. Supported fuzzers: `aflnet-success` *(modified aflnet for measuring message validity)*, `lemur-fuzz`, `all`.
```bash
./RQ4_Success_Ratio.sh <fuzzers> <protocols> <containers_count> <timeout> <outdir> <skipcount>

./RQ4_Success_Ratio.sh all all 10 3600 ./RQ4_Out 1
```

### Part 2 — Output Analysis (`output_analysis`)
All experiment outputs are stored as `.tar.gz` under `outdir`. Given `outdir=./out`:
```text
./{RQX}_Out/
├── Protocol1/
│   ├── Fuzzer1/
│   │   ├── {RQX}_{Fuzzer}_{Protocol}_{RunID}.tar.gz
│   ├── Fuzzer2/
│   └── ...
└── ...
```
where `{RQX}` is one of `RQ1_Coverage`, `RQ1_Crash`, `RQ2`, `RQ3`, `RQ4` and `{RunID}` is a 1-based run index (`1..containers_count`).

**RQ1 Coverage** — `./RQ1_Coverage_Analysis.sh /path/to/RQ1_Cov_Out --step_h 0.005` (second arg = sampling step in hours) → `/{Protocol}/branch_abs_over_time.png`.

**RQ1 Crash** — unique crashes are stored under `<tar-root>/crash_first_seen/` (`logs/`, `crash_timing.csv/.json`, `report.txt/.json/.csv`).

**RQ2 Design Choice** — `./RQ2_Venn_Diagram_Analysis.sh /path/to/RQ2_Out` → `/{Protocol}/{Protocol}_venn_diagram_striking_lemur.pdf`.

**RQ3 Ablation** — same coverage-style reporting as RQ1; `cov_over_time.csv` inside each tarball records branch coverage over time.

**RQ4 Message Validity** — `./RQ4_Success_Rate_Analysis.sh /path/to/RQ4_Out --dt 0.01` → `/{Protocol}/{Protocol}_exec_succ_ratio.pdf`.

### Notes / Tips
- **Debugging failed copies**: if `docker cp` fails, the script prints an error and keeps the container for debugging. Inspect logs with `docker logs <container_name>`.

---

## 1. LEMUR-Fuzz (`lemur-fuzz/`)

### Key properties
- **AFLNet-compatible** — follows AFLNet's build/run style; existing AFLNet scripts need only minimal changes.
- **Semantic-aware field-level mutators** — unlike *type-aware* mutators (e.g., Peach/Boofuzz, which mutate by generic field type — boundary values for integers, length/content for strings, raw-byte flips for byte-arrays), LEMUR-Fuzz's mutators are generated from protocol-specific field semantics in RFCs and produce meaningful values for protocol-specific fields (e.g., MQTT identifiers/topics), which type-aware mutation cannot achieve.
- **Generate-once, reuse-while-fuzzing** — components are generated once per protocol; fuzzing makes **no online LLM calls**.
- **Constraint-aware repair** — fixers repair cross-field constraints after mutation to improve acceptance and deeper execution.

### Ablation controls
| Variable | Effect |
|----------|--------|
| `SEM_OFF=1`   | Disable the semantic-aware field-level mutators (RQ3 "LEMUR-Fuzz Fix" — fixer-only variant). |
| `FIXER_OFF=1` | Disable constraint fixing after semantic mutation (RQ3 "LEMUR-Fuzz Mut" — mutator-only variant). |
| `HAVOC_OFF=1` | Disable AFLNet's byte-level havoc/splicing (semantic-only mode). |

Build guidance and an example command (Mosquitto/MQTT) are in [`lemur-fuzz/README.md`](lemur-fuzz/README.md).

---

## 2. Component generation (`components-generation/`)

Generates the four LLM-generated protocol-specific components once per protocol, plus automated quality checking.

| Component | Role |
|-----------|------|
| Message templates | Specify message structures and field semantics. |
| Parser / reassembler | Bytes ↔ structured messages. |
| Semantic-aware mutators | Field-level mutation respecting semantics (e.g., UTF-8). |
| Constraint fixers | Repair cross-field-constraint violations after mutation. |

### Quality checking
| Component | Checker |
|-----------|---------|
| Message templates | Manual checking against the spec. |
| Parser / reassembler | Metamorphic: `reassembler(parser(M)) == M`. |
| Mutators | Parseability: a semantically mutated message stays parseable. |
| Fixers | Constraint-violation: each constraint is violated and checked for correct repair. |

Run via `tests/`:
```bash
./tests/PR_mr/mr_test.sh <proto> <seed_dir>
./tests/mutator_sanity/run_mutator_sanity.sh <proto> <seed_dir>
./tests/fixer_sanity/run_fixer_sanity.sh <proto>
```

Checkers cannot guarantee correctness but provide empirically effective, fully-automated quality checking; failures are resolved by lightweight manual fixes. Environment setup and interactive usage are in [`components-generation/README.md`](components-generation/README.md).

