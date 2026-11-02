# A pipeline to generate protocol-specific components with LLM-assistance

LLM-assisted generator for the four protocol-specific components from our paper — message templates, parser/reassembler, semantic-aware mutators, and constraint fixers — generated once per protocol from an RFC (or other specification).

This repo drives an interactive, step-by-step pipeline that:

1. Reads an RFC (PDF or text) and leverages the LLM to reason over specification text;
2. Asks an LLM to generate the four components in C, including extracting cross-field constraints from the spec and generating a fixer for each;
3. Runs the three automated quality checkers (metamorphic checker for parser/reassembler, parseability checker for mutators, constraint-violation checker for fixers);
4. If a check fails, the system reports diagnostics and the issue is resolved by manual fixing; an experimental LLM-based auto-repair is also available.


## Requirements

- Python 3.10+ (recommended)
- A C compiler
- An OpenAI API key (set in `.env` or environment variables)

Python packages used by the pipeline include:

- `click`, `python-dotenv`
- `rich`, `questionary`
- `langchain`, `langchain-core`, `langchain-community`, `langchain-openai`, `langgraph`
- `faiss-cpu` (for the RAG vector store)

## Setup

Create a `.env` file in the repo root:

```bash
OPENAI_API_KEY=...your key...
# OPENAI_BASE_URL=...your base url... if using a custom endpoint
```

Optional environment variables:

- `RAG_CACHE_DIR=/path/to/cache` (default: `.cache/rag`)
- `RAG_DISABLE_CACHE=1` to disable caching

Install dependencies (example):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## Quickstart

MQTT v5.0 example:

```bash
python3 main.py --protocol mqtt --seed-dir tests/seeds/mqtt --rfc-path rfc/mqtt-v5.0.pdf
```

Notes:

- The pipeline is interactive. Before each step it will prompt you to **Continue / Retry previous / Skip / Exit**.
- If you do nothing, it auto-continues after ~60 seconds.
- The RFC(or other spec) can be a `.pdf` or a text file.

## What gets generated

Generated C artifacts go under:

- `llm/<proto>/<proto>_packets.h`       # message templates
- `llm/<proto>/<proto>_packets.c`       # message templates and a print function to output structured data
- `llm/<proto>/<proto>_parser.c`        # a parser to deserialize byte strings to structured data
- `llm/<proto>/<proto>_reassembler.c`   # a reassembler to serialize structured data to byte strings
- `llm/<proto>/<proto>_mutators.c`      # field-level semantic-aware mutators
- `llm/<proto>/<proto>_fixers.c`        # constraint fixers

The pipeline also generates fixer-test files under:

- `tests/fixer_sanity/<proto>_fixer_registry.c`
- `tests/fixer_sanity/<proto>_fixer_sanity_tests.c`

## Running checks manually

The three automated quality checkers from the paper (§III-E) are exposed as the scripts below. They execute test cases until line coverage reaches 100% under the harness or a fixed testing budget is exhausted.

**Metamorphic checker** (parser/reassembler): checks `reassembler(parser(M)) == M`.

```bash
./tests/PR_mr/mr_test.sh mqtt tests/seeds/mqtt
```

**Parseability checker** (mutators): a semantically mutated message must remain parseable.

```bash
./tests/mutator_sanity/run_mutator_sanity.sh mqtt tests/seeds/mqtt
```

**Constraint-violation checker** (fixers): each cross-field constraint is violated and checked for correct repair (compiles and runs `tests/fixer_sanity/<proto>_fixer_sanity_tests.c`).

```bash
./tests/fixer_sanity/run_fixer_sanity.sh mqtt
```

> These checkers cannot formally guarantee the correctness of LLM-generated components, but provide empirically effective, fully-automated quality checking; failures are resolved by lightweight manual fixes.

## Logs and state

- `tool_usage.log`: records tool calls (file reads, RFC search, file writes). It is reset on each run.
- `.pipeline_state.json`: caches pipeline state (e.g., discovered packet types / extracted constraints) so you can resume runs.

## Troubleshooting

- **RAG setup fails**: the pipeline will still run, but RFC grounding will be weaker. Ensure the RFC file exists and dependencies like `faiss-cpu` installed.
- **Compiler not found**: install `gcc`/`clang` and ensure they are on `PATH`.
- **OpenAI auth errors**: verify `OPENAI_API_KEY` is set and reachable from the environment running `python3 main.py`.
