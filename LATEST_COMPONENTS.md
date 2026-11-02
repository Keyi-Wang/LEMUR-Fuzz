# Unified Lemur-Fuzz component tree

As packaged on 2026-11-02, the four protocol directories below are also
mirrored under `components-generation/llm/` with byte-identical C and header
files. `COMPONENT_SHA256SUMS.txt` records the 30 canonical source files.
The four-protocol Docker image and experiment package is distributed
separately. It builds LEMUR-Fuzz from these same sources inside each image.

The canonical integrated repository is:

`lemur-fuzz/`

All four protocol implementations are kept together under `llm/`:

- `llm/dns/`: DNS parser, reassembler, mutators, fixers, packet model
- `llm/ssh/`: SSH parser, reassembler, mutators, fixers, packet model
- `llm/tls/`: TLS parser, reassembler, mutators, fixers, packet model
- `llm/dicom/`: DICOM parser, reassembler, mutators, fixers, packet model

The current integrated tree combines the latest available protocol work:

- DNS and TLS structural components from the TLS semantic-fix integration.
- SSH structural components from the SSH quality-fix integration, with the later richer-value mutator set.
- DICOM parser/reassembler from the common RFC corpus work, the later dataset/command/association mutators, and the newest cross-association/length/UID fixer pass.
- The common dispatcher and build files are those in the same `lemur-fuzz` tree, so the four protocols use one consistent dispatcher/build target.

Use this tree as the source for new images. Older directories such as `tlssemfix*`, `sshgex*`, `dicomvalid*`, `dicomcmdfields*`, and `dicomassoc*` are historical snapshots, not separate canonical repositories.
