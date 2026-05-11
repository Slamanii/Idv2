# idv2

An anonymous, cryptographically verifiable voting system for Democratic elections. Built on Solana with Pinocchio, a national-HSM-cluster model for voter secrets, and a Merkle commitment scheme with nullifier-based double-vote prevention.

**Status:** Pre-build. Architecture locked. 26-day solo-developer hackathon build.

## Read first

- (./docs/Document 3.pdf) — A philosophical overview of the decisons made predesign and post deployment.
- (./docs/IDv2_essay.docx) — full design narrative, covering the IDv1 → IDv2 pivot and the engineering deep-dive.


## Repository layout

```
idv2/
├── README.md               This file
├── docs/                   Design docs (read in the order above)
└── rust-workspace/         Cargo workspace — see rust-workspace/README.md
    ├── programs/           Four Pinocchio programs
    ├── enclave/            SoftHSM2 + PKCS#11 wrapper, WOTS, counter
    ├── clients/            Registration + tally verifier CLIs
    ├── dashboard/          Aggregation server
    ├── smt/                SMT server
    └── tests/              End-to-end test harness
```

## Build

```sh
cd rust-workspace
cargo build --workspace
```

The Pinocchio programs build with `cargo build-sbf` for deployment to Solana. Standard `cargo build` is for local development of clients, the enclave wrapper, and tests.

## License

TBD — not yet selected. All rights reserved until explicit license is added.
