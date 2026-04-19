# idv2

An anonymous, cryptographically verifiable voting system for Nigerian general elections. Built on Solana with Pinocchio, a national-HSM-cluster model for voter secrets, and a Merkle commitment scheme with nullifier-based double-vote prevention.

**Status:** Pre-build. Architecture locked. 26-day solo-developer hackathon build.

## Read first

- [`CONTEXT.md`](./CONTEXT.md) — project state and all locked-in decisions at a glance.
- [`docs/REPORT-v0.1.md`](./docs/REPORT-v0.1.md) — full design narrative in first person, covering the Option A → IDv2 pivot and the engineering deep-dive.
- [`docs/PROJECT-PLAN.md`](./docs/PROJECT-PLAN.md) — 4-layer build plan with account layouts, milestones, dependencies, and risks.
- [`docs/TIMELINE.md`](./docs/TIMELINE.md) — 26-day timeline with hard gates.
- [`docs/NOTES.md`](./docs/NOTES.md) — running decisions log.

## Repository layout

```
idv2/
├── CONTEXT.md              Single source of truth on current project state
├── README.md               This file
├── docs/                   Design docs (read in the order above)
└── rust-workspace/         Cargo workspace — see rust-workspace/README.md
    ├── programs/           Four Pinocchio programs
    ├── enclave/            SoftHSM2 + PKCS#11 wrapper, WOTS, counter
    ├── clients/            Registration + tally verifier CLIs
    ├── dashboard/          Aggregation server
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
