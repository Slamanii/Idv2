# idv2 — Rust Workspace

Scaffolded on 2026-04-18. All crates compile as empty stubs. Each layer gets filled in according to `../docs/TIMELINE.md`.

## Layout

```
rust-workspace/
├── programs/                 Pinocchio programs deployed to Solana
│   ├── election_registry/    ElectionAccount, root publishing
│   ├── voter_registry/       Sparse Merkle tree state
│   ├── ballot/               Vote verification (hot path)
│   └── tally/                Final on-chain tally
├── clients/                  CLI clients (registration, tally verifier)
├── enclave/                  SoftHSM2 + PKCS#11 wrapper, WOTS signing, monotonic counter
├── dashboard/                Aggregation server + WebSocket broadcast
└── tests/                    End-to-end test harness (100 voters / 3 candidates)
```

## Build

```sh
cargo build --workspace
```

The first `cargo build` will pull a lot of dependencies; expect a few minutes.
