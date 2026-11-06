# Working rules for avb-kit

This repository contains the AOSP AVB format only. Read `README.md` and
`docs/format.md` before a change.

## Boundary

- An item belongs here only when AOSP `external/avb` or `avbtool` defines it.
  Examples: the AVB0 header, the AVBf footer, the descriptor tags, the AVB public
  key blob, the algorithm types and the chain walk.
- Qualcomm stock-ABL conventions belong to abl-kit. Examples: the first embedded
  key as the trust anchor, the fixed SHA-256 VBH value, the `boot` property
  preference.
- Product policy stays with its owner. Examples: `.vbmp` records in maOS, the
  payload substitution rule in ablwrap, the trust decision in ODP.
- A change that adds a convention must name the AOSP source that defines it, or
  it must go to abl-kit.

## Crates

- `avb-format` has no dependencies and no allocation. Keep it that way.
- `avb-verify` has `alloc` and `sha2`. It holds hash helpers, the algorithm
  table and RSA PKCS#1 v1.5 verification.
- `avb-chain` has `alloc`. It verifies metadata only. Never claim payload or
  hashtree verification.
- `avb-graft` has no allocation and no dependencies.
- `avb-image` has `alloc`. It plans writes and does no I/O.
- All libraries are `no_std` and forbid unsafe code.
- Every trust input is explicit. `avb-chain` accepts caller-supplied key blobs
  and never scans a device image for a key.

## Style

- Documentation and commit messages use ASD-STE100 style: short sentences, one
  instruction per sentence, active voice, no semicolons.
- Docs describe the current implementation only.
- Comments that cite an AOSP file use the path under `external/avb`.

## Checks

Run these before a commit:

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo check --target aarch64-unknown-uefi -p avb-format -p avb-verify -p avb-chain -p avb-graft -p avb-image
```

The UEFI target needs `+nightly-2026-11-04` or a stable toolchain that installs
`aarch64-unknown-uefi`.

Commit with `git commit -S`. Use the agent key, not the owner key.

## Tests

- Keep every existing assertion. Adapt a test to a new API, do not weaken it.
- Tests that read a capture outside the repository must skip when the capture is
  absent, and must print `SKIP:` with the path.
- A synthetic fixture must never be described as verified. Only a real OEM
  signature proves verification.
