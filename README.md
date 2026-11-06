# avb-kit

Reusable Rust code for the AOSP AVB format. This repository keeps only what
AOSP `external/avb` and `avbtool` define. Qualcomm stock-ABL conventions live in
[`abl-kit`](../abl-kit).

License: Apache-2.0. Every library is `no_std`. Only the CLI uses `std`.

## Crates

| Crate | Runtime | Dependencies | Purpose |
|---|---|---|---|
| `avb-format` | `no_std`, no allocation | none | `AVB0` header, typed descriptors and iteration, `AVBf` footer parse and serialize, structural validation, exact metadata extent, footer extraction, AVB RSA public key blob parse and validation |
| `avb-verify` | `no_std` + `alloc` | `sha2`, `avb-format` | SHA-256 and SHA-512 helpers, the AVB algorithm table, RSA PKCS#1 v1.5 verification from an AVB key blob |
| `avb-chain` | `no_std` + `alloc` | `avb-format`, `avb-verify` | Chain plan: caller-supplied trusted keys, needs, supply, verdicts, metadata digests, properties |
| `avb-graft` | `no_std`, no allocation | `avb-format` | Graft plan and read overlay for a metadata and footer replacement |
| `avb-image` | `no_std` + `alloc` | `avb-graft` | Metadata placement, write plans, Android boot and DTBO payload extents |
| `tools/avbkit` | `std` | the crates above | Host CLI |

## Tool

```
avbkit inspect <image>
avbkit extract <image> [--out <file>]
avbkit verify-chain --key <blob> <root> [NAME=]image...
avbkit graft <image> --metadata <file> --out <file>
avbkit place --image <file> --metadata <file> --placement <keep|tail|at:OFFSET> --out <file>
```

`verify-chain` trusts only the keys given with `--key`. It does not scan an ABL
image and does not select a first key. `place --extent` takes `footer`, `zero`,
`boot`, `dtbo` or `known:END`.

The tool reads and writes files that the caller names. It does not open a block
device and does not sign an image.

## What the code checks

- Structural: header, footer, descriptor framing, block alignment, key blob
  arithmetic.
- Metadata signature: each vbmeta image against its embedded key, and a chained
  image against the key its parent demands.
- Nothing else. Payload and hashtree verification is `avbtool verify_image`.

See `docs/evidence.md` for the exact boundary.

## Out of scope

- Qualcomm stock-ABL conventions: first-key anchor, fixed SHA-256 VBH, `boot`
  property preference. These are in `abl-kit`.
- `.vbmp` records: maOS owns the product record format.
- ablwrap `resolve`, `avbview` and `pack`: wrapper policy and packaging stay in
  ablwrap.
- ODP trust policy and the `SET_VBH` reconstruction: ODP owns its platform
  decision.
- Signing, image creation and device I/O.

## Checks

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo check --target aarch64-unknown-uefi -p avb-format -p avb-verify -p avb-chain -p avb-graft -p avb-image
```

Tests that need a capture outside this repository print `SKIP:` and pass when
the capture is absent.
