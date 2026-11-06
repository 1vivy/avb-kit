# Provenance

## Imported history

This repository started from three source histories. Each import used
`git filter-repo` on a temporary clone. The source checkouts were not modified.

| Source | Source path | Destination at import |
|---|---|---|
| maOS `main` | `shared/avb-meta/` | `crates/avb-meta/` |
| maOS `main` | `shared/avb-graft/` | `crates/avb-graft/` |
| ablwrap `main` | `crates/avb-image/` | `crates/avb-image/` |

The maOS import ended at `3a92f93e` and the ablwrap import at `7b5ad6f`. The
imports were merged with `--allow-unrelated-histories` in commit `d8b5257`.
Authorship is preserved. Every rewritten commit lost its signature, which is
expected for a rewritten history.

## Split

The imported `avb-meta` crate is not part of this repository. Later commits
split it. Each item moved to the crate that owns its behavior.

| Imported item | New owner |
|---|---|
| `avb-graft::{validate_vbmeta, Vbmeta, Error}`, footer parse and serialize, header read | `avb-format` |
| `avb-meta::meta::{Header, Descriptor, descriptors, inspect, exact_metadata, vbmeta_entry, Defect}` | `avb-format` |
| `avb-meta::rsa::{AvbRSAPublicKeyHeader checks, key_blob_len, key_num_bits, n0inv, rr}` | `avb-format` |
| `avb-meta::{sha256, sha512, sha256_concat, sha512_concat, HashAlg}` | `avb-verify` |
| `avb-meta::rsa::rsa_pkcs1_verify` and the in-crate Montgomery arithmetic | `avb-verify` |
| `avb-meta::plan::{Plan, Verdict, Need, Accepted, Rejected, VbmetaDigest, CmdlineDigest, extract_vbmd}` | `avb-chain` |
| `avb-graft::{Graft, plan_graft, replacement_footer, ReadError}` | `avb-graft` |
| `patina_qcom_oem::avb::{Color, AvbDigest, VerificationReport}` | `avb-format` (ODP `main`; the values follow KeyMint `VerifiedBootState` and `libavb/avb_vbmeta_image.h`) |
| `avb-meta::api` | Dropped. The owner approved the removal. It had no consumer. |

The original RSA verification is in-crate fixed-width Montgomery arithmetic. It
has no private input and only the exponent 65537. `num-bigint` remains a test
oracle only.

## Conventions moved out of `avb-meta`

`avb-meta` contained Qualcomm stock-ABL conventions next to the AOSP format.
Each item below moved to `abl-kit`, or stayed with its owner, because AOSP
`external/avb` does not define it.

| Removed item | Why it left | New owner |
|---|---|---|
| `AblKey`, `AblKeys`, `abl_keys`, first-key `anchor()` | A key scan of an ABL image and the first-key rule are stock-ABL conventions | `abl-keys` |
| `Plan::anchored`, `Plan::anchored_with_extra`, `Verdict::Malformed(NoAnchorKey)`, trust-anchor accessors | The trust key is a caller input in libavb. The first-key rule is the ABL's | `abl-keys` (`AblPlan`) |
| `Verdict::WrongPartition` and the `vbmeta_<group>` coverage rule | This is avbtool group convention and a caller policy, not a libavb check | `abl-keys` (`identity_ok`) |
| `Properties` boot-first selection and `properties_source` | Property preference is an ABL product convention | `abl-keys` (`Properties`) |
| `Plan::authority_sha512` | The DICE authority digest over visited keys is a platform policy | `abl-keys` (`AblPlan::authority_sha512`) |
| `Plan::vbmeta_digest()` as a fixed SHA-256 VBH | The label and the hash choice are Qualcomm `SET_VBH` conventions | `abl-keys` (`AblPlan::vbmeta_digest`) |
| Recursion into chain descriptors found in a chained image | libavb rejects that case (`avb_slot_verify.c`). The generic walk now follows libavb | `avb-chain` (`Defect::ChainInChainedImage`) |

`avb-chain` keeps the raw evidence: `covered()`, `supplied_info()`,
`root_properties()`, `image_properties()`, `vbmeta_digest_with()`. A caller
applies its own policy to that evidence.

## Format sources

The wire format comes from AOSP `external/avb` at
`c5066a96caa7bf4150c0a8cc8cc14ab81733fdc7`:

- `libavb/avb_vbmeta_image.h`, `avb_vbmeta_image.c`;
- `libavb/avb_footer.h`;
- `libavb/avb_descriptor.h` and the five descriptor headers;
- `libavb/avb_rsa.h`, `avb_rsa.c`;
- `libavb/avb_slot_verify.c`, `avb_cmdline.c`;
- `avbtool.py`.

`crates/avb-graft` came from an earlier graft implementation. Its
`PROVENANCE.md` keeps the source hashes of that implementation.

`crates/avb-chain/tests/fixtures/aosp/` holds two files from the Apache-2.0 AOSP
`bootable/libbootloader` testdata: a SHA-512-signed root and its recorded
digest. The test uses them as a copy inside this repository.

## License

Every crate in this repository declares Apache-2.0. The imported maOS crates
were Apache-2.0. `ablwrap` declares Apache-2.0 at the workspace level and the
imported `avb-image` crate came from that workspace.
