# avb-meta provenance

Vendored from avb-kit commit `7bcfa096e8d5b2e460896415f490e961340301dd`,
`crates/avb-meta`, Apache-2.0. Local integration changes: rustfmt normalization
and the additive `HashAlg::is_empty` companion to its public `len` method;
upstream tests use lint-clean equivalent expressions and a tuple type alias.
The manifest inherits maos workspace package metadata and uses maos's canonical
`shared/avb-graft` at its existing relative path. avb-kit has no configured remote;
this snapshot is the release input, not a dependency on an adjacent checkout.

Verification is fixed-width in-crate Montgomery RSA (2048/4096/8192 bits);
num-bigint is a dev-only arithmetic oracle, never a firmware dependency.
Profile minting uses `Plan` for chain ordering, key matching and signature
verification, retaining mint's stricter descriptor policy and external payload
verification. `dev/abl-key` uses `AblKeys`.

Refresh by copying that crate from an explicitly reviewed avb-kit revision and
updating this record; retain the upstream no-I/O, no-unsafe layering contract.
