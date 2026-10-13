# avb-meta provenance

Vendored from avb-kit commit `d2ecec584f11c675cb8aff67fccba9ad05960da0`,
`crates/avb-meta`, Apache-2.0. Local integration changes: rustfmt normalization
and the additive `HashAlg::is_empty` companion to its public `len` method;
upstream tests use lint-clean equivalent expressions and a tuple type alias.
The manifest inherits maos workspace package metadata and uses maos's canonical
`shared/avb-graft` at its existing relative path. avb-kit has no configured remote;
this snapshot is the release input, not a dependency on an adjacent checkout.

Refresh by copying that crate from an explicitly reviewed avb-kit revision and
updating this record; retain the upstream no-I/O, no-unsafe layering contract.
