# What a result proves

Three different checks are easy to confuse. This document separates them.

## 1. Structural check

Owner: `avb-format::validate_vbmeta`, `avb-format::parse_footer`,
`avb-format::validate_key_blob`.

A structural check reads bytes and rejects impossible geometry. It checks the
magic, the version, the 64-byte block alignment and every offset and size pair.
It checks the descriptor strides and the zero padding. It checks the key blob's
length, modulus shape, `n0inv` and `rr`.

A structural success proves that the bytes can be read without a bounds error.
It proves nothing about who made them.

## 2. Metadata signature check

Owner: `avb-verify::rsa_pkcs1_verify`, reached through `avb-chain`.

The signature check takes one key blob that the caller trusts. It hashes the
header and the auxiliary block with the image's own algorithm. It raises the
signature to the public exponent 65537 modulo the modulus, and it compares the
result with the PKCS#1 v1.5 encoding for that hash.

A signature success proves that the holder of the private key made this
metadata. It does not prove what the metadata covers.

`avb-chain` adds the chain rules. A chained image must verify against the key
its parent's chain descriptor demands. The keys must match byte for byte. The
visit order must contain each demanded image once.

`Plan` accepts only caller-supplied trusted keys. It has no key discovery and no
anchor selection. A caller that scans a device image for a key makes its own
trust decision.

## 3. Payload and hashtree check

Owner: `avbtool verify_image`. Not in this repository.

A vbmeta image contains hash and hashtree descriptors for other partitions. A
metadata signature covers those descriptors. It does not cover the bytes of the
images that the descriptors name.

A complete plan therefore does not prove that `boot` or `system` holds the
expected payload. Only a payload check does. `avbtool verify_image` performs it,
and the maOS profile mint calls it explicitly for this reason.

## Reported values

`Plan::vbmeta_digest_with(HashAlg)` returns a digest over the ordered exact
metadata extents. The caller chooses the hash. A caller that needs the stock
Qualcomm VBH value computes SHA-256 over that order and applies its own
convention. `Plan::libavb_cmdline_digest()` returns what libavb writes to
`androidboot.vbmeta.*`, and returns nothing when the root disables verification.

Neither digest is a signature. Each proves the order and the bytes that the
caller already verified.

## Test evidence

The test suite uses two kinds of input.

- Real OEM captures prove the cryptographic path. These files live outside this
  repository. A test prints `SKIP:` and passes when a capture is absent.
- Synthetic fixtures prove the walk shape, the order and the refusals. They are
  unsigned by construction. A synthetic fixture never counts as signature
  evidence.
