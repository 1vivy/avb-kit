# AVB wire format

This document records the AOSP AVB format that the avb-kit crates implement. The
source of truth is AOSP `external/avb`. File and line references below name that
tree at `c5066a96caa7bf4150c0a8cc8cc14ab81733fdc7`, the revision that the maOS GBL
workspace pins.

The crates parse, validate and verify the format. They do not sign images and do
not write Android images.

## AVB0 vbmeta image

A vbmeta image starts with a 256-byte header. All integers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `AVB0` |
| 4 | 4 | `required_libavb_version_major` |
| 8 | 4 | `required_libavb_version_minor` |
| 12 | 8 | `authentication_data_block_size` |
| 20 | 8 | `auxiliary_data_block_size` |
| 28 | 4 | `algorithm_type` |
| 32 | 8 | `hash_offset` |
| 40 | 8 | `hash_size` |
| 48 | 8 | `signature_offset` |
| 56 | 8 | `signature_size` |
| 64 | 8 | `public_key_offset` |
| 72 | 8 | `public_key_size` |
| 80 | 8 | `public_key_metadata_offset` |
| 88 | 8 | `public_key_metadata_size` |
| 96 | 8 | `descriptors_offset` |
| 104 | 8 | `descriptors_size` |
| 112 | 8 | `rollback_index` |
| 120 | 4 | `flags` |
| 124 | 4 | `rollback_index_location` |
| 128 | 48 | `release_string` |
| 176 | 80 | Reserved, must be zero |

Source: `libavb/avb_vbmeta_image.h`.

The header is followed by the authentication block and the auxiliary block. Both
block sizes are multiples of 64 bytes. The hash, signature and public key offsets
are relative to the start of the authentication block. The descriptor offset is
relative to the start of the auxiliary block.

The exact metadata extent is `256 + authentication_data_block_size +
auxiliary_data_block_size`. Padding after that extent belongs to the partition,
not to the metadata.

Header rules that this repository checks:

- the magic is `AVB0`;
- both block sizes are 64-byte aligned;
- every offset and size pair stays inside its block;
- the reserved bytes are zero;
- `release_string` holds a NUL byte, and the bytes after that NUL are zero;
- the descriptor window is exactly consumed by aligned descriptors.

Flags:

- bit 0 (`VBMETA_FLAG_HASHTREE_DISABLED`) disables dm-verity;
- bit 1 (`VBMETA_FLAG_VERIFICATION_DISABLED`) makes libavb skip descriptor
  parsing and emit no `androidboot.vbmeta.*` properties.

## AVBf footer

A footered partition ends with a 64-byte footer. All integers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `AVBf` |
| 4 | 4 | `version_major` |
| 8 | 4 | `version_minor` |
| 12 | 8 | `original_image_size` |
| 20 | 8 | `vbmeta_offset` |
| 28 | 8 | `vbmeta_size` |
| 36 | 28 | Reserved, must be zero |

Source: `libavb/avb_footer.h`. The current format version is 1.0.

`original_image_size` is the payload length, which excludes the metadata and the
footer. The footer is valid only when `original_image_size <= vbmeta_offset` and
the metadata ends at or before the footer.

## Descriptors

Descriptors fill the descriptor window in order. Each descriptor starts with an
8-byte aligned header.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Tag |
| 8 | 8 | `num_bytes_following` |

The body starts at offset 16. The body length includes the body padding. The next
descriptor starts at the first 8-byte boundary after the body.

Source: `libavb/avb_descriptor.h`.

| Tag | Descriptor | Source file |
|---|---|---|
| 0 | Property | `avb_property_descriptor.h` |
| 1 | Hashtree | `avb_hashtree_descriptor.h` |
| 2 | Hash | `avb_hash_descriptor.h` |
| 3 | Kernel command line | `avb_kernel_cmdline_descriptor.h` |
| 4 | Chain partition | `avb_chain_partition_descriptor.h` |

This repository models the property, hash, hashtree and chain-partition
descriptors. It skips unknown tags without failing.

### Chain partition descriptor

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `rollback_index_location` |
| 4 | 4 | `partition_name_len` |
| 8 | 4 | `public_key_len` |
| 12 | `partition_name_len` | Partition name, UTF-8 |
| ... | `public_key_len` | AVB public key blob |

The partition name has no `_a`/`_b` suffix. The key blob uses the layout in the
next section.

### Hash descriptor

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `image_size` |
| 8 | 32 | `hash_algorithm` |
| 40 | 4 | `partition_name_len` |
| 44 | 4 | `salt_len` |
| 48 | 4 | `digest_len` |
| 52 | 4 | `flags` |
| 56 | 60 | Reserved |
| 116 | ... | Partition name, salt, digest |

### Hashtree descriptor

The hashtree descriptor holds the dm-verity geometry: block size, tree offset,
tree size, data block count, hash block count, the FEC numbers, the hash
algorithm, the root digest, the salt and the partition name. Source:
`avb_hashtree_descriptor.h`.

### Property descriptor

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `key_len` |
| 8 | 8 | `value_len` |
| 16 | `key_len` | Key |
| ... | `value_len` | Value |

The body is padded to an 8-byte boundary.

### Kernel command line descriptor

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `flags` |
| 4 | 4 | `cmdline_len` |
| 8 | `cmdline_len` | Command line |
| ... | 1 | NUL terminator |

## AVB public key blob

A vbmeta image and a chain descriptor carry a public key as an
`AvbRSAPublicKeyHeader` prefix followed by two big-endian integers.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `key_num_bits` |
| 4 | 4 | `n0inv` |
| 8 | `key_num_bits / 8` | `n`, the modulus |
| ... | `key_num_bits / 8` | `rr`, the value `2^(2 * key_num_bits) mod n` |

Source: `libavb/avb_rsa.h`. Format 1.0 supports 2048, 4096 and 8192-bit keys.
`avbtool extract_public_key` writes this exact blob.

A valid blob satisfies these rules:

- `key_num_bits` is one of 2048, 4096 or 8192;
- the modulus is odd and its top bit is set;
- `n0inv` equals `-1 / n[0] mod 2^32`;
- `rr` equals `2^(2 * key_num_bits) mod n`.

`avb-format` checks these rules with integer arithmetic only.

## Algorithm types

| Value | Algorithm |
|---|---|
| 0 | NONE |
| 1 | SHA-256 with RSA-2048 |
| 2 | SHA-256 with RSA-4096 |
| 3 | SHA-256 with RSA-8192 |
| 4 | SHA-512 with RSA-2048 |
| 5 | SHA-512 with RSA-4096 |
| 6 | SHA-512 with RSA-8192 |
| 7 | ML-DSA-65 |
| 8 | ML-DSA-87 |

Source: `libavb/avb_vbmeta_image.h`. `avb-verify` verifies values 1 to 6. It
parses values 7 and 8 and reports that it cannot verify them.

## Signature and hash layout

The authentication block holds the hash, the signature and the public key. For
the RSA types, the signed data is the header together with the auxiliary block.
The hash of that data is stored in the authentication block. The signature is
PKCS#1 v1.5 over the decoded DigestInfo structure for the hash.

Source: `libavb/avb_vbmeta_image.c`, function `avb_vbmeta_image_verify`.

## Chain walk

libavb appends a vbmeta image to its image list before it reads that image's
descriptors. It recurses into each chain-partition descriptor in descriptor
order. The list is therefore a depth-first pre-order traversal.

Two digests use that order:

- the Qualcomm ABL VBH is SHA-256 over the ordered set;
- `androidboot.vbmeta.digest` uses the root's algorithm, as
  `avb_append_options()` selects it in `libavb/avb_cmdline.c`.

`avb-chain` records the order and computes both digests on request. The ordered
set is the exact metadata extent of each image, with no partition padding.

## What each crate checks

| Check | Crate |
|---|---|
| Header, footer, descriptor framing | `avb-format`, `avb-graft` |
| AVB public key blob structure | `avb-format` |
| Metadata signature against one key | `avb-verify` |
| Chain key match, order and digests | `avb-chain` |
| Payload and hashtree verification | Not in this repository. `avbtool verify_image` owns it. |

`avb-chain` verifies metadata only. A verified plan does not prove that a payload
matches its hash or hashtree descriptor.
