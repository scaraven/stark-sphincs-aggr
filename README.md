# Post-Quantum Signature Verification with STARKs

STARK-provable verification of post-quantum signatures in Cairo, targeting Bitcoin soft-fork compatibility via [BIP-360](https://bip360.org/).

## Overview

This repository implements signature verification circuits for post-quantum schemes that can be proven with the Stwo STARK prover. The primary use case is batch verification of PQ signatures for Bitcoin transactions, where a single STARK proof attests to the validity of multiple signatures.

**Implemented schemes:**
- **SPHINCS+ Poseidon** — SPHINCS+ with native Poseidon hash for optimal ZK performance
- **SPHINCS+ BTC** — Bitcoin-optimized SPHINCS+ with WOTS+C (hash-based, stateless)
- **SPHINCS+ 128s** - Standard NIST parameter set (hash-based, stateless)
- **Falcon-512** — NIST finalist (lattice-based)

---

## SPHINCS+ Poseidon

A SPHINCS+ variant using **Poseidon** as the underlying hash function. Poseidon is an arithmetic-friendly hash designed specifically for zero-knowledge proof systems, making it extremely efficient within the STARK prover.

### Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| n | 16 | Security parameter (128-bit) |
| h | 63 | Total hypertree height |
| d | 7 | Number of hypertree layers |
| k | 14 | FORS trees |
| a | 12 | FORS tree height |
| w | 16 | Winternitz parameter |

### Why Poseidon?

- **Native field arithmetic** — Poseidon operates directly over the STARK field, eliminating costly bit decomposition
- **Minimal constraints** — Orders of magnitude fewer constraints compared to binary hashes like SHA-256 or Blake2s
- **Optimal for aggregation** — When batching many signature verifications, Poseidon's efficiency compounds

### Architecture

The implementation follows the standard SPHINCS+ structure:

1. **Message hashing** — Computes extended digest containing FORS indices and tree addressing
2. **FORS verification** — Verifies k=14 few-time signature trees of height a=12
3. **Hypertree verification** — Traverses d=7 layers of WOTS+ signatures with Merkle authentication paths

---

## SPHINCS+ BTC

Implementation of the Bitcoin-optimized SPHINCS+ variant from [Blockstream's paper](https://eprint.iacr.org/2025/2203.pdf). This variant reduces signature size through grinding-based optimizations while maintaining 128-bit security.

### Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| n | 16 | Hash output bytes (128-bit security) |
| h | 32 | Total hypertree height |
| d | 4 | Number of hypertree layers |
| k | 10 | FORS trees |
| a | 14 | FORS tree height |
| w | 256 | Winternitz parameter |

### WOTS+C Optimization

Standard WOTS+ requires `len1 + len2` chains where `len2` chains encode the checksum. WOTS+C eliminates checksum chains via signature-time grinding:

1. Signer searches for a counter `c` such that `H(message || c)` has its last τ=2 bytes equal to zero
2. Only `len1 - τ = 14` chains are included in the signature (vs 16+3=19 for standard WOTS+)
3. Counter is included in signature; verifier recomputes `H(message || c)` and checks the constraint

Expected grinding cost: ~65,536 hash evaluations per WOTS signature (4 layers × 2^16).

### Signature Size

| Component | Size |
|-----------|------|
| Randomizer | 16 B |
| FORS (10 trees × 15 nodes × 16 B) | 2,400 B |
| WOTS+C (4 layers × (14 chains + counter + 8 auth) × 16 B) | 1,424 B |
| **Total** | **3,840 B** |

### Hash Function

Uses **Blake2s-256** truncated to 128 bits. Blake2s has native Stwo AIR support, making it significantly more efficient than SHA-256 in the prover.

- **Native Stwo AIR support** — Blake2s has a dedicated algebraic intermediate representation in the Stwo prover, making it ~1000× more efficient than simulated hash functions
- **Performance** — By nature blake2s is more ZK friendly than sha256

SHA-256 exceeds the Stwo memory address limit (2^27) and cannot be proven with current prover constraints.

## Benchmarks

Single signature verification with the Stwo prover:

| Scheme | Cairo Steps | Proof Size | Prove Time |
|--------|-------------|------------|------------|
| SPHINCS+ Poseidon | ~300k | TBD | TBD |
| SPHINCS+ BTC (Blake2s) | ~4.4M | TBD | TBD |
| Falcon-512 | TBD | TBD | TBD |

---

## Project Structure

```
packages/
├── sphincs-core/         # Shared library for all SPHINCS+ packages
│   └── src/
│       ├── address/         # Dense & sparse address encoding
│       └── word_array.cairo # Word array utilities + hex helpers
├── sphincs-poseidon/     # SPHINCS+ with Poseidon hash
│   ├── src/
│   │   ├── sphincs.cairo    # Main verification logic
│   │   ├── wots.cairo       # WOTS+ implementation
│   │   ├── fors.cairo       # FORS tree verification
│   │   ├── hasher/          # Poseidon tweakable hash
│   │   └── params_128s.cairo
│   └── scripts/
│       └── generate_args.py # Python signer for test vectors
├── sphincs-btc/          # Bitcoin-optimized SPHINCS+
│   ├── src/
│   │   ├── sphincs.cairo
│   │   ├── wots_c.cairo     # WOTS+C with grinding
│   │   ├── fors.cairo
│   │   └── hasher/          # Blake2s tweakable hash
│   └── scripts/
└── falcon/               # Falcon-512 verification
```

---

## Prerequisites

- [Scarb](https://docs.swmansion.com/scarb/) — Cairo package manager
- Python 3.8+ — For test vector generation
- Rust nightly — For Stwo prover

---

## Technical Details

### Address Encoding

The address encoding lives in `sphincs-core` and is shared by all SPHINCS+ packages. It uses a 22-byte dense format optimized for Cairo's 32-bit word operations:

```
Bytes 0-7:    layer (1B) + tree_addr (7B)
Bytes 8-9:    type (1B) + padding (1B)
Bytes 10-13:  keypair (2B) + padding (2B)
Bytes 14-21:  tree_height/chain_addr (1B) + tree_index/hash_addr (3B)
```

### Tweakable Hash Construction

Both implementations use a tweakable hash `thash(pk_seed, addr, M)`:

**Poseidon variant:**
```
Poseidon(pk_seed || addr_components || M)
```
Where `addr_components` are 6 field elements encoding the SPHINCS+ address.

**Blake2s variant:**
```
Blake2s(pk_seed || zeros_48 || addr || M)[0:16]
```
The `pk_seed || zeros_48` block is precomputed and reused via state seeding.

### FORS Verification

FORS (Forest of Random Subsets) provides few-time signatures:
- Message hash is split into k indices (12-bit for Poseidon, 14-bit for BTC)
- Each index selects a leaf in its corresponding Merkle tree
- Authentication paths prove membership; all roots are hashed together

### Hypertree Verification

The hypertree chains multiple WOTS+ signatures:
- Each layer signs the root of the layer below
- Bottom layer signs the FORS public key
- Top layer root must match the public key

---

## References

- [BIP-360: Pay to Quantum Resistant Hash](https://bip360.org/)
- [Blockstream SPHINCS+ Bitcoin Proposal](https://eprint.iacr.org/2025/2203.pdf)
- [SPHINCS+ Specification](https://sphincs.org/data/sphincs+-r3.1-specification.pdf)
- [PQ Signatures and Scaling Bitcoin with STARKs](https://delvingbitcoin.org/t/post-quantum-signatures-and-scaling-bitcoin-with-starks/1584)

## License

MIT
