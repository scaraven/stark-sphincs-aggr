# Post-Quantum Signature Verification with STARKs

STARK-provable verification of post-quantum signatures in Cairo, targeting Bitcoin soft-fork compatibility via [BIP-360](https://bip360.org/).

## Overview

This repository implements signature verification circuits for post-quantum schemes that can be proven with the Stwo STARK prover. The primary use case is batch verification of PQ signatures for Bitcoin transactions, where a single STARK proof attests to the validity of multiple signatures.

**Implemented schemes:**
- **SPHINCS+ BTC** — Bitcoin-optimized SPHINCS+ with WOTS+C (hash-based, stateless)
- **SPHINCS+ 128s** — Standard NIST parameter set (hash-based, stateless)
- **Falcon-512** — NIST finalist (lattice-based)

## SPHINCS+ BTC

Implementation of the Bitcoin-optimized SPHINCS+ variant from [Blockstream's paper - Hash-based Signature Schemes for Bitcoin](https://eprint.iacr.org/2025/2203.pdf). This variant reduces signature size through grinding-based optimizations while maintaining 128-bit security.

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

The implementation uses **Blake2s-256** truncated to 128 bits. Blake2s is chosen because:

- **Native Stwo AIR support** — Blake2s has a dedicated algebraic intermediate representation in the Stwo prover, making it ~1000× more efficient than simulated hash functions
- **Performance** — By nature blake2s is more ZK friendly than sha256

SHA-256 exceeds the Stwo memory address limit (2^27) and cannot be proven with current prover constraints.

## Benchmarks

Single signature verification (Apple M3, Stwo prover):

| Scheme | Cairo Steps | Memory Adresses | Proof Size | Prove Time |
|--------|-------------|--------|------------|------------|
| SPHINCS+ BTC (Blake2s) | 238k | 238K | 4.8 MB | ~7s |
| SPHINCS+ 128s (Blake2s) | ~1.3M | ~1.2M | ~5 MB | ~15s |
| Falcon-512 | TBD | TBD | TBD | TBD |

## Project Structure

```
packages/
├── sphincs-btc/          # Bitcoin-optimized SPHINCS+
│   ├── src/
│   │   ├── sphincs.cairo    # Main verification logic
│   │   ├── wots_c.cairo     # WOTS+C implementation
│   │   ├── fors.cairo       # FORS tree verification
│   │   ├── hasher/          # Blake2s tweakable hash
│   │   └── params_btc.cairo # Parameter definitions
│   └── scripts/
│       └── generate_args.py # Python signer for test vectors
├── sphincs-plus/         # Standard SPHINCS+ 128s
└── falcon/               # Falcon-512 verification
```

## Usage

### Prerequisites

- [Scarb](https://docs.swmansion.com/scarb/) (Cairo package manager)
- Python 3.8+ (for test vector generation)
- Rust nightly (for Stwo prover)

### Install Stwo Prover

```bash
make install-stwo-run-and-prove
```

### SPHINCS+ BTC

Generate test vector and run verification:

```bash
# Generate signature (Python signer)
make sphincs-btc-args

# Execute Cairo verification
make sphincs-btc-execute

# Generate STARK proof
make sphincs-btc-prove
```

### SPHINCS+ 128s

```bash
make sphincs-execute
make sphincs-prove
```

### Falcon-512

```bash
make falcon-args
make falcon-execute
make falcon-prove
```

## Technical Details

### Address Encoding

The implementation uses a 22-byte dense address encoding optimized for Cairo's 32-bit word operations:

```
Bytes 0-7:    layer (1B) + tree_addr (7B)
Bytes 8-9:    type (1B) + padding (1B)
Bytes 10-13:  keypair (2B) + padding (2B)
Bytes 14-21:  tree_height/chain_addr (1B) + tree_index/hash_addr (3B)
```

### Tweakable Hash Construction

The tweakable hash `thash(pk_seed, addr, M)` is constructed as:

```
Blake2s(pk_seed || zeros_48 || addr || M)[0:16]
```

The `pk_seed || zeros_48` block is precomputed and reused across all hash evaluations via Blake2s state seeding.

### FORS Verification

FORS uses k=10 Merkle trees of height a=14. The message hash is split into 14-bit indices selecting one leaf per tree. Verification:

1. Extract 10 indices from the 18-byte message hash
2. For each tree: compute leaf from secret key, verify Merkle path to root
3. Hash all 10 roots to produce the FORS public key

### Hypertree Verification

The hypertree consists of d=4 layers of Merkle trees with 2^8=256 leaves each. Verification proceeds bottom-up:

1. Layer 0 signs the FORS public key
2. Each subsequent layer signs the root of the layer below
3. Final root must match the public key

## References

- [BIP-360: Pay to Quantum Resistant Hash](https://bip360.org/)
- [Blockstream SPHINCS+ Bitcoin Proposal](https://eprint.iacr.org/2025/2203.pdf)
- [SPHINCS+ Specification](https://sphincs.org/data/sphincs+-r3.1-specification.pdf)
- [PQ Signatures and Scaling Bitcoin with STARKs](https://delvingbitcoin.org/t/post-quantum-signatures-and-scaling-bitcoin-with-starks/1584)

## License

MIT
