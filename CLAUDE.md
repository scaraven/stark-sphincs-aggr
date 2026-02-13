# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository implements STARK-provable verification of post-quantum signature schemes in Cairo, targeting Bitcoin soft-fork compatibility via BIP-360. The primary use case is batch verification of post-quantum signatures for Bitcoin transactions, where a single STARK proof attests to the validity of multiple signatures.

**Implemented schemes:**
- **sphincs-btc**: Bitcoin-optimized SPHINCS+ with WOTS+C (hash-based, stateless)
- **sphincs-plus**: Standard NIST SPHINCS+ 128s parameter set
- **sphincs-poseidon**: SPHINCS+ with Poseidon hash (arithmetic-friendly)
- **falcon**: Falcon-512 (lattice-based, NIST finalist)

## Development Commands

### Building

```bash
# Build all packages
scarb build

# Build specific package
scarb build --package sphincs_btc
scarb build --package sphincs_plus
scarb build --package sphincs_poseidon
scarb build --package falcon
```

### Testing

```bash
# Run all tests
scarb test

# Run tests for specific package
scarb test --package sphincs_btc
scarb test --package sphincs_poseidon

# Run with verbose output
scarb test -v
```

### Generating Test Vectors

Python scripts generate test vectors for signature verification. Each package has its own script:

```bash
# sphincs-btc
cd packages/sphincs-btc/scripts
python generate_args.py

# sphincs-poseidon
cd packages/sphincs-poseidon/scripts
python generate_args.py

# falcon
cd packages/falcon/scripts
python generate_args.py
```

### Running STARK Proofs

Each package contains a `proving_task.json` that defines the Cairo function to prove. Use `stwo_run_and_prove` from the Stwo prover:

```bash
# Example for sphincs-btc
stwo_run_and_prove \
  --task-path packages/sphincs-btc/proving_task.json \
  --prover-params-path prover_params.json
```

The root `prover_params.json` configures STARK parameters (FRI queries, blowup factor, etc.).

### Benchmarking

```bash
# Single benchmark
python benchmarks/benchmark.py --name "test_name"

# With specific features
python benchmarks/benchmark.py \
  --name "blake_benchmark" \
  --features blake_hash

# From config file
python benchmarks/benchmark.py --config benchmarks/benchmark_config.json

# Compare results
python benchmarks/compare_results.py benchmarks/results/benchmark_*.json
```

## Architecture

### Package Structure

The repository uses a Scarb workspace with four main packages under `packages/`:

- **sphincs-btc**: Bitcoin-optimized variant with WOTS+C (eliminates checksum chains via grinding)
- **sphincs-plus**: Standard SPHINCS+ 128s implementation
- **sphincs-poseidon**: Poseidon hash backend for SPHINCS+ (experimental)
- **falcon**: Falcon-512 implementation (NTT-based lattice signatures)

### Hash Function Abstraction

The SPHINCS+ implementations use conditional compilation to switch hash backends:

**sphincs-btc**: Blake2s (feature: `blake_hash`) or SHA-256 (default)
- Blake2s is preferred due to native Stwo AIR support (~1000x faster proving)
- Hash output truncated to 128 bits (16 bytes) for n=16 security parameter

**sphincs-poseidon**: Uses Poseidon hash exclusively
- HashOutput is `felt252` instead of `[u32; 4]`
- Arithmetic-friendly for field operations
- Address encoding uses `into_field_components()` instead of byte arrays

### Address Encoding

SPHINCS+ uses a tweakable hash function with an "address" parameter that provides domain separation. Two implementations:

**Dense encoding** (default): 22-byte packed format optimized for Blake2s/SHA-256
- Layout: layer(1) + tree_addr(7) + type(1) + pad(1) + keypair(2) + pad(2) + tree_height/chain_addr(1) + tree_index/hash_addr(3)
- Used by `sphincs-btc` and `sphincs-plus` and `sphincs-poseidon` (feature: `sparse_addr` disables)

**Sparse encoding** (feature-gated): Field-element encoding for Poseidon
- Each field encodes logical components separately
- `into_field_components()` returns `[felt252; 8]` for Poseidon absorption
- Not used by anyone, this is an obselete feature

### SPHINCS+ Verification Flow

All SPHINCS+ verifiers follow this structure:

1. **Initialize hash context**: `initialize_hash_function(pk_seed)` pre-absorbs the public seed
2. **Hash message**: Extract tree address and leaf index from message digest
3. **Verify FORS**: Reconstruct FORS public key from signature and authentication paths
4. **Verify hypertree**: Bottom-up verification through d layers of WOTS signatures
   - Layer 0 signs the FORS public key
   - Each subsequent layer signs the root of the layer below
   - Final root must match `pk_root`

**sphincs-btc specific**: WOTS+C uses grinding to eliminate checksum chains
- Signature includes a counter value
- Verifier recomputes `H(message || counter)` and checks last τ=2 bytes are zero
- Only len1-τ=14 chains in signature (vs 16+3=19 for standard WOTS+)

### Tweakable Hash Construction

The core primitive `thash(pk_seed, addr, M)` differs by backend:

**Blake2s/SHA-256**:
```
thash = Hash(pk_seed || zeros_48 || addr || M)[0:16]
```
The `pk_seed || zeros_48` block is precomputed in the hash state during initialization.

**Poseidon**:
```
thash = Poseidon(pk_seed, addr[0..6], M)
```
State is initialized with `pk_seed`, then address components and message are absorbed.

### Scarb Features

**sphincs-btc**:
- `blake_hash`: Use Blake2s instead of SHA-256 (default: enabled)
- `debug`: Enable debug output

**sphincs-poseidon**:
- `sparse_addr`: Use sparse address encoding (required for Poseidon)

Features are specified in `Scarb.toml` under `[features]`.

## Important Files

- `prover_params.json`: Root-level STARK prover configuration (shared across packages)
- `packages/*/proving_task.json`: Per-package proving task definitions
- `packages/*/scripts/generate_args.py`: Python signers for test vector generation
- `benchmarks/benchmark.py`: Benchmarking harness for proof generation
- `packages/*/src/params_*.cairo`: Parameter definitions (n, h, d, k, a, w)

## Common Patterns

### Reading Hash Function Type

Check which hash backend is active:
- Look for `#[cfg(feature: "blake_hash")]` in hasher modules
- `HashOutput` type: `[u32; 4]` for Blake2s/SHA-256, `felt252` for Poseidon
- Import from `hasher::blake2s` or `hasher::poseidon` accordingly

### Working with Addresses

The `Address` type and `AddressTrait` are abstracted:
- Dense: `address.to_word_array()` returns byte-packed representation
- Sparse: `address.into_field_components()` returns field elements
- Always use the trait methods, never assume internal structure

### Testing Hash Functions

Consistency tests compare Cairo output with Python reference implementations:
- `packages/sphincs-btc/scripts/test_thash.py`: Verify thash outputs
- `packages/sphincs-btc/scripts/test_consistency.py`: End-to-end signature verification

Run Python scripts with the corresponding Python signer implementation to validate.

## sphincs-poseidon Deep Dive

### Poseidon Constraint Cost Model

Cairo's built-in Poseidon uses a sponge with **rate 2**: it absorbs 2 field elements per permutation. Each permutation has a fixed constraint cost in the Stwo AIR. Key cost formula:

- `state.update(x)`: absorbs one element. If the internal counter is odd, triggers a permutation.
- `state.finalize()`: adds padding, triggers a final permutation.
- Absorbing N elements costs `ceil(N/2)` permutations, plus 1 for finalize.

`update_with([felt252; N])` is NOT specially optimized — it serializes to `Array<felt252>` then calls `update` in a loop. Individual `update` calls are equivalent and avoid serialization overhead.

### thash Permutation Counts

Every `thash` call goes through `seed_address` which absorbs `pk_seed(1) + addr[0..5](6)` = 7 elements, then absorbs data:

| Function | Data elements | Total absorbed | Permutations |
|----------|--------------|----------------|--------------|
| `thash_single` | 1 | 8 | 5 |
| `thash_2` | 2 | 9 | 5 |
| `thash` (35 elts, WOTS PK) | 35 | 42 | 22 |
| `thash_fors_tree_root` (14 elts) | 14 | 21 | 11 |

### Hash Call Count Per Signature (~2,100 calls, ~10,600 permutations)

| Component | Hash calls | Permutations |
|-----------|-----------|--------------|
| `hash_message_128s` (2 hashes) | 2 | ~7 |
| FORS: 14 trees × (1 leaf + 12 auth levels) + 1 root hash | 183 | ~921 |
| WOTS: 7 layers × 35 chains × avg 7.5 steps | ~1,838 | ~9,190 |
| HT: 7 layers × (1 PK compress + 9 auth levels) | 70 | ~385 |
| **Total** | **~2,093** | **~10,503** |

WOTS chains dominate at ~87% of total permutations.

### Address Component Stability

Dense address encoding (default for sphincs-poseidon, `into_field_components() -> [felt252; 6]`):
- `[w0, w1, w2, w3, w4, w5]` where w0-w1 = layer+hypertree_addr, w2 = hypertree_addr+type, w3 = keypair, w4 = tree_height/chain_addr, w5 = tree_index/hash_addr

**Within a WOTS chain**: w0-w4 are constant, only w5 (hash_addr) changes per step.
**Within FORS trees**: w0-w3 are constant across all 14 trees (same layer, hypertree_addr, type, keypair). w4 and w5 change per tree level.
**Within compute_root**: w0-w3 are constant, w4 (tree_height) and w5 (tree_index) change per level.

This stability enables "partial precomputation" — absorbing shared prefix elements once and reusing the Poseidon state across multiple hash calls.

### Multi-Signature Batch Verification

Entry point: `main_multi` → `verify_128s_batch` (sphincs.cairo:130-144).
Currently calls `verify_128s` per signature independently — no shared computation between signatures. `initialize_hash_function(pk_seed)` is redundantly called per signature despite pk_seed being shared.

### sphincs-poseidon Parameters (params_128s.cairo)

| Parameter | Value | Notes |
|-----------|-------|-------|
| h (full height) | 63 | |
| d (layers) | 7 | |
| tree_height | 9 | h/d |
| k (FORS trees) | 14 | |
| a (FORS height) | 12 | |
| w (WOTS param) | 16 | |
| WOTS_LEN1 | 32 | message chains |
| WOTS_LEN2 | 3 | checksum chains |
| WOTS_LEN | 35 | total chains |

### Key Source Files (sphincs-poseidon)

- `src/hasher.cairo`: SpxCtx, initialize_hash_function, seed_address, thash variants, compute_root, hash_message_128s, felt252_to_u32_array
- `src/hasher/poseidon.cairo`: HashState wrapper, hash_init, hash_finalize variants, hash_update_block
- `src/wots.cairo`: wots_pk_from_sig, chain_hash_128s, base_w_128s, add_checksum_128s
- `src/fors.cairo`: fors_pk_from_sig, message_to_indices_128s
- `src/sphincs.cairo`: verify_128s, verify_128s_batch, split_xdigest_128s
- `src/address/dense.cairo`: Address struct (12 fields: 6 words + 6 cached), into_field_components -> [felt252; 6]
- `src/address/sparse.cairo`: Address struct (8 fields), into_field_components -> [felt252; 8] (only used with `sparse_addr` feature, which is NOT default)

## Known Constraints

- SHA-256 exceeds Stwo memory address limit (2^27) and cannot be proven with current prover
- Blake2s is strongly preferred for proof generation
- Poseidon backend is experimental (sphincs-poseidon package)
- Signature grinding in WOTS+C requires ~65,536 hash evaluations per signature

## References

- [BIP-360](https://bip360.org/): Pay to Quantum Resistant Hash
- [Blockstream SPHINCS+ Paper](https://eprint.iacr.org/2025/2203.pdf): Bitcoin-optimized parameters
- [SPHINCS+ Spec](https://sphincs.org/data/sphincs+-r3.1-specification.pdf): Original specification
