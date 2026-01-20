#!/usr/bin/env python3
"""
Systematic consistency testing between Python and Cairo implementations.

This script tests each component incrementally:
1. Blake2s raw hashing
2. thash (tweakable hash with address)
3. WOTS+C pk computation
4. pk_root computation
"""

import hashlib
import sys
import struct
from pathlib import Path

# Import from generate_args
sys.path.insert(0, str(Path(__file__).parent))
from generate_args import (
    SPX_N, SPX_D, SPX_TREE_HEIGHT,
    blake2s_raw, thash, Address,
    wots_pk_compressed, ht_treehash,
    bytes_to_u32s
)


def test_blake2s_basic():
    """Test basic Blake2s hashing."""
    print("=" * 60)
    print("Test 1: Basic Blake2s")
    print("=" * 60)
    
    # Test vectors
    test_inputs = [
        b"",  # Empty
        b"abc",  # Simple
        bytes(range(16)),  # 16 bytes sequence
    ]
    
    for i, data in enumerate(test_inputs):
        h = blake2s_raw(data)
        print(f"\nTest {i+1}:")
        print(f"  Input: {data.hex() if len(data) <= 32 else data[:32].hex() + '...'}")
        print(f"  Input length: {len(data)} bytes")
        print(f"  Blake2s output: {h.hex()}")
        print(f"  Output u32s: {bytes_to_u32s(h[:32])}")
    
    print("\n✓ Blake2s basic tests complete")
    print("Compare these outputs with Cairo implementation")


def test_thash():
    """Test thash (tweakable hash) function."""
    print("\n" + "=" * 60)
    print("Test 2: thash (Tweakable Hash)")
    print("=" * 60)
    
    # Use deterministic seeds
    pk_seed = bytes(range(16))
    test_data = bytes(range(16, 32))
    
    # Test with different address configurations
    addr = Address()
    
    test_cases = [
        ("Zero address", lambda a: None),
        ("Layer 1", lambda a: a.set_layer(1)),
        ("Tree addr 0x123", lambda a: a.set_tree_addr(0x123)),
        ("WOTS type", lambda a: a.set_type(Address.WOTS)),
        ("Complex", lambda a: (a.set_layer(2), a.set_tree_addr(0xABC), 
                              a.set_type(Address.HASHTREE), a.set_keypair(5))),
    ]
    
    for name, setup_fn in test_cases:
        addr = Address()
        setup_fn(addr)
        
        result = thash(pk_seed, addr, test_data)
        
        print(f"\n{name}:")
        print(f"  pk_seed: {pk_seed.hex()}")
        print(f"  address bytes: {addr.to_bytes().hex()}")
        print(f"  input: {test_data.hex()}")
        print(f"  thash output: {result.hex()}")
        print(f"  Output u32s: {bytes_to_u32s(result)}")
    
    print("\n✓ thash tests complete")


def test_wots_pk():
    """Test WOTS+C public key computation."""
    print("\n" + "=" * 60)
    print("Test 3: WOTS+C Public Key")
    print("=" * 60)
    
    # Deterministic seeds
    sk_seed = bytes(range(16))
    pk_seed = bytes(range(16, 32))
    
    # Address for WOTS
    addr = Address()
    addr.set_layer(0)
    addr.set_tree_addr(0)
    addr.set_keypair(0)
    addr.set_type(Address.WOTS)
    
    print(f"\nsk_seed: {sk_seed.hex()}")
    print(f"pk_seed: {pk_seed.hex()}")
    print(f"address bytes: {addr.to_bytes().hex()}")
    
    # Compute WOTS+C compressed pk
    pk_compressed = wots_pk_compressed(pk_seed, sk_seed, addr)
    
    print(f"\nWOTS+C compressed pk: {pk_compressed.hex()}")
    print(f"Output u32s: {bytes_to_u32s(pk_compressed)}")
    
    print("\n✓ WOTS+C pk test complete")


def test_pk_root():
    """Test pk_root computation."""
    print("\n" + "=" * 60)
    print("Test 4: pk_root Computation")
    print("=" * 60)
    
    # Deterministic seeds
    sk_seed = bytes(range(16))
    pk_seed = bytes(range(16, 32))
    
    print(f"\nsk_seed: {sk_seed.hex()}")
    print(f"pk_seed: {pk_seed.hex()}")
    
    # Compute pk_root (top layer root)
    print("\nComputing pk_root (this may take a while)...")
    addr = Address()
    addr.set_layer(SPX_D - 1)
    addr.set_tree_addr(0)
    
    pk_root = ht_treehash(pk_seed, sk_seed, addr, 0, SPX_TREE_HEIGHT)
    
    print(f"\npk_root: {pk_root.hex()}")
    print(f"Output u32s: {bytes_to_u32s(pk_root)}")
    
    print("\n✓ pk_root test complete")


def test_incremental_tree():
    """Test incremental tree computation for debugging."""
    print("\n" + "=" * 60)
    print("Test 5: Incremental Tree Computation")
    print("=" * 60)
    
    # Deterministic seeds
    sk_seed = bytes(range(16))
    pk_seed = bytes(range(16, 32))
    
    print(f"\nsk_seed: {sk_seed.hex()}")
    print(f"pk_seed: {pk_seed.hex()}")
    
    # Compute first few leaves
    addr = Address()
    addr.set_layer(SPX_D - 1)
    addr.set_tree_addr(0)
    addr.set_type(Address.WOTS)
    
    print("\nFirst 3 leaves:")
    for leaf_idx in range(3):
        addr.set_keypair(leaf_idx)
        leaf_pk = wots_pk_compressed(pk_seed, sk_seed, addr)
        print(f"  Leaf {leaf_idx}: {leaf_pk.hex()}")
        print(f"    u32s: {bytes_to_u32s(leaf_pk)}")
    
    # Compute subtree roots at different heights
    addr.set_type(Address.HASHTREE)
    print("\nSubtree roots at different heights:")
    for height in [1, 2, 3]:
        root = ht_treehash(pk_seed, sk_seed, addr, 0, height)
        print(f"  Height {height}: {root.hex()}")
        print(f"    u32s: {bytes_to_u32s(root)}")
    
    print("\n✓ Incremental tree test complete")


def main():
    print("SPHINCS+ BTC Consistency Test Suite")
    print("=" * 60)
    print("Testing Python implementation components")
    print("Compare outputs with Cairo implementation using --features debug")
    print("=" * 60)
    
    # Run all tests
    test_blake2s_basic()
    test_thash()
    # test_wots_pk()
    # test_incremental_tree()
    # test_pk_root()
    
    print("\n" + "=" * 60)
    print("All tests complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Create Cairo test program to output the same values")
    print("2. Compare outputs to find where they diverge")
    print("3. Fix the inconsistency")


if __name__ == "__main__":
    main()
