#!/usr/bin/env python3
"""Quick test to verify thash computation matches expectations."""

import sys
sys.path.insert(0, '.')

from generate_args import (
    thash, Address, SPX_N, message_to_indices,
    check_wots_c_constraints, compute_modified_message,
    grind_wots_counter
)

def test_thash():
    """Test basic thash computation."""
    pk_seed = bytes(SPX_N)  # All zeros
    addr = Address()
    addr.set_type(Address.FORSTREE)

    input_data = b'\x01' * 16

    result = thash(pk_seed, addr, input_data)
    print(f"thash result: {result.hex()}")
    print(f"Result length: {len(result)} bytes")

    # Verify it's deterministic
    result2 = thash(pk_seed, addr, input_data)
    assert result == result2, "thash should be deterministic"
    print("thash is deterministic: OK")


def test_message_to_indices():
    """Test message to indices conversion."""
    # Test with known input
    mhash = bytes(range(18))  # 0x00, 0x01, ..., 0x11 (18 bytes)
    indices = message_to_indices(mhash)

    print(f"Message hash: {mhash.hex()}")
    print(f"Indices: {indices}")
    print(f"Number of indices: {len(indices)}")

    # Verify we get 10 indices
    assert len(indices) == 10, f"Expected 10 indices, got {len(indices)}"
    # Verify all indices are 14-bit (0-16383)
    for idx in indices:
        assert 0 <= idx <= 16383, f"Index {idx} out of range"
    print("message_to_indices: OK")


def test_wots_c_constraints():
    """Test WOTS+C constraint checking."""
    # Should fail: last 2 bytes not zero
    bad_msg = bytes(16)  # all zeros except...
    bad_msg = b'\xff' * 14 + b'\x01\x00'  # last byte 0, second-to-last 1
    assert not check_wots_c_constraints(bad_msg), "Should fail: byte 14 is not 0"

    # Should pass: last 2 bytes are zero
    good_msg = b'\xff' * 14 + b'\x00\x00'
    assert check_wots_c_constraints(good_msg), "Should pass: last 2 bytes are 0"

    print("wots_c_constraints: OK")


def test_grinding():
    """Test WOTS+C counter grinding."""
    pk_seed = bytes(SPX_N)
    addr = Address()
    addr.set_type(Address.WOTS)
    addr.set_layer(0)

    message = b'\xab' * 16

    print("Testing grinding (this may take a moment)...")
    modified, counter = grind_wots_counter(pk_seed, addr, message)

    print(f"Found counter: {counter}")
    print(f"Modified message: {modified.hex()}")
    print(f"Last 2 bytes: {modified[-2]:02x} {modified[-1]:02x}")

    # Verify constraints
    assert check_wots_c_constraints(modified), "Modified message should satisfy constraints"
    print("Grinding: OK")


if __name__ == "__main__":
    print("=== Testing SPHINCS+ BTC components ===\n")

    print("1. Testing thash...")
    test_thash()
    print()

    print("2. Testing message_to_indices...")
    test_message_to_indices()
    print()

    print("3. Testing WOTS+C constraints...")
    test_wots_c_constraints()
    print()

    print("4. Testing grinding...")
    test_grinding()
    print()

    print("=== All tests passed! ===")
