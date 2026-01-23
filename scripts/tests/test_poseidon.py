import pytest
from src.poseidon_hash.hash  import poseidon_hash


@pytest.mark.xfail(reason="expected output not set yet")
def test_poseidon_hash_sample():
    inputs = [1, 2, 3, 4, 5]
    result = poseidon_hash(inputs)

    # TODO: replace `expected` with the integer hash output you expect.
    expected = None

    # Once you have the expected integer value, change/remove the xfail marker
    # and set `expected` accordingly.
    assert result == expected