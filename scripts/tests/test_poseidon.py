import pytest
from poseidon_hash.hash  import poseidon_hash

def test_poseidon_hash_sample():
    inputs = [1, 2, 3, 4, 5]
    result = poseidon_hash(inputs)

    expected = 611250879885582549814822745980582240134120981459161846704834910080944450980
    assert result == expected