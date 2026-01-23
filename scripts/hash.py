from typing import List
import poseidon_py.poseidon_hash as poseidon

def poseidon_hash(inputs: List[int]) -> int:
    return poseidon.poseidon_hash_many(inputs)

# export
__all__ = ["poseidon_hash"]

# Sanity check for poseidon hasher
assert(poseidon_hash([1,2,3,4,5]) == 611250879885582549814822745980582240134120981459161846704834910080944450980)
