from typing import List
import poseidon_py.poseidon_hash as poseidon

def poseidon_hash(inputs: List[int]) -> int:
    return poseidon.poseidon_hash_many(inputs)

# export
__all__ = ["poseidon_hash"]
