from typing import List
from starknet_crypto_py import poseidon_hash_many as rs_poseidon_hash_many 

def poseidon_hash(inputs: List[int]) -> int:
    return rs_poseidon_hash_many(inputs)

# export
__all__ = ["poseidon_hash"]

# Sanity check for poseidon hasher
assert(poseidon_hash([1, 2, 3, 4, 5, 6, 7, 8]) == 142523731258509939608696022271238521916410456401611624853849835202137558864)
