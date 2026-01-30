#!/usr/bin/env python3
"""
Generate valid test vectors for SPHINCS+ BTC (Bitcoin-optimized parameters).

This implementation exactly matches the Cairo verification logic to produce
cryptographically valid signatures using Blake2s hash function.

Parameters:
- n=16 (hash output bytes)
- h=32 (total height)
- d=4 (hypertree layers)
- tree_height=8 (per subtree)
- k=10 (FORS trees)
- a=14 (FORS height)
- w=256 (WOTS parameter)
- hash=Blake2s (STARK-optimized)
"""

from typing import List
from hash import poseidon_hash
import struct
import json
import sys

# === Parameters ===
SPX_N = 16  # hash output bytes
SPX_FULL_HEIGHT = 32
SPX_D = 4
SPX_TREE_HEIGHT = 8
SPX_FORS_HEIGHT = 14
SPX_FORS_TREES = 10
SPX_FORS_BASE_OFFSET = 1 << SPX_FORS_HEIGHT  # 16384
SPX_WOTS_W = 256
SPX_WOTS_LEN1 = 16
SPX_WOTS_C_LEN = 14  # Without last 2 chains
SPX_WOTS_C_OMIT = 2
SPX_WOTS_TARGET_SUM = 2040
SPX_DGST_BYTES = 30  # mhash(21) + tree_addr(7) + leaf_idx(2)

class Address:
    """
    Dense address encoding matching Cairo implementation (22 bytes).

    Layout:
    - w0 (4 bytes): layer (1 byte) + hypertree_addr high (3 bytes)
    - w1 (4 bytes): hypertree_addr mid (4 bytes)
    - w2 (4 bytes): hypertree_addr low (1 byte) + type (1 byte) + padding (2 bytes)
    - w3 (4 bytes): keypair (2 bytes) + padding (2 bytes)
    - w4 (4 bytes): padding (1 byte) + tree_height/chain_addr (1 byte) + tree_index_hi (2 bytes)
    - w5 (2 bytes): tree_index_lo (2 bytes) or hash_addr
    """

    # Address types matching Cairo
    WOTS = 0
    WOTSPK = 1
    HASHTREE = 2
    FORSTREE = 3
    FORSPK = 4
    WOTSPRF = 5
    FORSPRF = 6

    def __init__(self):
        self.layer = 0
        self.tree_addr = 0
        self.addr_type = 0
        self.keypair = 0
        self.tree_height = 0
        self.tree_index = 0
        self.chain_addr = 0
        self.hash_addr = 0

    def copy(self):
        a = Address()
        a.layer = self.layer
        a.tree_addr = self.tree_addr
        a.addr_type = self.addr_type
        a.keypair = self.keypair
        a.tree_height = self.tree_height
        a.tree_index = self.tree_index
        a.chain_addr = self.chain_addr
        a.hash_addr = self.hash_addr
        return a

    def set_layer(self, layer: int):
        self.layer = layer & 0xFF

    def set_tree_addr(self, addr: int):
        self.tree_addr = addr & 0xFFFFFFFFFFFFFFFF

    def set_type(self, t: int):
        self.addr_type = t & 0xFF

    def set_keypair(self, kp: int):
        self.keypair = kp & 0xFFFF

    def set_tree_height(self, h: int):
        self.tree_height = h & 0xFF

    def set_tree_index(self, idx: int):
        self.tree_index = idx & 0xFFFFFFFF

    def set_chain_addr(self, c: int):
        self.chain_addr = c & 0xFF

    def set_hash_addr(self, h: int):
        self.hash_addr = h & 0xFF

    def to_ints(self) -> List[int]:
        """
        Serialize to 22 bytes matching Cairo's WordArray format.

        Cairo stores: 5 full u32 words + 1 partial word (2 bytes) = 22 bytes
        """
        # w0: layer (1 byte) | tree_addr high 3 bytes
        tree_hi = (self.tree_addr >> 40) & 0xFFFFFF
        w0 = (self.layer << 24) | tree_hi

        # w1: tree_addr mid 4 bytes
        w1 = (self.tree_addr >> 8) & 0xFFFFFFFF

        # w2: tree_addr low (1 byte) | type (1 byte) | 2 padding bytes
        tree_lo = self.tree_addr & 0xFF
        w2 = (tree_lo << 24) | (self.addr_type << 16)

        # w3: keypair (2 bytes) | 2 padding bytes
        w3 = self.keypair << 16

        # w4: For WOTS addresses use chain_addr, otherwise tree_height
        # Cairo stores: padding (1 byte) | height/chain (1 byte) | tree_idx high (2 bytes)
        if self.addr_type in (Address.WOTS, Address.WOTSPK):
            height_or_chain = self.chain_addr
        else:
            height_or_chain = self.tree_height

        tree_idx_hi = (self.tree_index >> 16) & 0xFFFF
        w4 = (height_or_chain << 16) | tree_idx_hi

        # w5: tree_index low (2 bytes) or hash_addr for WOTS
        if self.addr_type in (Address.WOTS, Address.WOTSPK):
            w5_2bytes = self.hash_addr & 0xFFFF
        else:
            w5_2bytes = self.tree_index & 0xFFFF

        # Pack as 5 u32 words (big-endian) + 2 bytes
        return [w0, w1, w2, w3, w4, w5_2bytes]


def thash(pk_seed: int, address: Address, input_data: List[int]) -> int:
    """
    Tweakable hash matching Cairo's poseidon hash implementation
    """
    # Build the full input: pk_seed padded to 64 bytes + address + input

    data = [pk_seed] + address.to_ints() + input_data
    return poseidon_hash(data)


def compute_modified_message(pk_seed: int, address: Address, message: List[int], counter: int) -> int:
    """
    Compute modified message for WOTS+C: H(message || counter).
    This is the message that must satisfy WOTS+C constraints.
    """
    # Input: message (16 bytes) || counter (4 bytes)
    return thash(pk_seed, address, message + [counter])


def check_wots_c_constraints(message_bytes: bytes) -> bool:
    """
    Check if message satisfies WOTS+C constraints:
    Last SPX_WOTS_C_OMIT (2) bytes must be zero.
    This allows omitting those chains from the signature.
    """
    # Check last OMIT bytes are zero
    for i in range(SPX_WOTS_LEN1 - SPX_WOTS_C_OMIT, SPX_WOTS_LEN1):
        if message_bytes[i] != 0:
            return False

    return True


def grind_wots_counter(pk_seed: bytes, address: Address, message: bytes) -> tuple:
    """
    Grind to find a counter such that H(message || counter) satisfies WOTS+C constraints.
    Returns (modified_message, counter).
    """
    for counter in range(2**32):
        modified = compute_modified_message(pk_seed, address, message, counter)
        if check_wots_c_constraints(modified):
            return modified, counter
        if counter % 100000 == 0 and counter > 0:
            print(f"  Grinding counter: {counter}...", file=sys.stderr)
    raise ValueError("Could not find valid counter (exhausted 2^32 attempts)")


def chain_hash(pk_seed: bytes, address: Address, input_val: bytes, start: int, steps: int) -> bytes:
    """WOTS hash chain: hash 'steps' times starting from position 'start'."""
    addr = address.copy()
    addr.set_type(Address.WOTS)
    result = input_val
    for i in range(start, start + steps):
        addr.set_hash_addr(i)
        result = thash(pk_seed, addr, result)
    return result


def wots_sk(pk_seed: bytes, sk_seed: bytes, address: Address, chain_idx: int) -> bytes:
    """Derive WOTS secret key for a chain using PRF."""
    addr = address.copy()
    addr.set_type(Address.WOTSPRF)
    addr.set_chain_addr(chain_idx)
    addr.set_hash_addr(0)
    return thash(pk_seed, addr, sk_seed)


def wots_pk_chain(pk_seed: bytes, sk_seed: bytes, address: Address, chain_idx: int) -> bytes:
    """Compute single WOTS public key chain element."""
    sk = wots_sk(pk_seed, sk_seed, address, chain_idx)
    addr = address.copy()
    addr.set_type(Address.WOTS)
    addr.set_chain_addr(chain_idx)
    return chain_hash(pk_seed, addr, sk, 0, SPX_WOTS_W - 1)


def wots_pk(pk_seed: bytes, sk_seed: bytes, address: Address) -> bytes:
    """
    Compute WOTS+C public key (concatenation of first SPX_WOTS_C_LEN=14 chain endpoints).
    For WOTS+C, only the signed chains are used in the public key tree.
    """
    pk_parts = []
    for i in range(SPX_WOTS_C_LEN):  # Only 14 chains, not 16
        pk_i = wots_pk_chain(pk_seed, sk_seed, address, i)
        pk_parts.append(pk_i)
    return b''.join(pk_parts)


def wots_pk_compressed(pk_seed: bytes, sk_seed: bytes, address: Address) -> bytes:
    """Compute compressed WOTS+C public key (thash of first 14 chains only)."""
    pk_concat = wots_pk(pk_seed, sk_seed, address)
    addr = address.copy()
    addr.set_type(Address.WOTSPK)
    return thash(pk_seed, addr, pk_concat)


def wots_sign(pk_seed: bytes, sk_seed: bytes, modified_message: bytes, address: Address) -> list:
    """
    Sign with WOTS using the modified message (after grinding).
    Returns list of signature chain values (first SPX_WOTS_C_LEN chains only).
    """
    digits = list(modified_message)
    sig_chains = []

    for i in range(SPX_WOTS_C_LEN):
        sk = wots_sk(pk_seed, sk_seed, address, i)
        addr = address.copy()
        addr.set_type(Address.WOTS)
        addr.set_chain_addr(i)
        # Hash chain up to digit value
        sig_i = chain_hash(pk_seed, addr, sk, 0, digits[i])
        sig_chains.append(sig_i)

    return sig_chains


def fors_sk_leaf(pk_seed: bytes, sk_seed: bytes, address: Address, tree_idx: int, leaf_idx: int) -> bytes:
    """Derive FORS secret key for a leaf."""
    addr = address.copy()
    addr.set_type(Address.FORSPRF)
    idx = tree_idx * SPX_FORS_BASE_OFFSET + leaf_idx
    addr.set_tree_index(idx)
    return thash(pk_seed, addr, sk_seed)


def fors_leaf_hash(pk_seed: bytes, sk_seed: bytes, address: Address, tree_idx: int, leaf_idx: int) -> bytes:
    """Compute FORS leaf hash."""
    sk = fors_sk_leaf(pk_seed, sk_seed, address, tree_idx, leaf_idx)
    addr = address.copy()
    addr.set_type(Address.FORSTREE)
    addr.set_tree_height(0)
    idx = tree_idx * SPX_FORS_BASE_OFFSET + leaf_idx
    addr.set_tree_index(idx)
    return thash(pk_seed, addr, sk)


def fors_treehash(pk_seed: bytes, sk_seed: bytes, address: Address,
                  tree_idx: int, start_idx: int, height: int) -> bytes:
    """Compute FORS subtree root using treehash."""
    if height == 0:
        return fors_leaf_hash(pk_seed, sk_seed, address, tree_idx, start_idx)

    left = fors_treehash(pk_seed, sk_seed, address, tree_idx, start_idx, height - 1)
    right = fors_treehash(pk_seed, sk_seed, address, tree_idx, start_idx + (1 << (height - 1)), height - 1)

    addr = address.copy()
    addr.set_type(Address.FORSTREE)
    addr.set_tree_height(height)
    base = tree_idx * SPX_FORS_BASE_OFFSET
    addr.set_tree_index((base >> height) + (start_idx >> height))

    return thash(pk_seed, addr, left + right)


def fors_gen_auth(pk_seed: bytes, sk_seed: bytes, address: Address,
                  tree_idx: int, leaf_idx: int) -> list:
    """Generate FORS authentication path for a leaf."""
    auth = []
    for h in range(SPX_FORS_HEIGHT):
        sibling_idx = (leaf_idx >> h) ^ 1
        start = sibling_idx << h
        node = fors_treehash(pk_seed, sk_seed, address, tree_idx, start, h)
        auth.append(node)
    return auth


def fors_tree_root(pk_seed: bytes, sk_seed: bytes, address: Address, tree_idx: int) -> bytes:
    """Compute root of a single FORS tree."""
    return fors_treehash(pk_seed, sk_seed, address, tree_idx, 0, SPX_FORS_HEIGHT)


def fors_pk(pk_seed: bytes, sk_seed: bytes, address: Address) -> bytes:
    """Compute FORS public key (hash of all tree roots)."""
    roots = []
    for tree_idx in range(SPX_FORS_TREES):
        root = fors_tree_root(pk_seed, sk_seed, address, tree_idx)
        roots.append(root)

    addr = address.copy()
    addr.set_type(Address.FORSPK)
    return thash(pk_seed, addr, b''.join(roots))


def message_to_indices(mhash: bytes) -> list:
    """
    Convert FORS message hash to leaf indices (14 bits each, k=10 indices).
    Must match Cairo's message_to_indices_btc exactly.

    Cairo processes bytes from the beginning (big-endian) and accumulates
    bits until it has 14 bits, then extracts an index.
    """
    indices = []
    acc = 0
    acc_bits = 0
    byte_idx = 0

    while len(indices) < SPX_FORS_TREES and byte_idx < len(mhash):
        # Read next byte
        byte_val = mhash[byte_idx]
        byte_idx += 1

        # Accumulate: shift left by 8 and add new byte
        acc = (acc << 8) | byte_val
        acc_bits += 8

        # Extract 14-bit indices while we have enough bits
        while acc_bits >= 14 and len(indices) < SPX_FORS_TREES:
            shift_amount = acc_bits - 14
            idx = (acc >> shift_amount) & 0x3FFF  # 14-bit mask
            indices.append(idx)
            acc = acc & ((1 << shift_amount) - 1)  # Keep remaining bits
            acc_bits -= 14

    # Pad with zeros if we don't have enough indices
    while len(indices) < SPX_FORS_TREES:
        indices.append(0)

    return indices


def fors_sign(pk_seed: bytes, sk_seed: bytes, mhash: bytes, address: Address) -> list:
    """Generate FORS signature."""
    indices = message_to_indices(mhash)

    tree_sigs = []
    for tree_idx in range(SPX_FORS_TREES):
        leaf_idx = indices[tree_idx]

        # Secret key for this leaf
        sk = fors_sk_leaf(pk_seed, sk_seed, address, tree_idx, leaf_idx)

        # Authentication path
        auth = fors_gen_auth(pk_seed, sk_seed, address, tree_idx, leaf_idx)

        tree_sigs.append((sk, auth))

    return tree_sigs


def ht_leaf(pk_seed: bytes, sk_seed: bytes, address: Address, leaf_idx: int) -> bytes:
    """Compute hypertree leaf (compressed WOTS pk)."""
    addr = address.copy()
    addr.set_keypair(leaf_idx)
    return wots_pk_compressed(pk_seed, sk_seed, addr)


def ht_treehash(pk_seed: bytes, sk_seed: bytes, address: Address,
                start_idx: int, height: int) -> bytes:
    """Compute subtree root."""
    if height == 0:
        return ht_leaf(pk_seed, sk_seed, address, start_idx)

    left = ht_treehash(pk_seed, sk_seed, address, start_idx, height - 1)
    right = ht_treehash(pk_seed, sk_seed, address, start_idx + (1 << (height - 1)), height - 1)

    addr = address.copy()
    addr.set_type(Address.HASHTREE)
    addr.set_tree_height(height)
    addr.set_tree_index(start_idx >> height)
    # Clear keypair - internal nodes don't use it (Cairo compute_root uses keypair=0)
    addr.set_keypair(0)

    return thash(pk_seed, addr, left + right)


def ht_gen_auth(pk_seed: bytes, sk_seed: bytes, address: Address, leaf_idx: int) -> list:
    """Generate authentication path for hypertree layer."""
    auth = []
    for h in range(SPX_TREE_HEIGHT):
        sibling_idx = (leaf_idx >> h) ^ 1
        start = sibling_idx << h
        node = ht_treehash(pk_seed, sk_seed, address, start, h)
        auth.append(node)
    return auth


def hash_message(randomizer: int, pk_seed: int, pk_root: int,
                 message: List[int]) -> int:
    """
    Hash message to get extended digest (SPX_DGST_BYTES = 22 bytes).
    """
    # First hash: H(R || pk_seed || pk_root || message)
    seed = poseidon_hash([randomizer, pk_seed, pk_root] + message)

    # MGF1 expansion: H(R || pk_seed || seed || counter=0)
    expanded = poseidon_hash([randomizer, pk_seed, seed, 0])

    return expanded


def split_digest(digest: int) -> tuple:
    """Split extended digest into mhash, tree_addr, leaf_idx."""
    # digest is 30 bytes:
    # - mhash: 21 bytes (for k=10, a=14: 140 bits)
    # - tree_addr: 7 bytes (54 bits)
    # - leaf_idx: 2 byte (9 bits)
    # - mhash | 2 discarded bits | tree_addr | 7 discarded bits | leaf_idx

    leaf_idx = digest & 0x1FF  # 9 bits
    digest >>= 16

    tree_addr = digest & 0x3FFFFFFFFFFFFF  # 54 bits
    digest >>= 56

    return digest, tree_addr, leaf_idx


# Convert bytes to list of u32 values (little-endian)
# This is used for interfacing with blake2s hashlib
def bytes_to_u32s_little(data: bytes) -> list:
    """Convert bytes to list of u32 values"""
    result = []
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        if len(chunk) < 4:
            chunk = chunk + b'\x00' * (4 - len(chunk))
        result.append(struct.unpack("<I", chunk)[0])
    return result

# --- Helper to convert bytes to big-endian u32s for Cairo output ---
def bytes_to_u32s(data: bytes) -> list:
    """Convert bytes to list of u32 values"""
    result = []
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        if len(chunk) < 4:
            chunk = b'\x00' * (4 - len(chunk)) + chunk
        result.append(struct.unpack(">I", chunk)[0])
    return result


class SphinxBtcSigner:
    """Complete SPHINCS+ BTC signer with WOTS+C grinding."""

    def __init__(self, sk_seed: int, pk_seed: int):
        self.sk_seed = sk_seed
        self.pk_seed = pk_seed

        # Compute public key root (this is expensive - computes full hypertree)
        print("Computing public key root (this may take a while)...", file=sys.stderr)
        self.pk_root = self._compute_pk_root()
        print(f"Public key root: {self.pk_root.hex()}", file=sys.stderr)

    def _compute_pk_root(self) -> bytes:
        """Compute the top-level root of the hypertree."""
        addr = Address()
        addr.set_layer(SPX_D - 1)
        addr.set_tree_addr(0)
        return ht_treehash(self.pk_seed, self.sk_seed, addr, 0, SPX_TREE_HEIGHT)

    def sign(self, message: List[int]) -> dict:
        """Sign a message with full SPHINCS+ BTC signature."""
        # Generate randomizer (deterministic for reproducibility)
        randomizer = poseidon_hash([self.sk_seed] + message)

        # Hash message to get extended digest
        digest = hash_message(randomizer, self.pk_seed, self.pk_root, message)
        mhash, tree_addr, leaf_idx = split_digest(digest)

        print(f"Message digest: tree_addr={tree_addr}, leaf_idx={leaf_idx}", file=sys.stderr)

        # FORS address
        fors_addr = Address()
        fors_addr.set_layer(0)
        fors_addr.set_tree_addr(tree_addr)
        fors_addr.set_type(Address.FORSTREE)
        fors_addr.set_keypair(leaf_idx)

        # Generate FORS signature
        print("Generating FORS signature...", file=sys.stderr)
        fors_sig = fors_sign(self.pk_seed, self.sk_seed, mhash, fors_addr)

        # Compute FORS public key (this is what layer 0 WOTS signs)
        fors_root = fors_pk(self.pk_seed, self.sk_seed, fors_addr)
        print(f"FORS root: {fors_root.hex()}", file=sys.stderr)

        # WOTS+C signatures for each hypertree layer
        wots_sigs = []
        current_tree_addr = tree_addr
        current_leaf_idx = leaf_idx
        current_root = fors_root  # Message for layer 0

        for layer in range(SPX_D):
            print(f"Layer {layer}: tree_addr={current_tree_addr}, leaf_idx={current_leaf_idx}", file=sys.stderr)

            # Address for this layer
            addr = Address()
            addr.set_layer(layer)
            addr.set_tree_addr(current_tree_addr)
            addr.set_keypair(current_leaf_idx)
            addr.set_type(Address.WOTS)

            # Grind for valid counter
            print(f"  Grinding for WOTS+C counter...", file=sys.stderr)
            modified_message, counter = grind_wots_counter(
                self.pk_seed, addr, current_root
            )
            print(f"  Found counter: {counter}", file=sys.stderr)

            # Sign with WOTS using modified message
            sig_chains = wots_sign(self.pk_seed, self.sk_seed, modified_message, addr)

            # Generate auth path for this layer
            addr.set_type(Address.HASHTREE)
            auth_path = ht_gen_auth(self.pk_seed, self.sk_seed, addr, current_leaf_idx)

            wots_sigs.append({
                'chains': sig_chains,
                'counter': counter,
                'auth_path': auth_path
            })

            # Compute this layer's root for next iteration
            if layer < SPX_D - 1:
                current_root = ht_treehash(self.pk_seed, self.sk_seed, addr, 0, SPX_TREE_HEIGHT)
                current_leaf_idx = current_tree_addr & 0xFF
                current_tree_addr >>= 8

        return {
            'randomizer': randomizer,
            'fors_sig': fors_sig,
            'wots_sigs': wots_sigs
        }


def serialize_test_vector(sig: dict, pk_seed: bytes, pk_root: bytes, message: bytes) -> list:
    """Serialize to Cairo-compatible format (list of felt252 values)."""
    result = []

    # === Public key ===
    result.extend(bytes_to_u32s(pk_seed))
    result.extend(bytes_to_u32s(pk_root))

    # === Signature ===
    # Randomizer (16 bytes = 4 u32)
    result.extend(bytes_to_u32s(sig['randomizer']))

    # FORS signature: 10 trees * (sk_seed + 14 auth_path entries)
    for tree_sig in sig['fors_sig']:
        sk, auth = tree_sig
        result.extend(bytes_to_u32s(sk))  # 4 u32
        for a in auth:
            result.extend(bytes_to_u32s(a))  # 14 * 4 u32

    # WOTS+C Merkle signatures: 4 layers
    for wots_sig in sig['wots_sigs']:
        # 14 chains (each 16 bytes = 4 u32)
        for chain_val in wots_sig['chains']:
            result.extend(bytes_to_u32s(chain_val))
        # Counter (1 u32)
        result.append(wots_sig['counter'])
        # 8 auth path entries (each 16 bytes = 4 u32)
        for auth in wots_sig['auth_path']:
            result.extend(bytes_to_u32s(auth))

    # === Message as WordArray ===
    msg_len = len(message)
    full_words = msg_len // 4
    remaining = msg_len % 4

    words = []
    for i in range(full_words):
        words.append(struct.unpack(">I", message[i*4:(i+1)*4])[0])

    last_word = 0
    if remaining > 0:
        for b in message[full_words*4:]:
            last_word = (last_word << 8) | b

    result.append(len(words))  # Array length
    result.extend(words)
    result.append(last_word)
    result.append(remaining)

    return result


def serialize_multi_sig_vector(sigs: list, pk_seed: bytes, pk_root: bytes, messages: list) -> list:
    """Serialize multiple signatures to Cairo-compatible format."""
    result = []
    
    # === Public key (shared for all signatures) ===
    result.extend(bytes_to_u32s(pk_seed))
    result.extend(bytes_to_u32s(pk_root))
    
    # === Number of signatures ===
    result.append(len(sigs))
    
    # === Each signature ===
    for sig, message in zip(sigs, messages):
        # Randomizer (16 bytes = 4 u32)
        result.extend(bytes_to_u32s(sig['randomizer']))
        
        # FORS signature: 10 trees * (sk_seed + 14 auth_path entries)
        for tree_sig in sig['fors_sig']:
            sk, auth = tree_sig
            result.extend(bytes_to_u32s(sk))  # 4 u32
            for a in auth:
                result.extend(bytes_to_u32s(a))  # 14 * 4 u32
        
        # WOTS+C Merkle signatures: 4 layers
        for wots_sig in sig['wots_sigs']:
            # 14 chains (each 16 bytes = 4 u32)
            for chain_val in wots_sig['chains']:
                result.extend(bytes_to_u32s(chain_val))
            # Counter (1 u32)
            result.append(wots_sig['counter'])
            # 8 auth path entries (each 16 bytes = 4 u32)
            for auth in wots_sig['auth_path']:
                result.extend(bytes_to_u32s(auth))
        
        # === Message as WordArray ===
        msg_len = len(message)
        full_words = msg_len // 4
        remaining = msg_len % 4
        
        words = []
        for i in range(full_words):
            words.append(struct.unpack(">I", message[i*4:(i+1)*4])[0])
        
        last_word = 0
        if remaining > 0:
            for b in message[full_words*4:]:
                last_word = (last_word << 8) | b
        
        result.append(len(words))  # Array length
        result.extend(words)
        result.append(last_word)
        result.append(remaining)
    
    return result

def main():
    """
    let randomizer = 0xdeadbeef;
        let pk_seed = 0xcafebabe;
        let pk_root = 0xfeedface;

        let message = WordArrayTrait::new(array![0x11111111, 0x22222222, 0x33333333], 0, 0);
        let digest = hash_message_128s(randomizer, pk_seed, pk_root, message.span());
    """
    randomizer = 0xdeadbeef
    pk_seed = 0xcafebabe
    pk_root = 0xfeedface

    message = [0x11111111, 0x22222222, 0x33333333]
    digest = hash_message(randomizer, pk_seed, pk_root, message)
    print(digest)


if __name__ == "__main__":
    main()