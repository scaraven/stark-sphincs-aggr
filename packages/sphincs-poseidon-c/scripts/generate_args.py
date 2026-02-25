#!/usr/bin/env python3
"""
Generate valid test vectors for SPHINCS+ with Poseidon hash (WOTS+C variant).

This implementation uses field elements (felt252) instead of bytes,
matching the Cairo Poseidon implementation.

Parameters (matching params_128s.cairo):
- h=33 (total height)
- d=3 (hypertree layers)
- tree_height=11 (per subtree)
- k=9 (FORS trees)
- a=15 (FORS height)
- w=16 (WOTS parameter)
- hash=Poseidon (arithmetic-friendly)
- WOTS+C: grinding over counter to eliminate checksum chains
"""

import os
from typing import List
from hash import poseidon_hash
from concurrent.futures import ProcessPoolExecutor, as_completed
import argparse
import json
import sys

# === Parameters (matching params_128s.cairo) ===
SPX_N = 16  # hash output bytes (for reference, but we use felt252)
SPX_FULL_HEIGHT = 33
SPX_D = 3
SPX_TREE_HEIGHT = 11  # SPX_FULL_HEIGHT / SPX_D
SPX_FORS_HEIGHT = 15
SPX_FORS_TREES = 9
SPX_FORS_BASE_OFFSET = 1 << SPX_FORS_HEIGHT  # 32768
SPX_FORS_MSG_BYTES = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) // 8  # 17
SPX_TREE_BITS = SPX_TREE_HEIGHT * (SPX_D - 1)  # 22
SPX_LEAF_BITS = SPX_TREE_HEIGHT  # 11
SPX_DGST_BYTES = SPX_FORS_MSG_BYTES + (SPX_TREE_BITS + 7) // 8 + (SPX_LEAF_BITS + 7) // 8  # 22
SPX_WOTS_W = 16
SPX_WOTS_LOGW = 4
SPX_WOTS_LEN1 = 8 * SPX_N // SPX_WOTS_LOGW  # 32
# WOTS+C: no checksum chains — grinding replaces them
SPX_WOTS_LEN = SPX_WOTS_LEN1  # 32
SPX_WOTS_CSUM = 304  # Target sum of all base-w digits for WOTS+C grinding

class Address:
    """
    Dense address encoding matching Cairo implementation.
    Stores address as 6 u32 words internally, converts to field elements for hashing.
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

    def to_field_elements(self) -> List[int]:
        """
        Convert address to 6 field elements (one per u32 word).
        Matches Cairo's dense Address::into_field_components().
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
        if self.addr_type in (Address.WOTS, Address.WOTSPK):
            height_or_chain = self.chain_addr
        else:
            height_or_chain = self.tree_height

        tree_idx_hi = (self.tree_index >> 16) & 0xFFFF
        w4 = (height_or_chain << 16) | tree_idx_hi

        # w5: tree_index low (2 bytes) or hash_addr for WOTS
        if self.addr_type in (Address.WOTS, Address.WOTSPK):
            w5 = self.hash_addr & 0xFFFF
        else:
            w5 = self.tree_index & 0xFFFF

        # Return as field elements (just the u32 values as ints)
        return [w0, w1, w2, w3, w4, w5]


def thash(pk_seed: int, address: Address, input_data: List[int]) -> int:
    """
    Tweakable hash using Poseidon with field elements.
    Matches Cairo's thash implementation in hasher.cairo:39-44.

    Returns: felt252 (as Python int)
    """
    # Get address as 6 field elements
    addr_fields = address.to_field_elements()

    # Build input: pk_seed, then 6 address components, then data
    data = [pk_seed] + addr_fields + input_data

    return poseidon_hash(data)


def felt252_to_u32_array(value: int) -> List[int]:
    """
    Convert felt252 to array of 4 u32 values (little-endian).
    Matches Cairo's conversion in sphincs.cairo:86-93.
    """
    result = []
    for _ in range(4):
        result.append(value & 0xFFFFFFFF)
        value >>= 32
    return result


def base_w_128s(input_array: List[int]) -> List[int]:
    """
    Convert array of u32 values to base-w (w=16) representation.
    Matches Cairo's base_w_128s in wots.cairo:109-123.

    Each u32 is split into 8 nibbles (4-bit chunks).
    Returns list of SPX_WOTS_LEN1 = 32 nibbles.
    """
    out = []
    for word in input_array:
        # Extract 8 nibbles from this u32 (big-endian nibbles)
        for i in range(7, -1, -1):
            nibble = (word >> (i * 4)) & 0xF
            out.append(nibble)
    return out


def grind_wotsc_counter(pk_seed: int, wots_pk_addr: Address, root: int) -> tuple:
    """
    WOTS+C grinding: find counter such that sum(base_w(H(wotspk_addr, [root, counter]))) == SPX_WOTS_CSUM.

    Matches Cairo's verify_128s_with_ctx:
        root_digest = thash(ctx, @wots_pk_addr, array![root, *counter].span())
        root_u32_array = felt252_to_u32_array(root_digest)  # little-endian
        verify_checksum_128s: asserts sum(base_w(root_u32_array)) == SPX_WOTS_CSUM

    Returns: (counter: int, root_digest: int, msg_u32: List[int], digits: List[int])
    """
    counter = 0
    MAX_COUNTER = 100_000
    while counter < MAX_COUNTER:
        root_digest = thash(pk_seed, wots_pk_addr, [root, counter])
        msg_u32 = felt252_to_u32_array(root_digest)  # little-endian
        digits = base_w_128s(msg_u32)
        if sum(digits) == SPX_WOTS_CSUM:
            return counter, root_digest, msg_u32, digits
        if counter % 1000 == 0:
            print(f"Grinding WOTS+C: counter={counter}, sum={sum(digits)}", file=sys.stderr)
        counter += 1
    raise ValueError(f"WOTS+C grinding failed after {MAX_COUNTER} attempts")

def chain_hash(pk_seed: int, address: Address, input_val: int, start: int, steps: int) -> int:
    """
    WOTS hash chain: hash 'steps' times starting from position 'start'.
    Works with field elements (felt252).
    """
    addr = address.copy()
    addr.set_type(Address.WOTS)
    result = input_val
    for i in range(start, start + steps):
        addr.set_hash_addr(i)
        result = thash(pk_seed, addr, [result])
    return result


def wots_sk(pk_seed: int, sk_seed: int, address: Address, chain_idx: int) -> int:
    """Derive WOTS secret key for a chain using PRF. Returns felt252."""
    addr = address.copy()
    addr.set_type(Address.WOTSPRF)
    addr.set_chain_addr(chain_idx)
    addr.set_hash_addr(0)
    return thash(pk_seed, addr, [sk_seed])


def wots_pk_chain(pk_seed: int, sk_seed: int, address: Address, chain_idx: int) -> int:
    """Compute single WOTS public key chain element. Returns felt252."""
    sk = wots_sk(pk_seed, sk_seed, address, chain_idx)
    addr = address.copy()
    addr.set_type(Address.WOTS)
    addr.set_chain_addr(chain_idx)
    return chain_hash(pk_seed, addr, sk, 0, SPX_WOTS_W - 1)


def wots_pk(pk_seed: int, sk_seed: int, address: Address) -> List[int]:
    """
    Compute WOTS public key (all SPX_WOTS_LEN=35 chain endpoints).
    Returns list of felt252 values.
    """
    pk_parts = []
    for i in range(SPX_WOTS_LEN):
        pk_i = wots_pk_chain(pk_seed, sk_seed, address, i)
        pk_parts.append(pk_i)
    return pk_parts


def wots_pk_compressed(pk_seed: int, sk_seed: int, address: Address) -> int:
    """Compute compressed WOTS public key (hash of all chains). Returns felt252."""
    pk_list = wots_pk(pk_seed, sk_seed, address)
    addr = address.copy()
    addr.set_type(Address.WOTSPK)
    return thash(pk_seed, addr, pk_list)


def wots_sign_wotsc(pk_seed: int, sk_seed: int, message_root: int, address: Address) -> dict:
    """
    Sign with WOTS+C: grind a counter so that sum(base_w(H(wotspk_addr, [root, counter]))) == SPX_WOTS_CSUM.

    Args:
        message_root: felt252 value to sign (FORS pk or previous layer root)
        address: WOTS address (type WOTS, keypair set)

    Returns: dict with 'chains' (SPX_WOTS_LEN=32 felt252 sig values) and 'counter' (int)
    """
    # Build WOTSPK address for grinding (same as wots_addr but type WOTSPK)
    wots_pk_addr = address.copy()
    wots_pk_addr.set_type(Address.WOTSPK)

    # Grind counter until checksum constraint is satisfied
    counter, _root_digest, _msg_u32, digits = grind_wotsc_counter(pk_seed, wots_pk_addr, message_root)

    # Generate signature chains using the ground digits
    sig_chains = []
    for i in range(SPX_WOTS_LEN):
        sk = wots_sk(pk_seed, sk_seed, address, i)
        addr = address.copy()
        addr.set_type(Address.WOTS)
        addr.set_chain_addr(i)
        # Hash chain up to digit value
        sig_i = chain_hash(pk_seed, addr, sk, 0, digits[i])
        sig_chains.append(sig_i)

    return {'chains': sig_chains, 'counter': counter}


def fors_sk_leaf(pk_seed: int, sk_seed: int, address: Address, tree_idx: int, leaf_idx: int) -> int:
    """Derive FORS secret key for a leaf. Returns felt252."""
    addr = address.copy()
    addr.set_type(Address.FORSPRF)
    idx = tree_idx * SPX_FORS_BASE_OFFSET + leaf_idx
    addr.set_tree_index(idx)
    return thash(pk_seed, addr, [sk_seed])


def fors_leaf_hash(pk_seed: int, sk_seed: int, address: Address, tree_idx: int, leaf_idx: int) -> int:
    """Compute FORS leaf hash. Returns felt252."""
    sk = fors_sk_leaf(pk_seed, sk_seed, address, tree_idx, leaf_idx)
    addr = address.copy()
    addr.set_type(Address.FORSTREE)
    addr.set_tree_height(0)
    idx = tree_idx * SPX_FORS_BASE_OFFSET + leaf_idx
    addr.set_tree_index(idx)
    return thash(pk_seed, addr, [sk])


def build_fors_tree(pk_seed: int, sk_seed: int, address: Address, tree_idx: int) -> List[int]:
    """
    Build a complete FORS tree bottom-up and return it as a flat array.

    Uses 1-indexed binary heap layout:
        nodes[1] = root
        nodes[num_leaves .. 2*num_leaves-1] = leaves
        parent of nodes[i] = nodes[i >> 1]
        children of nodes[i] = nodes[2*i], nodes[2*i+1]

    Returns: list of length 2*num_leaves (index 0 unused)
    """
    num_leaves = 1 << SPX_FORS_HEIGHT  # 32768
    nodes = [0] * (2 * num_leaves)
    base = tree_idx * SPX_FORS_BASE_OFFSET

    # Step 1: compute all leaves
    for i in range(num_leaves):
        nodes[num_leaves + i] = fors_leaf_hash(pk_seed, sk_seed, address, tree_idx, i)

    # Step 2: build internal nodes bottom-up
    for h in range(1, SPX_FORS_HEIGHT + 1):
        # Nodes at this height span indices [num_leaves >> h .. (num_leaves >> h)*2 - 1]
        level_start = num_leaves >> h
        level_end = level_start * 2
        for i in range(level_start, level_end):
            left = nodes[2 * i]
            right = nodes[2 * i + 1]

            addr = address.copy()
            addr.set_type(Address.FORSTREE)
            addr.set_tree_height(h)
            # tree_index: the leaf range start for this node is (i - level_start) * (1 << h)
            leaf_start = (i - level_start) * (1 << h)
            addr.set_tree_index((base >> h) + (leaf_start >> h))

            nodes[i] = thash(pk_seed, addr, [left, right])

    return nodes


def fors_extract_auth_path(nodes: List[int], leaf_idx: int) -> List[int]:
    """Extract auth path from a precomputed FORS tree. O(height), no hashing."""
    num_leaves = 1 << SPX_FORS_HEIGHT
    auth = []
    idx = num_leaves + leaf_idx
    for _ in range(SPX_FORS_HEIGHT):
        sibling = idx ^ 1
        auth.append(nodes[sibling])
        idx >>= 1
    return auth


def fors_pk_from_trees(pk_seed: int, address: Address, roots: List[int]) -> int:
    """Compute FORS public key from precomputed tree roots. Returns felt252."""
    addr = address.copy()
    addr.set_type(Address.FORSPK)
    return thash(pk_seed, addr, roots)

def message_to_indices(mhash: int) -> List[int]:
    """
    Convert FORS message hash to leaf indices (SPX_FORS_HEIGHT=15 bits each, k=9 indices).
    Must match Cairo's message_to_indices_128s exactly.

    Args:
        mhash: 17-byte value packed into an int (from split_digest)
    """
    mhash_words = []
    # 1st tree gets the highest 15 bits, 2nd gets next 15 bits
    for i in range(SPX_FORS_TREES):
        shift = (SPX_FORS_TREES - 1 - i) * SPX_FORS_HEIGHT + 1 # this ensures we include the top bit
        word = (mhash >> shift) & ((1 << SPX_FORS_HEIGHT) - 1)
        mhash_words.append(word)

    return mhash_words


def fors_sign_and_pk(pk_seed: int, sk_seed: int, mhash: int, address: Address) -> tuple:
    """
    Generate FORS signature and public key using bottom-up tree building.
    Builds each tree once and extracts both auth paths and roots from it.

    Args:
        mhash: 17-byte value packed into an int (from split_digest)

    Returns: (tree_sigs, fors_root) where tree_sigs is list of (sk, auth_path) tuples
    """
    indices = message_to_indices(mhash)

    tree_sigs = []
    roots = []
    for tree_idx in range(SPX_FORS_TREES):
        leaf_idx = indices[tree_idx]

        # Build the entire tree once
        nodes = build_fors_tree(pk_seed, sk_seed, address, tree_idx)

        # Extract root (index 1 in 1-indexed heap)
        roots.append(nodes[1])

        # Extract secret key for the signed leaf
        sk = fors_sk_leaf(pk_seed, sk_seed, address, tree_idx, leaf_idx)

        # Extract auth path from precomputed tree (no hashing!)
        auth = fors_extract_auth_path(nodes, leaf_idx)

        tree_sigs.append((sk, auth))

    # Compute FORS public key from the roots
    fors_root = fors_pk_from_trees(pk_seed, address, roots)

    return tree_sigs, fors_root


def build_ht_layer(pk_seed: int, sk_seed: int, address: Address) -> List[int]:
    """
    Build a complete hypertree layer bottom-up and return as a flat array.

    Uses 1-indexed binary heap layout (same as build_fors_tree):
        nodes[1] = root
        nodes[num_leaves .. 2*num_leaves-1] = leaves (compressed WOTS PKs)

    Returns: list of length 2*num_leaves (index 0 unused)
    """
    num_leaves = 1 << SPX_TREE_HEIGHT  # 2048
    nodes = [0] * (2 * num_leaves)

    # Step 1: compute all leaves (each is a compressed WOTS PK)
    for i in range(num_leaves):
        addr = address.copy()
        addr.set_keypair(i)
        nodes[num_leaves + i] = wots_pk_compressed(pk_seed, sk_seed, addr)

    # Step 2: build internal nodes bottom-up
    for h in range(1, SPX_TREE_HEIGHT + 1):
        level_start = num_leaves >> h
        level_end = level_start * 2
        for i in range(level_start, level_end):
            left = nodes[2 * i]
            right = nodes[2 * i + 1]

            addr = address.copy()
            addr.set_type(Address.HASHTREE)
            addr.set_tree_height(h)
            # The leaf range start for node i at this height
            leaf_start = (i - level_start) * (1 << h)
            addr.set_tree_index(leaf_start >> h)
            addr.set_keypair(0)

            nodes[i] = thash(pk_seed, addr, [left, right])

    return nodes


def ht_extract_auth_path(nodes: List[int], leaf_idx: int) -> List[int]:
    """Extract auth path from a precomputed hypertree layer. O(height), no hashing."""
    num_leaves = 1 << SPX_TREE_HEIGHT
    auth = []
    idx = num_leaves + leaf_idx
    for _ in range(SPX_TREE_HEIGHT):
        sibling = idx ^ 1
        auth.append(nodes[sibling])
        idx >>= 1
    return auth


def wordarray_to_felt252_list(message_u32: List[int], last_word: int = 0, last_num_bytes: int = 0) -> List[int]:
    """
    Convert WordArray (u32 words) to felt252 list, matching Cairo's WordSpan.into_felt252().

    Each full u32 word is cast directly to felt252.
    The last partial word is shifted left to align to the MSB.
    """
    result = [w for w in message_u32]  # Each u32 becomes a felt252

    if last_num_bytes == 1:
        result.append(last_word * 0x1000000)
    elif last_num_bytes == 2:
        result.append(last_word * 0x10000)
    elif last_num_bytes == 3:
        result.append(last_word * 0x100)

    return result


def hash_message(randomizer: int, pk_seed: int, pk_root: int,
                 message_u32: List[int], last_word: int = 0, last_num_bytes: int = 0) -> int:
    """
    Hash message to get extended digest.
    Matches Cairo's hash_message_128s in hasher.cairo:68-99.

    The message is a WordArray of u32 words. Cairo converts them to felt252 via
    into_felt252() before Poseidon-hashing.

    Returns: felt252
    """
    # Convert u32 words to felt252 list (matching Cairo's WordSpan.into_felt252())
    msg_felts = wordarray_to_felt252_list(message_u32, last_word, last_num_bytes)

    # First stage: Hash(randomizer || pk_seed || pk_root || message_felts)
    seed = poseidon_hash([randomizer, pk_seed, pk_root] + msg_felts)

    # Second stage (MGF1): Hash(randomizer || pk_seed || seed || 0)
    expanded = poseidon_hash([randomizer, pk_seed, seed, 0])

    return expanded


def derive_seeds(rng_seed: int) -> tuple:
    """Derive sk_seed and pk_seed deterministically from rng_seed."""
    sk_seed = poseidon_hash([rng_seed, 1])
    pk_seed = poseidon_hash([rng_seed, 2])
    return sk_seed, pk_seed


def message_to_wordarray_felts(message_u32: List[int], last_word: int = 0, last_num_bytes: int = 0) -> List[int]:
    """
    Serialize a message (list of u32 words) to WordArray Serde format for Cairo deserialization.

    WordArray { input: Array<u32>, last_input_word: u32, last_input_num_bytes: u32 }
    Cairo Serde for Array<u32>: [length, elem0, elem1, ...]
    Then last_input_word and last_input_num_bytes follow.

    Returns: [array_len, ...u32_elements, last_word, last_num_bytes]
    """
    result = []
    result.append(len(message_u32))   # Array length
    result.extend(message_u32)         # u32 word elements
    result.append(last_word)           # last_input_word (u32)
    result.append(last_num_bytes)      # last_input_num_bytes (u32)
    return result


def split_digest(digest: int) -> tuple:
    """
    Split extended digest into mhash, tree_addr, leaf_idx.
    Must match Cairo's split_xdigest_128s in sphincs.cairo.

    For sphincs-poseidon+c params (SPX_DGST_BYTES = 22 bytes = 176 bits):
      Digest layout (from LSB):
        bits  0-10  : leaf_idx       (SPX_LEAF_BITS = 11)
        bits 11-15  : unused         (SPX_LEAF_BYTES*8 - SPX_LEAF_BITS = 5)
        bits 16-37  : tree_address   (SPX_TREE_BITS = 22)
        bits 38-39  : unused         (SPX_TREE_BYTES*8 - SPX_TREE_BITS = 2)
        bits 40-175 : mhash          (SPX_FORS_MSG_BYTES = 17 bytes = 136 bits)

      In the 8 u32 words [a,b,c,d,e,f,g,h] (a=MSB, h=LSB):
        a = 0, b = 0  (zero, beyond 176-bit digest)
        c < 2^16      (only lower 16 bits used, holds mhash bytes 15-16)
        d             (mhash bytes 11-14)
        e             (mhash bytes 7-10)
        f             (mhash bytes 3-6)
        g[8:32]       (mhash bytes 0-2)
        g[6:8]        (2 unused tree bits)
        g[0:6]        (tree_address bits 16-21, upper 6 bits)
        h[16:32]      (tree_address bits  0-15, lower 16 bits)
        h[11:16]      (5 unused leaf bits)
        h[0:11]       (leaf_idx)

    Returns: (mhash: int, tree_addr: int, leaf_idx: int)
      where mhash is the 17-byte value packed into an int:
    """
    # Convert to u32 array (big-endian): a = MSB word, h = LSB word
    def felt252_to_u32_array_be(value: int) -> List[int]:
        u256_val = value & ((1 << 256) - 1)
        result = []
        for _ in range(8):
            result.append((u256_val >> 224) & 0xFFFFFFFF)
            u256_val <<= 32
        return result

    arr = felt252_to_u32_array_be(digest)
    _a, _b, c, d, e, f, g, h = arr

    # --- leaf_idx: lower 11 bits of h (SPX_LEAF_BITS=11, divisor=2^11=0x800) ---
    leaf_idx = h & 0x7FF
    h_rem = h >> 11

    # h_rem = h[11:32] (21 bits). Skip h[11:16] (5 unused bits).
    # h_tree = h[16:32] = lower 16 bits of tree_address.
    h_tree = h_rem >> 5  # drop 5 bits → bits 16-31 of h

    # --- tree_address: 22 bits spanning g[0:6] and h[16:32] ---
    # g[0:6] = upper 6 bits of tree_address
    g_tree = g & 0x3F       # lower 6 bits = tree_address upper bits
    g_div = g >> 6           # g[6:32]
    # Skip g[6:8] (2 unused bits)
    g_mhash = g_div >> 2     # g[8:32] = 24 bits, 3 mhash bytes

    tree_address = (g_tree << 16) | h_tree

    mhash = g_mhash + f * (1 << 24) + e * (1 << 56) + d * (1 << 88) + (c % 0x10000) * (1 << 120)
    return mhash, tree_address, leaf_idx


class SphincsPoseidonSigner:
    """Complete SPHINCS+ Poseidon signer with WOTS+C (counter grinding)."""

    def __init__(self, sk_seed: int, pk_seed: int, pk_root: int = None):
        self.sk_seed = sk_seed
        self.pk_seed = pk_seed

        if pk_root is not None:
            self.pk_root = pk_root
        else:
            # Compute public key root
            print("Computing public key root (this may take a while)...", file=sys.stderr)
            self.pk_root = self._compute_pk_root()
            print(f"Public key root: {hex(self.pk_root)}", file=sys.stderr)

    def _compute_pk_root(self) -> int:
        """Compute the top-level root of the hypertree. Returns felt252."""
        addr = Address()
        addr.set_layer(SPX_D - 1)
        addr.set_tree_addr(0)
        nodes = build_ht_layer(self.pk_seed, self.sk_seed, addr)
        return nodes[1]  # root

    def sign(self, message_u32: List[int], last_word: int = 0, last_num_bytes: int = 0,
             quiet: bool = False) -> dict:
        """Sign a message with full SPHINCS+ signature.

        Args:
            message_u32: Message as list of u32 words (matching WordArray.input)
            last_word: Last partial word (matching WordArray.last_input_word)
            last_num_bytes: Number of valid bytes in last_word (matching WordArray.last_input_num_bytes)
            quiet: If True, suppress per-layer progress output
        """
        # Generate randomizer (deterministic for reproducibility)
        # Use the same felt252 representation that Cairo uses for hashing
        msg_felts = wordarray_to_felt252_list(message_u32, last_word, last_num_bytes)
        randomizer = poseidon_hash([self.sk_seed] + msg_felts)

        # Hash message to get extended digest
        digest = hash_message(randomizer, self.pk_seed, self.pk_root,
                              message_u32, last_word, last_num_bytes)
        mhash, tree_addr, leaf_idx = split_digest(digest)

        if not quiet:
            print(f"Message digest: tree_addr={tree_addr}, leaf_idx={leaf_idx}, message_hash={hex(mhash)}", file=sys.stderr)

        # FORS address
        fors_addr = Address()
        fors_addr.set_layer(0)
        fors_addr.set_tree_addr(tree_addr)
        fors_addr.set_type(Address.FORSTREE)
        fors_addr.set_keypair(leaf_idx)

        # Generate FORS signature and public key in one pass (builds each tree once)
        if not quiet:
            print("Generating FORS signature...", file=sys.stderr)
        fors_sig, fors_root = fors_sign_and_pk(self.pk_seed, self.sk_seed, mhash, fors_addr)
        if not quiet:
            print(f"FORS root: {hex(fors_root)}", file=sys.stderr)

        # WOTS signatures for each hypertree layer
        wots_sigs = []
        current_tree_addr = tree_addr
        current_leaf_idx = leaf_idx
        current_root = fors_root  # Message for layer 0

        for layer in range(SPX_D):
            if not quiet:
                print(f"Layer {layer}: tree_addr={current_tree_addr}, leaf_idx={current_leaf_idx}", file=sys.stderr)

            # Address for this layer
            addr = Address()
            addr.set_layer(layer)
            addr.set_tree_addr(current_tree_addr)
            addr.set_keypair(current_leaf_idx)
            addr.set_type(Address.WOTS)

            # Sign with WOTS+C (grinding over counter, no checksum chains)
            wotsc_result = wots_sign_wotsc(self.pk_seed, self.sk_seed, current_root, addr)

            if not quiet:
                print(f"  WOTS+C counter={wotsc_result['counter']}", file=sys.stderr)

            # Build the entire hypertree layer once (gets both auth path and root)
            addr.set_type(Address.HASHTREE)
            ht_nodes = build_ht_layer(self.pk_seed, self.sk_seed, addr)

            # Extract auth path from precomputed tree (no hashing!)
            auth_path = ht_extract_auth_path(ht_nodes, current_leaf_idx)

            wots_sigs.append({
                'chains': wotsc_result['chains'],
                'counter': wotsc_result['counter'],
                'auth_path': auth_path
            })

            # Extract root for next iteration (already computed!)
            if layer < SPX_D - 1:
                current_root = ht_nodes[1]  # root
                current_leaf_idx = current_tree_addr & ((1 << SPX_TREE_HEIGHT) - 1)
                current_tree_addr >>= SPX_TREE_HEIGHT

        return {
            'randomizer': randomizer,
            'fors_sig': fors_sig,
            'wots_sigs': wots_sigs
        }


def _sign_worker(sk_seed, pk_seed, pk_root, message_u32, last_word, last_num_bytes, index):
    """Worker function for parallel signature generation."""
    signer = SphincsPoseidonSigner(sk_seed, pk_seed, pk_root=pk_root)
    sig = signer.sign(message_u32, last_word, last_num_bytes, quiet=True)
    return index, sig


def serialize_test_vector(sig: dict, pk_seed: int, pk_root: int,
                          message_u32: List[int], last_word: int = 0, last_num_bytes: int = 0) -> List[int]:
    """
    Serialize to flat array format for Cairo Serde deserialization.
    Matches sphincs-btc serialization pattern.

    Returns: List[int] (felt252 values to be hex-encoded for JSON)
    """
    result = []

    # === Public key ===
    result.append(pk_seed)     # felt252
    result.append(pk_root)      # felt252

    # === Signature ===
    result.append(sig['randomizer'])  # felt252

    # FORS signature: SPX_FORS_TREES=9 trees * (sk + SPX_FORS_HEIGHT=15 auth_path entries)
    for sk, auth in sig['fors_sig']:
        result.append(sk)      # felt252
        result.extend(auth)    # SPX_FORS_HEIGHT felt252 values

    # WOTS+C Merkle signatures: SPX_D=3 layers
    for wots_sig in sig['wots_sigs']:
        # SPX_WOTS_LEN=32 chains (no checksum chains in WOTS+C)
        result.extend(wots_sig['chains'])    # 32 felt252 values
        result.append(wots_sig['counter'])   # counter (felt252)
        # SPX_TREE_HEIGHT=11 auth path entries
        result.extend(wots_sig['auth_path'])  # 11 felt252 values

    # === Message as WordArray (u32 words) ===
    result.extend(message_to_wordarray_felts(message_u32, last_word, last_num_bytes))

    return result


def serialize_multi_sig_vector(sigs: list, pk_seed: int, pk_root: int, messages: list) -> List[int]:
    """Serialize multiple signatures to Cairo-compatible format for MultiSigArgs."""
    result = []

    # === Public key (shared for all signatures) ===
    result.append(pk_seed)   # felt252
    result.append(pk_root)   # felt252

    # === Number of signatures ===
    result.append(len(sigs))

    # === Each (signature, message) pair ===
    for sig, (msg_u32, last_word, last_num_bytes) in zip(sigs, messages):
        # Signature
        result.append(sig['randomizer'])  # felt252

        # FORS signature: SPX_FORS_TREES=9 trees * (sk + SPX_FORS_HEIGHT=15 auth_path entries)
        for sk, auth in sig['fors_sig']:
            result.append(sk)      # felt252
            result.extend(auth)    # SPX_FORS_HEIGHT felt252 values

        # WOTS+C Merkle signatures: SPX_D=3 layers
        for wots_sig in sig['wots_sigs']:
            result.extend(wots_sig['chains'])    # 32 felt252 values
            result.append(wots_sig['counter'])   # counter (felt252)
            result.extend(wots_sig['auth_path'])  # 11 felt252 values

        # Message as WordArray
        result.extend(message_to_wordarray_felts(msg_u32, last_word, last_num_bytes))

    return result


def main():
    """Generate SPHINCS+ Poseidon test vectors."""
    parser = argparse.ArgumentParser(
        description="Generate SPHINCS+ Poseidon test vectors with multi-signature support"
    )
    parser.add_argument(
        '--num-signatures', '-n',
        type=int,
        default=1,
        help='Number of signatures to generate (default: 1)'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=0,
        help='RNG seed for deterministic generation (default: 0)'
    )
    parser.add_argument(
        '--message-prefix',
        default='test',
        help='Prefix for generated messages (default: "test")'
    )
    parser.add_argument(
        '--output', '-o',
        default=None,
        help='Output file (default: stdout)'
    )
    parser.add_argument(
        '--workers', '-w',
        type=int,
        default=None,
        help='Number of parallel workers (default: cpu_count for multi-sig, 1 for single)'
    )
    args = parser.parse_args()

    if args.workers is None:
        args.workers = os.cpu_count() if args.num_signatures > 1 else 1

    print("=== SPHINCS+ Poseidon Test Vector Generator ===", file=sys.stderr)
    print(f"Parameters: h={SPX_FULL_HEIGHT}, d={SPX_D}, k={SPX_FORS_TREES}, a={SPX_FORS_HEIGHT}, w={SPX_WOTS_W}", file=sys.stderr)
    print(f"Number of signatures: {args.num_signatures}", file=sys.stderr)
    print(f"RNG seed: {args.seed}", file=sys.stderr)

    # Derive seeds deterministically
    sk_seed, pk_seed = derive_seeds(args.seed)
    print(f"\nSecret seed: {hex(sk_seed)}", file=sys.stderr)
    print(f"Public seed: {hex(pk_seed)}", file=sys.stderr)

    # Create signer
    signer = SphincsPoseidonSigner(sk_seed, pk_seed)

    # Prepare messages
    messages = []
    for i in range(args.num_signatures):
        # Convert message string to u32 words for WordArray representation.
        # Each character becomes a byte, packed into big-endian u32 words.
        message_str = f"{args.message_prefix}{i}"
        message_bytes = message_str.encode('ascii')

        # Pack bytes into u32 words (big-endian, 4 bytes per word)
        message_u32 = []
        full_words = len(message_bytes) // 4
        for j in range(full_words):
            w = (message_bytes[j*4] << 24) | (message_bytes[j*4+1] << 16) | \
                (message_bytes[j*4+2] << 8) | message_bytes[j*4+3]
            message_u32.append(w)

        # Handle remaining bytes as last_word
        remaining = len(message_bytes) % 4
        last_word = 0
        for j in range(remaining):
            last_word = (last_word << 8) | message_bytes[full_words * 4 + j]
        last_num_bytes = remaining

        messages.append((message_u32, last_word, last_num_bytes))

    # Generate signatures
    if args.workers <= 1 or args.num_signatures == 1:
        # Sequential (preserves progress output)
        sigs = []
        for i, (msg_u32, last_word, last_num_bytes) in enumerate(messages):
            print(f"\nSigning message {i+1}/{args.num_signatures}: {args.message_prefix}{i}", file=sys.stderr)
            sig = signer.sign(msg_u32, last_word, last_num_bytes)
            sigs.append(sig)
    else:
        # Parallel
        print(f"\nSigning {args.num_signatures} messages using {args.workers} workers...", file=sys.stderr)
        sigs = [None] * args.num_signatures
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    _sign_worker, sk_seed, pk_seed, signer.pk_root,
                    msg_u32, last_word, last_num_bytes, i
                ): i
                for i, (msg_u32, last_word, last_num_bytes) in enumerate(messages)
            }
            for future in as_completed(futures):
                idx, sig = future.result()
                sigs[idx] = sig
                print(f"  Completed signature {idx+1}/{args.num_signatures}", file=sys.stderr)

    # Serialize
    if args.num_signatures == 1:
        msg_u32, msg_last_word, msg_last_num_bytes = messages[0]
        result = serialize_test_vector(sigs[0], pk_seed, signer.pk_root,
                                       msg_u32, msg_last_word, msg_last_num_bytes)
    else:
        result = serialize_multi_sig_vector(sigs, pk_seed, signer.pk_root, messages)

    print(f"\nTotal elements: {len(result)}", file=sys.stderr)
    print(f"Signature(s) generated successfully!", file=sys.stderr)

    # Output as JSON array of hex strings
    hex_values = [hex(v) for v in result]
    output_data = json.dumps(hex_values)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_data)
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output_data)


if __name__ == "__main__":
    main()
