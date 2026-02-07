#!/usr/bin/env python3
"""
Generate valid test vectors for SPHINCS+ with Poseidon hash.

This implementation uses field elements (felt252) instead of bytes,
matching the Cairo Poseidon implementation.

Parameters (matching params_128s.cairo):
- h=63 (total height)
- d=7 (hypertree layers)
- tree_height=9 (per subtree)
- k=14 (FORS trees)
- a=12 (FORS height)
- w=16 (WOTS parameter)
- hash=Poseidon (arithmetic-friendly)
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
SPX_FULL_HEIGHT = 63
SPX_D = 7
SPX_TREE_HEIGHT = 9  # SPX_FULL_HEIGHT / SPX_D
SPX_FORS_HEIGHT = 12
SPX_FORS_TREES = 14
SPX_FORS_BASE_OFFSET = 1 << SPX_FORS_HEIGHT  # 4096
SPX_FORS_MSG_BYTES = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) // 8  # 21
SPX_TREE_BITS = SPX_TREE_HEIGHT * (SPX_D - 1)  # 54
SPX_LEAF_BITS = SPX_TREE_HEIGHT  # 9
SPX_DGST_BYTES = SPX_FORS_MSG_BYTES + (SPX_TREE_BITS + 7) // 8 + (SPX_LEAF_BITS + 7) // 8  # 30
SPX_WOTS_W = 16
SPX_WOTS_LOGW = 4
SPX_WOTS_LEN1 = 8 * SPX_N // SPX_WOTS_LOGW  # 32
SPX_WOTS_LEN2 = 3  # checksum length
SPX_WOTS_LEN = SPX_WOTS_LEN1 + SPX_WOTS_LEN2  # 35

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


def compute_checksum(msg_base_w: List[int]) -> List[int]:
    """
    Compute WOTS checksum in base-w.
    Matches Cairo's wots_pk_from_sig checksum computation.
    """
    csum = 0
    for digit in msg_base_w:
        csum += (SPX_WOTS_W - 1) - digit

    # Convert checksum to base-w (SPX_WOTS_LEN2 = 3 digits for W=16)
    # Must match Cairo's big-endian nibble order: [e, f, g] for csum = 0xefg
    e = csum // 0x100
    fg = csum % 0x100
    f = fg // 0x10
    g = fg % 0x10

    return [e, f, g]


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


def wots_sign(pk_seed: int, sk_seed: int, message_root: int, address: Address) -> List[int]:
    """
    Sign with WOTS using standard W=16 with checksum.

    Args:
        message_root: felt252 value to sign

    Returns: list of SPX_WOTS_LEN=35 felt252 signature values
    """
    # Convert message to u32 array (little-endian)
    msg_u32 = felt252_to_u32_array(message_root)

    # Convert to base-w
    msg_base_w = base_w_128s(msg_u32)

    # Compute checksum
    checksum = compute_checksum(msg_base_w)

    # Full message with checksum
    digits = msg_base_w + checksum

    # Generate signature chains
    sig_chains = []
    for i in range(SPX_WOTS_LEN):
        sk = wots_sk(pk_seed, sk_seed, address, i)
        addr = address.copy()
        addr.set_type(Address.WOTS)
        addr.set_chain_addr(i)
        # Hash chain up to digit value
        sig_i = chain_hash(pk_seed, addr, sk, 0, digits[i])
        sig_chains.append(sig_i)

    return sig_chains


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


def fors_treehash(pk_seed: int, sk_seed: int, address: Address,
                  tree_idx: int, start_idx: int, height: int) -> int:
    """Compute FORS subtree root using treehash. Returns felt252."""
    if height == 0:
        return fors_leaf_hash(pk_seed, sk_seed, address, tree_idx, start_idx)

    left = fors_treehash(pk_seed, sk_seed, address, tree_idx, start_idx, height - 1)
    right = fors_treehash(pk_seed, sk_seed, address, tree_idx, start_idx + (1 << (height - 1)), height - 1)

    addr = address.copy()
    addr.set_type(Address.FORSTREE)
    addr.set_tree_height(height)
    base = tree_idx * SPX_FORS_BASE_OFFSET
    addr.set_tree_index((base >> height) + (start_idx >> height))

    return thash(pk_seed, addr, [left, right])


def fors_gen_auth(pk_seed: int, sk_seed: int, address: Address,
                  tree_idx: int, leaf_idx: int) -> List[int]:
    """Generate FORS authentication path for a leaf. Returns list of felt252."""
    auth = []
    for h in range(SPX_FORS_HEIGHT):
        sibling_idx = (leaf_idx >> h) ^ 1
        start = sibling_idx << h
        node = fors_treehash(pk_seed, sk_seed, address, tree_idx, start, h)
        auth.append(node)
    return auth


def fors_tree_root(pk_seed: int, sk_seed: int, address: Address, tree_idx: int) -> int:
    """Compute root of a single FORS tree. Returns felt252."""
    return fors_treehash(pk_seed, sk_seed, address, tree_idx, 0, SPX_FORS_HEIGHT)


def fors_pk(pk_seed: int, sk_seed: int, address: Address) -> int:
    """Compute FORS public key (hash of all tree roots). Returns felt252."""
    roots = []
    for tree_idx in range(SPX_FORS_TREES):
        root = fors_tree_root(pk_seed, sk_seed, address, tree_idx)
        roots.append(root)

    addr = address.copy()
    addr.set_type(Address.FORSPK)
    return thash(pk_seed, addr, roots)


def mhash_felt_to_wordspan(mhash_felt: int) -> List[tuple]:
    """
    Convert mhash felt252 to WordSpan representation: list of (word, num_bytes) pairs.
    Matches Cairo's split_xdigest_128s output format.

    The mhash is 21 bytes = 5 full u32 words (big-endian) + 1 trailing byte.
    """
    # Convert felt252 to 21 big-endian bytes
    mhash_bytes = mhash_felt.to_bytes(SPX_FORS_MSG_BYTES, byteorder='big')

    words = []
    full_words = len(mhash_bytes) // 4  # 5
    for i in range(full_words):
        w = (mhash_bytes[i*4] << 24) | (mhash_bytes[i*4+1] << 16) | \
            (mhash_bytes[i*4+2] << 8) | mhash_bytes[i*4+3]
        words.append((w, 4))

    remaining = len(mhash_bytes) % 4  # 1
    if remaining > 0:
        last_word = 0
        for j in range(remaining):
            last_word = (last_word << 8) | mhash_bytes[full_words * 4 + j]
        words.append((last_word, remaining))

    return words


def message_to_indices(mhash_felt: int) -> List[int]:
    """
    Convert FORS message hash (felt252) to leaf indices (12 bits each, k=14 indices).
    Must match Cairo's message_to_indices_128s exactly.

    Cairo processes WordSpan words in order, but reverses bytes within each u32 word
    to get little-endian byte order, then extracts 12-bit indices from that stream.
    """
    wordspan = mhash_felt_to_wordspan(mhash_felt)

    indices = []
    acc = 0
    acc_bits = 0

    for word, num_bytes in wordspan:
        if num_bytes == 4:
            # Decompose BE word [ab cd ef gh] into bytes
            ab = (word >> 24) & 0xFF
            cd = (word >> 16) & 0xFF
            ef = (word >> 8) & 0xFF
            gh = word & 0xFF

            if acc_bits == 0:
                c = cd >> 4
                d = cd & 0xF
                indices.append(d * 0x100 + ab)
                indices.append(ef * 0x10 + c)
                acc = gh
                acc_bits = 8
            elif acc_bits == 8:
                a = ab >> 4
                b = ab & 0xF
                g = gh >> 4
                h = gh & 0xF
                indices.append(b * 0x100 + acc)
                indices.append(cd * 0x10 + a)
                indices.append(h * 0x100 + ef)
                acc = g
                acc_bits = 4
            elif acc_bits == 4:
                e = ef >> 4
                f = ef & 0xF
                indices.append(ab * 0x10 + acc)
                indices.append(f * 0x100 + cd)
                indices.append(gh * 0x10 + e)
                acc = 0
                acc_bits = 0
        elif num_bytes == 1:
            assert acc_bits == 4, f'invalid acc_bits ({acc_bits}) for last byte'
            indices.append(word * 0x10 + acc)

    return indices


def fors_sign(pk_seed: int, sk_seed: int, mhash: int, address: Address) -> List[tuple]:
    """
    Generate FORS signature.

    Args:
        mhash: felt252 message hash

    Returns: list of (sk, auth_path) tuples, each element is felt252
    """
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


def ht_leaf(pk_seed: int, sk_seed: int, address: Address, leaf_idx: int) -> int:
    """Compute hypertree leaf (compressed WOTS pk). Returns felt252."""
    addr = address.copy()
    addr.set_keypair(leaf_idx)
    return wots_pk_compressed(pk_seed, sk_seed, addr)


def ht_treehash(pk_seed: int, sk_seed: int, address: Address,
                start_idx: int, height: int) -> int:
    """Compute subtree root. Returns felt252."""
    if height == 0:
        return ht_leaf(pk_seed, sk_seed, address, start_idx)

    left = ht_treehash(pk_seed, sk_seed, address, start_idx, height - 1)
    right = ht_treehash(pk_seed, sk_seed, address, start_idx + (1 << (height - 1)), height - 1)

    addr = address.copy()
    addr.set_type(Address.HASHTREE)
    addr.set_tree_height(height)
    addr.set_tree_index(start_idx >> height)
    addr.set_keypair(0)

    return thash(pk_seed, addr, [left, right])


def ht_gen_auth(pk_seed: int, sk_seed: int, address: Address, leaf_idx: int) -> List[int]:
    """Generate authentication path for hypertree layer. Returns list of felt252."""
    auth = []
    for h in range(SPX_TREE_HEIGHT):
        sibling_idx = (leaf_idx >> h) ^ 1
        start = sibling_idx << h
        node = ht_treehash(pk_seed, sk_seed, address, start, h)
        auth.append(node)
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
    Must match Cairo's split_xdigest_128s in sphincs.cairo:117-147.

    Returns: (mhash: felt252, tree_addr: int, leaf_idx: int)
    """
    # Convert to u32 array (big-endian)
    def felt252_to_u32_array_be(value: int) -> List[int]:
        # Convert to u256 first
        u256_val = value & ((1 << 256) - 1)
        result = []
        for _ in range(8):
            result.append((u256_val >> 224) & 0xFFFFFFFF)
            u256_val <<= 32
        return result

    arr = felt252_to_u32_array_be(digest)
    a, b, c, d, e, f, g, h = arr

    # Work backwards from least significant bits
    # Take last 9 bits from h as leaf index
    leaf_idx = h & 0x1FF
    h_rem = h >> 9

    # Take next 54 bits as tree address from h, g, f
    # h[16:32] + g[0:32] + f[0:6] = 54 bits
    f_mod = f & 0x3F  # 6 bits
    tree_address = (h_rem // 0x80) + (g * 0x10000) + (f_mod * 0x1000000000000)

    # f[8:32] + e + d + c + b + a[0:16] = message hash (21 bytes)
    a_mod = a & 0xFFFF

    # Reconstruct mhash as felt252
    # Take bits: a[0:16] + b + c + d + e + f[6:32]
    f_hi = f >> 8  # upper 24 bits of f
    e_full = e
    d_full = d
    c_full = c
    b_full = b
    a_lo = a_mod

    # Build 21-byte (168-bit) value
    mhash = (a_lo << 152) | (b_full << 120) | (c_full << 88) | (d_full << 56) | (e_full << 24) | f_hi

    return mhash, tree_address, leaf_idx


class SphincsPoseidonSigner:
    """Complete SPHINCS+ Poseidon signer (no grinding, standard WOTS+)."""

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
        return ht_treehash(self.pk_seed, self.sk_seed, addr, 0, SPX_TREE_HEIGHT)

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
            print(f"Message digest: tree_addr={tree_addr}, leaf_idx={leaf_idx}", file=sys.stderr)

        # FORS address
        fors_addr = Address()
        fors_addr.set_layer(0)
        fors_addr.set_tree_addr(tree_addr)
        fors_addr.set_type(Address.FORSTREE)
        fors_addr.set_keypair(leaf_idx)

        # Generate FORS signature
        if not quiet:
            print("Generating FORS signature...", file=sys.stderr)
        fors_sig = fors_sign(self.pk_seed, self.sk_seed, mhash, fors_addr)

        # Compute FORS public key (this is what layer 0 WOTS signs)
        fors_root = fors_pk(self.pk_seed, self.sk_seed, fors_addr)
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

            # Sign with WOTS (standard W=16 with checksum)
            sig_chains = wots_sign(self.pk_seed, self.sk_seed, current_root, addr)

            # Generate auth path for this layer
            addr.set_type(Address.HASHTREE)
            auth_path = ht_gen_auth(self.pk_seed, self.sk_seed, addr, current_leaf_idx)

            wots_sigs.append({
                'chains': sig_chains,
                'auth_path': auth_path
            })

            # Compute this layer's root for next iteration
            if layer < SPX_D - 1:
                current_root = ht_treehash(self.pk_seed, self.sk_seed, addr, 0, SPX_TREE_HEIGHT)
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

    # FORS signature: 14 trees * (sk + 12 auth_path entries)
    for sk, auth in sig['fors_sig']:
        result.append(sk)      # felt252
        result.extend(auth)    # 12 felt252 values

    # WOTS Merkle signatures: 7 layers
    for wots_sig in sig['wots_sigs']:
        # 35 chains (SPX_WOTS_LEN = 35)
        result.extend(wots_sig['chains'])  # 35 felt252 values
        # 9 auth path entries (SPX_TREE_HEIGHT = 9)
        result.extend(wots_sig['auth_path'])  # 9 felt252 values

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

        # FORS signature: 14 trees * (sk + 12 auth_path entries)
        for sk, auth in sig['fors_sig']:
            result.append(sk)      # felt252
            result.extend(auth)    # 12 felt252 values

        # WOTS Merkle signatures: 7 layers
        for wots_sig in sig['wots_sigs']:
            result.extend(wots_sig['chains'])     # 35 felt252 values
            result.extend(wots_sig['auth_path'])  # 9 felt252 values

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
