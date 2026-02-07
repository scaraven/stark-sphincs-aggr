// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

// Available hash functions.
mod poseidon;
use core::hash::{HashStateExTrait, HashStateTrait};

// Poseidon backend (arithmetic-friendly).
use poseidon::{HashState, hash_finalize, hash_init};
use poseidon::{hash_finalize_1, hash_finalize_2, hash_finalize_fors_tree_root};

// Imports.
use crate::address::{Address, AddressTrait};
use crate::params_128s;
use crate::word_array::{WordSpan, WordSpanTrait};

/// Hash output.
pub type HashOutput = felt252;

/// Hash context.
#[derive(Drop, Copy, Default, Debug)]
pub struct SpxCtx {
    state_seeded: HashState,
}

/// Partially-absorbed Poseidon state for reuse across related hash calls.
/// This holds a Poseidon state that has already absorbed pk_seed and some
/// address components, allowing subsequent calls to absorb only the remaining
/// components and data, significantly reducing the number of Poseidon permutations.
#[derive(Drop, Copy)]
pub struct PartialCtx {
    pub state: HashState,
}

/// Absorb the constant pub_seed using one round of the compression function
/// This initializes `state_seeded`, which can then be reused in `thash`.
pub fn initialize_hash_function(pk_seed: HashOutput) -> SpxCtx {
    let mut state: HashState = Default::default();
    hash_init(ref state);
    state.state = state.state.update(pk_seed);
    SpxCtx { state_seeded: state }
}

/// Pre-absorb pk_seed + 4 address words (a0-a3).
/// Reusable across hash calls that share w0-w3 (e.g., within a FORS tree or Merkle tree traversal).
pub fn partial_seed_4(
    ctx: SpxCtx, a0: felt252, a1: felt252, a2: felt252, a3: felt252,
) -> PartialCtx {
    let mut state = ctx.state_seeded;
    state.state = state.state.update_with([a0, a1, a2, a3]);
    PartialCtx { state }
}

/// Pre-absorb pk_seed + 5 address words (a0-a4).
/// Reusable across hash calls that share w0-w4 (e.g., within a WOTS chain).
pub fn partial_seed_5(
    ctx: SpxCtx, a0: felt252, a1: felt252, a2: felt252, a3: felt252, a4: felt252,
) -> PartialCtx {
    let mut state = ctx.state_seeded;
    state.state = state.state.update_with([a0, a1, a2, a3]);
    state.state = state.state.update(a4);
    PartialCtx { state }
}

#[inline]
fn seed_address(ctx: SpxCtx, address: @Address) -> HashState {
    let [a0, a1, a2, a3, a4, a5] = address.into_field_components();
    let mut state = ctx.state_seeded;
    state.state = state.state.update_with([a0, a1, a2, a3, a4, a5]);
    state
}

/// Poseidon-backed thash.
pub fn thash(ctx: SpxCtx, address: @Address, data: Span<felt252>) -> HashOutput {
    let mut state = seed_address(ctx, address);
    hash_finalize(ref state, data)
}

pub fn thash_fors_tree_root(
    ctx: SpxCtx, address: @Address, data: [felt252; params_128s::SPX_FORS_TREES],
) -> HashOutput {
    let mut state = seed_address(ctx, address);
    hash_finalize_fors_tree_root(ref state, data)
}

pub fn thash_single(ctx: SpxCtx, address: @Address, data: HashOutput) -> HashOutput {
    let mut state = seed_address(ctx, address);
    hash_finalize_1(ref state, data)
}

pub fn thash_2(ctx: SpxCtx, address: @Address, data0: HashOutput, data1: HashOutput) -> HashOutput {
    let mut state = seed_address(ctx, address);
    hash_finalize_2(ref state, data0, data1)
}

/// thash_single absorbing only a5 + data.
/// Used with a PartialCtx that has already absorbed pk_seed + a0-a4.
pub fn thash_single_partial_5(pctx: PartialCtx, a5: felt252, data: HashOutput) -> HashOutput {
    let mut state = pctx.state;
    state.state = state.state.update(a5);
    hash_finalize_1(ref state, data)
}

/// thash_single absorbing a4 + a5 + data.
/// Used with a PartialCtx that has already absorbed pk_seed + a0-a3.
pub fn thash_single_partial_4(
    pctx: PartialCtx, a4: felt252, a5: felt252, data: HashOutput,
) -> HashOutput {
    let mut state = pctx.state;
    state.state = state.state.update_with([a4, a5]);
    hash_finalize_1(ref state, data)
}

/// thash_2 absorbing a4 + a5 + data0 + data1.
/// Used with a PartialCtx that has already absorbed pk_seed + a0-a3.
pub fn thash_2_partial_4(
    pctx: PartialCtx, a4: felt252, a5: felt252, data0: HashOutput, data1: HashOutput,
) -> HashOutput {
    let mut state = pctx.state;
    state.state = state.state.update_with([a4, a5]);
    hash_finalize_2(ref state, data0, data1)
}

/// Convert a felt252 to an array of 8 u32s (big-endian).
/// Note the msb u32 will have some leading zeros as felt252 is only 252 bits.
pub fn felt252_to_u32_array(value: felt252) -> [u32; 8] {
    let mut value_u256: u256 = value.into();

    // Take 32 bits at a time
    let (rem, a) = DivRem::div_rem(value_u256, 0x100000000);
    let (rem, b) = DivRem::div_rem(rem, 0x100000000);
    let (rem, c) = DivRem::div_rem(rem, 0x100000000);
    let (rem, d) = DivRem::div_rem(rem, 0x100000000);
    let (rem, e) = DivRem::div_rem(rem, 0x100000000);
    let (rem, f) = DivRem::div_rem(rem, 0x100000000);
    let (rem, g) = DivRem::div_rem(rem, 0x100000000);
    let (o, h) = DivRem::div_rem(rem, 0x100000000);

    assert(o == 0, 'felt252_to_u32_array: overflow');

    [
        h.try_into().unwrap(), g.try_into().unwrap(), f.try_into().unwrap(), e.try_into().unwrap(),
        d.try_into().unwrap(), c.try_into().unwrap(), b.try_into().unwrap(), a.try_into().unwrap(),
    ]
}

/// Hash a message using selected hash function.
pub fn hash_message_128s(
    randomizer: HashOutput, pk_seed: HashOutput, pk_root: HashOutput, message: WordSpan,
) -> felt252 {
    let mut data: Array<felt252> = array![];
    data.append(randomizer);
    data.append(pk_seed);
    data.append(pk_root);

    let msg_words = message.into_felt252();
    data.append_span(msg_words.span());

    let mut state: HashState = Default::default();
    poseidon::hash_init(ref state);

    // Compute the seed for XOF.
    let seed = poseidon::hash_finalize(ref state, data.span());

    // Apply MGF1 to the seed - optimized to avoid array allocation.
    poseidon::hash_init(ref state);
    state.state = state.state.update(randomizer);
    state.state = state.state.update(pk_seed);
    state.state = state.state.update(seed);
    state.state = state.state.update(0); // MGF1 counter = 0
    let buffer = state.state.finalize();

    buffer
}

/// Compute the root of a tree given the leaf and the authentication path.
pub fn compute_root(
    ctx: SpxCtx,
    address: @Address,
    leaf: HashOutput,
    mut auth_path: Span<HashOutput>,
    mut leaf_idx: u32,
    mut idx_offset: u32,
) -> HashOutput {
    let mut node = leaf;
    let mut i = 0;
    let mut address = address.clone();

    while let Some(hash_witness) = auth_path.pop_front() {
        let (q, r) = DivRem::div_rem(leaf_idx, 2);

        let (word0, word1) = if r == 0 {
            (node, *hash_witness)
        } else {
            (*hash_witness, node)
        };

        i += 1;
        leaf_idx = q;
        idx_offset /= 2;

        address.set_tree_height(i);
        address.set_tree_index(leaf_idx + idx_offset);

        node = thash_2(ctx, @address, word0, word1);
    }

    node
}

/// Compute the root of a tree given the leaf and authentication path,
/// using a pre-built PartialCtx that has already absorbed pk_seed + a0-a3.
/// This avoids redundant absorption when processing multiple trees with shared address prefixes.
pub fn compute_root_with_pctx(
    pctx: PartialCtx,
    address: @Address,
    leaf: HashOutput,
    mut auth_path: Span<HashOutput>,
    mut leaf_idx: u32,
    mut idx_offset: u32,
) -> HashOutput {
    let mut node = leaf;
    let mut i = 0;
    let mut address = address.clone();

    while let Some(hash_witness) = auth_path.pop_front() {
        let (q, r) = DivRem::div_rem(leaf_idx, 2);

        let (word0, word1) = if r == 0 {
            (node, *hash_witness)
        } else {
            (*hash_witness, node)
        };

        i += 1;
        leaf_idx = q;
        idx_offset /= 2;

        address.set_tree_height(i);
        address.set_tree_index(leaf_idx + idx_offset);

        let [_, _, _, _, a4, a5] = address.into_field_components();
        node = thash_2_partial_4(pctx, a4, a5, word0, word1);
    }

    node
}

/// Serialize and deserialize HashOutput.
pub impl HashOutputSerde of Serde<HashOutput> {
    fn serialize(self: @HashOutput, ref output: Array<felt252>) {
        output.append(*self)
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<HashOutput> {
        let h0: felt252 = (*serialized.pop_front().expect('h0'));
        Some(h0)
    }
}

#[cfg(or(test, feature: "debug"))]
pub fn to_hex(data: Span<u32>) -> ByteArray {
    let word_span = WordSpanTrait::new(data, 0, 0);
    crate::word_array::hex::words_to_hex(word_span)
}

#[cfg(test)]
mod tests {
    use crate::WordArrayTrait;
    use crate::address::AddressType;
    use super::{*, initialize_hash_function};

    #[test]
    fn test_felt252_to_u32_array() {
        let value: felt252 = 0x0123456890abcdef0123456890abcdef0123456890abcdef0123456890abcde;
        let arr = felt252_to_u32_array(value);
        assert_eq!(
            arr,
            [
                0x0123456, 0x890abcde, 0xf0123456, 0x890abcde, 0xf0123456, 0x890abcde, 0xf0123456,
                0x890abcde,
            ],
        );
    }

    #[test]
    fn test_hash_message_128() {
        let randomizer = 0xdeadbeef;
        let pk_seed = 0xcafebabe;
        let pk_root = 0xfeedface;

        let message = WordArrayTrait::new(array![0x11111111, 0x22222222, 0x33333333], 0, 0);
        let digest = hash_message_128s(randomizer, pk_seed, pk_root, message.span());

        assert_eq!(
            digest, 2182198415344895388480530065214389512836123652580788368776596040288394447218,
        );
    }

    #[test]
    fn test_initialize_hash_function() {
        let pk_seed = 0x1234;
        let ctx = initialize_hash_function(pk_seed);
        let mut state = ctx.state_seeded;

        state.state = state.state.update(0);
        let output_1 = state.state.finalize();

        let mut state = Default::default();
        hash_init(ref state);

        state.state = state.state.update(pk_seed);
        state.state = state.state.update(0);
        let output_2 = state.state.finalize();

        assert_eq!(output_1, output_2, "Initialized hash states do not match");
        assert_eq!(
            output_1,
            379277542665157213325042857308534457199001041868780771123009522510742340366,
            "Poseidon hash output does not match expected value",
        );
    }

    #[test]
    fn test_hash_finalize() {
        let pk_seed = 0xdeadbeef;
        let mut address: Address = Default::default();
        address.set_hypertree_layer(0x01);
        address.set_address_type(AddressType::HASHTREE);
        address.set_keypair(0x3456);

        let ctx = initialize_hash_function(pk_seed);

        let data: [felt252; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        let output = thash(ctx, @address, data.span());

        assert_eq!(
            output,
            1190188513163088186241995297500126947589582629387601832785015242379216793975,
            "Poseidon hash output does not match expected value",
        );
    }
}
