// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

// Available hash functions.
mod poseidon;
use core::hash::HashStateTrait;

// Poseidon backend (arithmetic-friendly).
pub use poseidon::hash_update_16_finalize;
use poseidon::{
    HashState, hash_init, hash_update_16, hash_update_3_finalize, hash_update_4_finalize,
    hash_update_5_finalize,
};

// Imports.
use crate::address::{Address, AddressTrait};
use crate::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};

/// Hash output.
/// This encodes a [u32; 4] as a felt252 in little-endian
pub type HashOutput = felt252;

/// Hash context.
#[derive(Drop, Copy, Default, Debug)]
pub struct SpxCtx {
    state_seeded: HashState,
}

/// Absorb the constant pub_seed using one round of the compression function
/// This initializes `state_seeded`, which can then be reused in `thash`.
pub fn initialize_hash_function(pk_seed: HashOutput) -> SpxCtx {
    let mut state: HashState = Default::default();
    hash_init(ref state);
    state.state = state.state.update(pk_seed);
    SpxCtx { state_seeded: state }
}

/// Poseidon-backed thash for 1 input field element.
pub fn thash_single(ctx: SpxCtx, address: @Address, data: felt252) -> HashOutput {
    let (a0, a1) = address.into_fields();
    let mut state = ctx.state_seeded;
    hash_update_3_finalize(ref state, [a0, a1, data])
}

/// Poseidon-backed thash for 2 input words
pub fn thash_8(ctx: SpxCtx, address: @Address, word0: felt252, word1: felt252) -> HashOutput {
    let (a0, a1) = address.into_fields();
    let mut state = ctx.state_seeded;
    hash_update_4_finalize(ref state, [a0, a1, word0, word1])
}

/// Poseidon-backed thash for FORS public key hashing.
pub fn thash_140(ctx: SpxCtx, address: @Address, mut data: Span<felt252>) -> HashOutput {
    let mut state = ctx.state_seeded;
    let (a0, a1) = address.into_fields();

    assert(data.len() == 35, 'thash_140: expected len = 35');

    // Do initial update with address fields
    if let Some(chunk) = data.multi_pop_front::<14>() {
        let [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13] = (*chunk).unbox();
        hash_update_16(
            ref state, [a0, a1, d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13],
        );
    }

    while let Some(chunk) = data.multi_pop_front::<16>() {
        let [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15] = (*chunk)
            .unbox();
        hash_update_16(
            ref state, [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15],
        );
    }

    match data.multi_pop_front::<5>() {
        Some(chunk) => {
            let [d0, d1, d2, d3, d4] = (*chunk).unbox();
            hash_update_5_finalize(ref state, [d0, d1, d2, d3, d4])
        },
        None => panic!("thash_140: unexpected data length"),
    }
}

/// Poseidon-backed thash for multiple field elements
pub fn thash_56(ctx: SpxCtx, address: @Address, mut data: Span<felt252>) -> HashOutput {
    let (a0, a1) = address.into_fields();
    let mut state = ctx.state_seeded;

    let data_len = data.len();
    assert(data_len == 14, 'thash_56: expected len = 14');

    while let Some(chunk) = data.multi_pop_front::<14>() {
        let [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13] = (*chunk).unbox();
        return hash_update_16_finalize(
            ref state, [a0, a1, d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13],
        );
    }

    panic!("thash_56: unexpected data length");
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

    [h.try_into().unwrap(), g.try_into().unwrap(), f.try_into().unwrap(), e.try_into().unwrap(), 
    d.try_into().unwrap(), c.try_into().unwrap(), b.try_into().unwrap(), a.try_into().unwrap()]
}

/// Hash a message using selected hash function.
/// Returns the extended message digest of size SPX_DGST_BYTES as a [WordArray].
/// NOTE: this is not a generic implementation, rather a shortcut for 128s.
/// As Poseidon only returns field elements, we use blake hashing here instead.
pub fn hash_message_128s(
    randomizer: HashOutput,
    pk_seed: HashOutput,
    pk_root: HashOutput,
    message: WordSpan,
    output_len: u32,
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

    let mut xof_data: Array<felt252> = array![];
    xof_data.append(randomizer);
    xof_data.append(pk_seed);
    xof_data.append(seed);
    xof_data.append(0); // MGF1 counter = 0

    // Apply MGF1 to the seed.
    let buffer = poseidon::hash_finalize(ref state, xof_data.span());

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

        node = thash_8(ctx, @address, word0, word1);
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
    use super::*;

    #[test]
    fn test_felt252_to_u32_array() {
        let value: felt252 = 0x0123456890abcdef0123456890abcdef0123456890abcdef0123456890abcde;
        let arr = felt252_to_u32_array(value);
        assert_eq!(arr, 
            [0x01234568, 0x90abcdef, 0x01234568, 0x90abcdef,
             0x01234568, 0x90abcdef, 0x01234568, 0x90abcde]);
    }
}