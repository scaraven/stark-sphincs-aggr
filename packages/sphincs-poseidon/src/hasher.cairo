// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

// Available hash functions.
mod blake;
mod poseidon;

// Poseidon backend (arithmetic-friendly).
pub use poseidon::hash_update_block;
use poseidon::{
    HashState, hash_finalize_block, hash_init, hash_update,
};

use core::hash::HashStateTrait;

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
pub fn thash_4(ctx: SpxCtx, address: @Address, data: felt252) -> HashOutput {
    let (a0, a1) = address.into_fields();
    let mut state = ctx.state_seeded;
    hash_finalize_block(
        ref state, [a0, a1, data, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
}

/// Poseidon-backed thash for 2 input words
pub fn thash_8(ctx: SpxCtx, address: @Address, word0: felt252, word1: felt252) -> HashOutput {
    let (a0, a1) = address.into_fields();
    let mut state = ctx.state_seeded;
    hash_finalize_block(
        ref state, [a0, a1, word0, word1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
}

/// Poseidon-backed thash for FORS public key hashing.
pub fn thash_140(ctx: SpxCtx, address: @Address, mut data: Span<felt252>) -> HashOutput {
    let mut state = ctx.state_seeded;
    let (a0, a1) = address.into_fields();

    assert(data.len() == 35, 'thash_140: expected len = 35');

    // Do initial update with address fields
    if let Some(chunk) = data.multi_pop_front::<14>() {
        let [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13] = (*chunk).unbox();
        hash_update(ref state, [a0, a1, d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13]);
    }

    while let Some(chunk) = data.multi_pop_front::<16>() {
        let [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15] =
            (*chunk).unbox();
        hash_update(ref state, [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15]);
    }

    match data.multi_pop_front::<5>() {
        Some(chunk) => {
            let [d0, d1, d2, d3, d4] = (*chunk).unbox();
            hash_finalize_block(ref state, [d0, d1, d2, d3, d4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        },
        None => panic!("thash_140: unexpected data length")
    }
}

/// Poseidon-backed thash for multiple field elements
pub fn thash_56(ctx: SpxCtx, address: @Address, mut data: Span<felt252>) -> HashOutput {
    let (a0, a1) = address.into_fields();
    let mut state = ctx.state_seeded;

    let data_len = data.len();
    assert(data_len == 14, 'thash_56: expected len = 14');

    while let Some(chunk) = data.multi_pop_front::<14>() {
        let [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13] =
            (*chunk).unbox();
        return hash_finalize_block(ref state, [a0, a1, d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13]);
    }

    panic!("thash_56: unexpected data length");
}

/// Convert a felt252 to an array of 4 u32s (little-endian).
fn felt252_to_u32_array(value: felt252) -> Array<u32> {
    let value_u256: u256 = value.into();
    let mut result: Array<u32> = array![];
    
    result.append((value_u256 & 0xFFFFFFFF).try_into().unwrap());
    result.append(((value_u256 / 0x100000000) & 0xFFFFFFFF).try_into().unwrap());
    result.append(((value_u256 / 0x10000000000000000) & 0xFFFFFFFF).try_into().unwrap());
    result.append(((value_u256 / 0x1000000000000000000000000) & 0xFFFFFFFF).try_into().unwrap());
    
    result
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
) -> WordArray {
    let mut data: Array<u32> = array![];
    data.append_span(felt252_to_u32_array(randomizer).span());
    data.append_span(felt252_to_u32_array(pk_seed).span());
    data.append_span(felt252_to_u32_array(pk_root).span());

    let (msg_words, msg_last_word, msg_last_word_len) = message.into_components();
    data.append_span(msg_words);

    let mut state: blake::HashState = Default::default();
    blake::hash_init(ref state);

    // Compute the seed for XOF.
    let seed = blake::hash_finalize(state, data, msg_last_word, msg_last_word_len);

    let mut xof_data: Array<u32> = array![];
    xof_data.append_span(felt252_to_u32_array(randomizer).span());
    xof_data.append_span(felt252_to_u32_array(pk_seed).span());
    xof_data.append_span(seed.span());
    xof_data.append(0); // MGF1 counter = 0

    // Apply MGF1 to the seed.
    let mut buffer = blake::hash_finalize(state, xof_data, 0, 0).span();

    // Construct the digest from the extended output.
    // NOTE: we haven't cleared the LSB of the last word, has to be handled correctly.
    let last_word = *buffer.pop_back().unwrap();

    // Construct the digest from the first 7 words (28 bits) and add 2 bytes from the last word.
    let res = WordArrayTrait::new(buffer.into(), last_word / 0x10000, 2);
    assert(res.byte_len() == output_len, 'Invalid extended digest length');
    res
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