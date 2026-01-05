// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

// Available hash functions.
mod poseidon;

// Poseidon backend (arithmetic-friendly).
pub use poseidon::{
    HashState, hash_finalize, hash_finalize_block, hash_init, hash_update, hash_update_block,
};

// Imports.
use crate::address::{Address, AddressTrait, AddressType};
use crate::params_128s::SPX_HASH_LEN;
use crate::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};

/// Hash output.
pub type HashOutput = [u32; SPX_HASH_LEN];

/// Hash context.
#[derive(Drop, Copy, Default, Debug)]
pub struct SpxCtx {
    state_seeded: HashState,
}

/// Absorb the constant pub_seed using one round of the compression function
/// This initializes `state_seeded`, which can then be reused in `thash`.
pub fn initialize_hash_function(pk_seed: HashOutput) -> SpxCtx {
    let mut state: HashState = Default::default();
    let [a, b, c, d] = pk_seed;
    hash_init(ref state);
    hash_update_block(ref state, [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    SpxCtx { state_seeded: state }
}

/// Poseidon-backed thash for 4 input words
pub fn thash_4(ctx: SpxCtx, address: @Address, data: [u32; 4]) -> HashOutput {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();
    let [d0, d1, d2, d3] = data;
    let mut state = ctx.state_seeded;
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, 0, 0, 0, 0],
    );
    [h0, h1, h2, h3]
}

/// Poseidon-backed thash for 5 input words (same block layout as Blake).
pub fn thash_5(ctx: SpxCtx, address: @Address, word0: [u32; 4], word1: u32) -> HashOutput {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();
    let [d0, d1, d2, d3] = word0;
    let d4 = word1;
    let mut state = ctx.state_seeded;
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, d4, 0, 0, 0],
    );
    [h0, h1, h2, h3]
}

/// Poseidon-backed thash for 8 input words
pub fn thash_8(ctx: SpxCtx, address: @Address, word0: [u32; 4], word1: [u32; 4]) -> HashOutput {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();
    let [d0, d1, d2, d3] = word0;
    let [d4, d5, d6, d7] = word1;
    let mut state = ctx.state_seeded;
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, d4, d5, d6, d7],
    );
    [h0, h1, h2, h3]
}

/// Poseidon-backed thash for FORS public key hashing.
pub fn thash_140(ctx: SpxCtx, address: @Address, mut data: Span<[u32; 4]>) -> HashOutput {
    let mut state = ctx.state_seeded;
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();

    let Some(block) = data.multi_pop_front::<2>() else {
        panic!("thash_140: expected len = 10");
    };
    let [w0, w1] = (*block).unbox();
    let [d0, d1, d2, d3] = w0;
    let [d4, d5, d6, d7] = w1;
    hash_update_block(
        ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, d4, d5, d6, d7],
    );

    while let Some(block) = data.multi_pop_front::<4>() {
        let [w0, w1, w2, w3] = (*block).unbox();
        let [d0, d1, d2, d3] = w0;
        let [d4, d5, d6, d7] = w1;
        let [d8, d9, d10, d11] = w2;
        let [d12, d13, d14, d15] = w3;
        hash_update_block(
            ref state,
            [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15],
        );
    }

    let w0 = data.pop_front().unwrap();
    assert(data.is_empty(), 'thash_140: expected len = 35');
    let [d0, d1, d2, d3] = *w0;
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [d0, d1, d2, d3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    [h0, h1, h2, h3]
}

/// Poseidon-backed thash for WOTS chaining.
pub fn thash_56(ctx: SpxCtx, address: @Address, data: Span<[u32; 4]>) -> HashOutput {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = address.into_components();
    let data = data.try_into().expect('thash_btc_56: expected len = 14');
    let [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13] = (*data).unbox();
    let mut state = ctx.state_seeded;

    let [d0, d1, d2, d3] = w0;
    let [d4, d5, d6, d7] = w1;
    let [d8, d9, d10, d11] = w2;
    let [d12, d13, d14, d15] = w3;
    let [d16, d17, d18, d19] = w4;
    let [d20, d21, d22, d23] = w5;
    let [d24, d25, d26, d27] = w6;
    let [d28, d29, d30, d31] = w7;
    let [d32, d33, d34, d35] = w8;
    let [d36, d37, d38, d39] = w9;
    let [d40, d41, d42, d43] = w10;
    let [d44, d45, d46, d47] = w11;
    let [d48, d49, d50, d51] = w12;
    let [d52, d53, d54, d55] = w13;

    hash_update_block(
        ref state, [a0, a1, a2, a3, a4, a5, a6, a7, d0, d1, d2, d3, d4, d5, d6, d7],
    );
    hash_update_block(
        ref state, [d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23],
    );
    hash_update_block(
        ref state, [d24, d25, d26, d27, d28, d29, d30, d31, d32, d33, d34, d35, d36, d37, d38, d39],
    );
    let [h0, h1, h2, h3, _, _, _, _] = hash_finalize_block(
        ref state, [d40, d41, d42, d43, d44, d45, d46, d47, d48, d49, d50, d51, d52, d53, d54, d55],
    );
    [h0, h1, h2, h3]
}

/// Compute a truncated hash of the data.
pub fn thash_128s(ctx: SpxCtx, address: @Address, buffer: WordArray) -> HashOutput {
    let (words, last_word, last_word_len) = buffer.into_components();
    let [d0, d1, d2, d3, _, _, _, _] = hash_finalize(
        ctx.state_seeded, words, last_word, last_word_len,
    );
    [d0, d1, d2, d3]
}

/// Hash a message using selected hash function.
/// Returns the extended message digest of size SPX_DGST_BYTES as a [WordArray].
/// NOTE: this is not a generic implementation, rather a shortcut for 128s.
pub fn hash_message_128s(
    randomizer: HashOutput,
    pk_seed: HashOutput,
    pk_root: HashOutput,
    message: WordSpan,
    output_len: u32,
) -> WordArray {
    let mut data: Array<u32> = array![];
    data.append_span(randomizer.span());
    data.append_span(pk_seed.span());
    data.append_span(pk_root.span());

    let (msg_words, msg_last_word, msg_last_word_len) = message.into_components();
    data.append_span(msg_words);

    let mut state: HashState = Default::default();
    hash_init(ref state);

    // Compute the seed for XOF.
    let seed = hash_finalize(state, data, msg_last_word, msg_last_word_len);

    let mut xof_data: Array<u32> = array![];
    xof_data.append_span(randomizer.span());
    xof_data.append_span(pk_seed.span());
    xof_data.append_span(seed.span());
    xof_data.append(0); // MGF1 counter = 0

    // Apply MGF1 to the seed.
    let mut buffer = hash_finalize(state, xof_data.into(), 0, 0).span();

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
        for elt in self.span() {
            output.append((*elt).into());
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<HashOutput> {
        let h0: u32 = (*serialized.pop_front().expect('h0')).try_into().unwrap();
        let h1: u32 = (*serialized.pop_front().expect('h1')).try_into().unwrap();
        let h2: u32 = (*serialized.pop_front().expect('h2')).try_into().unwrap();
        let h3: u32 = (*serialized.pop_front().expect('h3')).try_into().unwrap();
        Some([h0, h1, h2, h3])
    }
}

#[cfg(or(test, feature: "debug"))]
pub fn to_hex(data: Span<u32>) -> ByteArray {
    let word_span = WordSpanTrait::new(data, 0, 0);
    crate::word_array::hex::words_to_hex(word_span)
}