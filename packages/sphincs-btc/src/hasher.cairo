// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

// Available hash functions.
mod blake2s;
mod sha256;

// Cairo-friendly hash function (custom AIR in Stwo)
#[cfg(feature: "blake_hash")]
pub use blake2s::{HashState, hash_finalize, hash_init, hash_update, hash_update_block};

// Default hash function according to the sha256 parameters.
#[cfg(not(feature: "blake_hash"))]
pub use sha256::{HashState, hash_finalize, hash_init, hash_update, hash_update_block};

// Imports.
use crate::address::{Address, AddressTrait};
use crate::params_btc::SPX_HASH_LEN;
use crate::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};

/// Hash output.
pub type HashOutput = [u32; SPX_HASH_LEN];

/// Hash context.
#[derive(Drop, Copy, Default, Debug)]
pub struct SpxCtx {
    state_seeded: HashState,
}

/// Absorb the constant pub_seed using one round of the compression function
/// This initializes state_seeded, which can then be reused in thash
pub fn initialize_hash_function(pk_seed: HashOutput) -> SpxCtx {
    let mut state: HashState = Default::default();
    let [a, b, c, d] = pk_seed;
    hash_init(ref state);
    hash_update_block(ref state, [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    SpxCtx { state_seeded: state }
}

/// Compute a truncated hash of the data.
pub fn thash_btc(ctx: SpxCtx, address: @Address, input: Span<u32>) -> HashOutput {
    let mut buffer = address.to_word_array();
    buffer.append_u32_span(input);
    let (words, last_word, last_word_len) = buffer.into_components();
    let [d0, d1, d2, d3, _, _, _, _] = hash_finalize(
        ctx.state_seeded, words, last_word, last_word_len,
    );
    [d0, d1, d2, d3]
}

/// Hash a message using selected hash function.
/// Returns the extended message digest of size SPX_DGST_BYTES as a [WordArray].
/// NOTE: Adapted for Bitcoin-optimized parameters (h=32, d=4, k=10, a=14).
pub fn hash_message_btc(
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
    let hash_output = hash_finalize(state, xof_data.into(), 0, 0);

    // For output_len = 22 bytes (SPX_DGST_BYTES for btc params):
    // We need 5 full words (20 bytes) + 2 bytes from the 6th word
    // hash_output = [w0, w1, w2, w3, w4, w5, w6, w7] - 32 bytes total
    let [w0, w1, w2, w3, w4, w5, _, _] = hash_output;

    // Take first 5 words (20 bytes) + top 2 bytes of w5 (2 bytes) = 22 bytes
    let words: Array<u32> = array![w0, w1, w2, w3, w4];
    let partial_word = w5 / 0x10000; // Top 2 bytes of w5

    let res = WordArrayTrait::new(words, partial_word, 2);
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

        let mut buffer: Array<u32> = array![];
        if r == 0 {
            buffer.append_span(node.span());
            buffer.append_span(hash_witness.span());
        } else {
            buffer.append_span(hash_witness.span());
            buffer.append_span(node.span());
        }

        i += 1;
        leaf_idx = q;
        idx_offset /= 2;

        address.set_tree_height(i);
        address.set_tree_index(leaf_idx + idx_offset);

        node = thash_btc(ctx, @address, buffer.span());
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
