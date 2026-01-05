// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use core::hash::{HashStateExTrait, HashStateTrait};
use core::traits::DivRem;
use core::poseidon::PoseidonTrait;
use core::poseidon::{HashState as PoseidonHashState};

/// Poseidon incremental state.
/// The Poseidon hash state maintains 3 field elements (s0, s1, s2).
#[derive(Debug, Drop, Copy)]
pub struct HashState {
    pub(crate) state: PoseidonHashState,
    pub(crate) byte_len: u32,
}

impl HashStateDefault of Default<HashState> {
    fn default() -> HashState {
        HashState { state: PoseidonTrait::new(), byte_len: 0 }
    }
}

/// Initializes the Poseidon hasher state.
pub fn hash_init(ref state: HashState) {
    state.state = PoseidonHashState { s0: 0, s1: 0, s2: 0, odd: false };
    state.byte_len = 0;
}

/// Updates the Poseidon hasher state with a single block of 16 u32 values.
pub fn hash_update_block(ref state: HashState, data: [u32; 16]) {
    state.byte_len += 64;
    
    // Update with array of u32
    state.state = state.state.update_with(data);
}

/// Updates the Poseidon hasher state with the given data (data length must be a multiple of 16).
pub fn hash_update(ref state: HashState, mut data: Span<u32>) {
    while let Some(chunk) = data.multi_pop_front::<16>() {
        hash_update_block(ref state, chunk.unbox());
    }
    assert(data.is_empty(), 'unaligned poseidon block');
}

pub fn hash_finalize_block(ref state: HashState, data: [u32; 16]) -> [u32; 8] {
    let updated_state = state.state.update_with(data);
    state.byte_len += 64;

    let out = updated_state.finalize();
    // Convert felt252 to [u32; 8]
    felt252_to_u32_array(out)
}

/// Finalizes the Poseidon hasher state and returns the hash.
/// Follows the same process as the blake2s hasher for padding and finalization.
pub fn hash_finalize(
    mut state: HashState, input: Array<u32>, last_input_word: u32, last_input_num_bytes: u32,
) -> [u32; 8] {
    let mut data = input.span();

    while let Some(chunk) = data.multi_pop_front::<16>() {
        hash_update_block(ref state, chunk.unbox());
    }

    let mut buffer: Array<u32> = array![];
    buffer.append_span(data);

    if last_input_num_bytes == 1 {
        buffer.append(last_input_word * 0x1000000);
    } else if last_input_num_bytes == 2 {
        buffer.append(last_input_word * 0x10000);
    } else if last_input_num_bytes == 3 {
        buffer.append(last_input_word * 0x100);
    }

    state.byte_len += buffer.len() * 4;

    for _ in buffer.len()..16 {
        buffer.append(0);
    }

    let msg = buffer.span();
    hash_update(ref state, msg);
    let out = state.state.finalize();

    // Convert felt252 to [u32; 8]
    felt252_to_u32_array(out)
}

/// TODO: This is currently insecure, as we will always get zero bytes at the end as padding
/// Consider revising this and replacing [u32; 8] instances with felt252
fn felt252_to_u32_array(x: felt252) -> [u32; 8] {
    let mut input: u256 = x.into();

    let mut r: Array<u32> = array![];

    for _ in 0..8_usize {
        let (quotient, remainder) = DivRem::div_rem(input, 0x100000000);
        input = quotient;
        let r_elem: u32 = remainder.try_into().unwrap();
        r.append(r_elem)
    }
    
    let mut r_span = r.span();

    let chunk = r_span.multi_pop_front::<8>().unwrap();
    chunk.unbox()
}