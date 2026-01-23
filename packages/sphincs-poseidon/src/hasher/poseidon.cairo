// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::{HashState as PoseidonHashState, PoseidonTrait};

/// Poseidon incremental state.
/// The Poseidon hash state maintains 3 field elements (s0, s1, s2).
#[derive(Debug, Drop, Copy)]
pub struct HashState {
    pub(crate) state: PoseidonHashState,
}

impl HashStateDefault of Default<HashState> {
    fn default() -> HashState {
        HashState { state: PoseidonTrait::new() }
    }
}

/// Initializes the Poseidon hasher state.
pub fn hash_init(ref state: HashState) {
    // no-op
}

/// Updates the Poseidon hasher state with a single block of felt252 values.
#[inline]
pub fn hash_update_16(ref state: HashState, data: [felt252; 16]) {
    state.state = state.state.update_with(data);
}

#[inline]
pub fn hash_update_5(ref state: HashState, data: [felt252; 5]) {
    state.state = state.state.update_with(data);
}

#[inline]
pub fn hash_update_4(ref state: HashState, data: [felt252; 4]) {
    state.state = state.state.update_with(data);
}

#[inline]
pub fn hash_update_3(ref state: HashState, data: [felt252; 3]) {
    state.state = state.state.update_with(data);
}

pub fn hash_update_5_finalize(ref state: HashState, data: [felt252; 5]) -> felt252 {
    hash_update_5(ref state, data);
    state.state.finalize()
}

pub fn hash_update_4_finalize(ref state: HashState, data: [felt252; 4]) -> felt252 {
    hash_update_4(ref state, data);
    state.state.finalize()
}

pub fn hash_update_3_finalize(ref state: HashState, data: [felt252; 3]) -> felt252 {
    hash_update_3(ref state, data);
    state.state.finalize()
}

pub fn hash_update_16_finalize(ref state: HashState, data: [felt252; 16]) -> felt252 {
    hash_update_16(ref state, data);
    state.state.finalize()
}

/// Updates the Poseidon hasher state with the given data (data length must be a multiple of 16).
pub fn hash_update_block(ref state: HashState, mut data: Span<felt252>) {
    while let Some(chunk) = data.multi_pop_front::<16>() {
        hash_update_16(ref state, chunk.unbox());
    }
    assert(data.is_empty(), 'unaligned poseidon block');
}

/// Finalizes the Poseidon hasher state and returns the hash.
pub fn hash_finalize(ref state: HashState, input: Span<felt252>) -> felt252 {
    hash_update_block(ref state, input);
    state.state.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] 
    fn test_hash_length_consitent() {
        // This tests ensures that if we hash 4 felt252 values and then update with 1 more, we 
        // get the same result as hashing all 5 at once.
        let mut state: HashState = Default::default();

        let data: [felt252; 4] = [1, 2, 3, 4];
        hash_update_4(ref state, data);
        state.state = state.state.update(5);

        let output1 = state.state.finalize();

        let mut state = Default::default();
        let data: [felt252; 5] = [1, 2, 3, 4, 5];
        let output2 = hash_update_5_finalize(ref state, data);

        assert_eq!(output1, output2, "Poseidon hash outputs do not match");
    }
}
