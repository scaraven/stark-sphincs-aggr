// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::PoseidonTrait;
use core::poseidon::{HashState as PoseidonHashState};

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
    state.state = PoseidonTrait::new();
}

/// Updates the Poseidon hasher state with a single block of 2 felt252 values.
#[inline]
pub fn hash_update(ref state: HashState, data: [felt252; 16]) {
    // Update with felt252
    state.state = state.state.update_with(data);
}

/// Updates the Poseidon hasher state with the given data (data length must be a multiple of 16).
pub fn hash_update_block(ref state: HashState, mut data: Span<felt252>) {
    while let Some(chunk) = data.multi_pop_front::<16>() {
        hash_update(ref state, chunk.unbox());
    }
    assert(data.is_empty(), 'unaligned poseidon block');
}

pub fn hash_finalize_block(ref state: HashState, data: [felt252; 16]) -> felt252 {
    hash_update(ref state, data);
    state.state.finalize()
}

/// Finalizes the Poseidon hasher state and returns the hash.
pub fn hash_finalize(
    ref state: HashState, input: Array<felt252>
) -> felt252 {
    hash_update_block(ref state, input.span());
    state.state.finalize()
}