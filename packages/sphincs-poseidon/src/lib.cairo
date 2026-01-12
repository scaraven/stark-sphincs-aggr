// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

pub mod address;
pub mod fors;
pub mod hasher;
pub mod params_128s;
pub mod sphincs;
pub mod word_array;
pub mod wots;
use crate::sphincs::{SphincsPublicKey, SphincsSignature};
use crate::word_array::{WordArray, WordArrayTrait};

#[derive(Drop, Serde, Default)]
pub struct Args {
    /// Sphincs+ public key.
    pub pk: SphincsPublicKey,
    /// Sphincs+ signature.
    pub sig: SphincsSignature,
    /// Message.
    pub message: WordArray,
}

#[executable]
fn main() {
    let pk = SphincsPublicKey {
        pk_root: 2101057191,
        pk_seed: 502713403,
    };

    let sig = SphincsSignature {
        randomizer: 123456789,
        fors_sig: Default::default(),
        wots_merkle_sig_list: Default::default(),
    };

    let message: WordArray = Default::default();
    let res = sphincs::verify_128s(message.span(), sig, pk);
    check_result(res);
}

fn check_result(res: bool) { // TODO: generate a valid signature for poseidon_hash
}
