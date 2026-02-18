// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

pub use sphincs_core::address;
pub use sphincs_core::word_array;
pub use sphincs_core::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};
pub mod fors;
pub mod hasher;
pub mod params_128s;
pub mod sphincs;
pub mod wots;
use crate::sphincs::{SphincsPublicKey, SphincsSignature};

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
fn main(args: Args) {
    let Args { pk, sig, message } = args;
    let res = sphincs::verify_128s(message.span(), sig, pk);
    check_result(res);
}

#[cfg(feature: "blake_hash")]
fn check_result(res: bool) { // TODO: generate a valid signature for blake_hash
}

#[cfg(feature: "poseidon_hash")]
fn check_result(res: bool) { // TODO: generate a valid signature for poseidon_hash
}

#[cfg(and(not(feature: "blake_hash"), not(feature: "poseidon_hash")))]
fn check_result(res: bool) {
    assert(res, 'invalid signature');
}
