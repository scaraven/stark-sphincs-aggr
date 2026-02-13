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

#[derive(Drop, Serde)]
pub struct MultiSigArgs {
    /// SPHINCS+ Poseidon public key (shared across all signatures).
    pub pk: SphincsPublicKey,
    /// Array of signature-message pairs.
    pub sig_msg_pairs: Array<(SphincsSignature, WordArray)>,
}

#[executable]
fn main(args: Args) {
    let Args { pk, sig, message } = args;
    let res = sphincs::verify_128s(message.span(), sig, pk);
    check_result(res);
}

#[executable]
fn main_multi(args: MultiSigArgs) {
    let MultiSigArgs { pk, sig_msg_pairs } = args;
    let res = sphincs::verify_128s_batch(sig_msg_pairs.span(), pk);
    check_result(res);
}

#[cfg(feature: "debug")]
fn check_result(res: bool) {
    println!("Verification result: {}", res);
}

#[cfg(not(feature: "debug"))]
fn check_result(res: bool) {
    assert(res, 'Signature verification failed');
}
