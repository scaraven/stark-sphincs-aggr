// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! Bitcoin-optimized SPHINCS+ signature verification.
//!
//! This implementation follows Blockstream's optimizations:
//! - WOTS+C: Eliminate checksum chains via grinding (w=256)
//! - FORS+C: Force last tree index to 0, omit auth path
//! - Reduced hypertree: h=32, d=4
//!
//! Target signature size: ~3.4KB

pub mod address;
pub mod fors;
pub mod fors_c;
pub mod hasher;
pub mod params_btc;
pub mod sphincs;
pub mod word_array;
pub mod wots_c;

use crate::sphincs::{SphincsPublicKey, SphincsSignature};
use crate::word_array::{WordArray, WordArrayTrait};

#[derive(Drop, Serde, Default)]
pub struct Args {
    /// SPHINCS+ BTC public key.
    pub pk: SphincsPublicKey,
    /// SPHINCS+ BTC signature.
    pub sig: SphincsSignature,
    /// Message.
    pub message: WordArray,
}

#[derive(Drop, Serde)]
pub struct MultiSigArgs {
    /// SPHINCS+ BTC public key (shared across all signatures).
    pub pk: SphincsPublicKey,
    /// Number of signatures to verify.
    pub num_sigs: u32,
    /// Array of signature-message pairs.
    pub sig_msg_pairs: Array<(SphincsSignature, WordArray)>,
}

#[executable]
fn main(args: Args) {
    let Args { pk, sig, message } = args;
    let res = sphincs::verify_btc(message.span(), sig, pk);
    check_result(res);
}

#[executable]
fn main_multi(args: MultiSigArgs) {
    let MultiSigArgs { pk, num_sigs, sig_msg_pairs } = args;
    let res = sphincs::verify_btc_batch(sig_msg_pairs.span(), pk);
    check_result(res);
}

#[cfg(or(feature: "blake_hash", feature: "debug"))]
fn check_result(_res: bool) {
    // Skip signature verification in blake_hash or debug mode
}

#[cfg(not(or(feature: "blake_hash", feature: "debug")))]
fn check_result(res: bool) {
    assert(res, 'invalid signature');
}
