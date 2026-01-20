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

use hasher::hash_finalize;
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
    /// Array of signature-message pairs.
    pub sig_msg_pairs: Array<(SphincsSignature, WordArray)>,
}

// #[executable]
// fn main(args: Args) {
//     let Args { pk, sig, message } = args;
//     let res = sphincs::verify_btc(message.span(), sig, pk);
//     check_result(res);
// }

#[executable]
fn main_multi(args: MultiSigArgs) {
    let MultiSigArgs { pk, sig_msg_pairs } = args;
    let res = sphincs::verify_btc_batch(sig_msg_pairs.span(), pk);
    check_result(res);
}

const BLAKE2S_256_IV: [u32; 8] = [
    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

#[derive(Drop, Serde)]
struct TestArgs {
    dummy: u32,
}

fn to_hex(data: Span<u32>) -> ByteArray {
    let word_span = WordSpanTrait::new(data, 0, 0);
    crate::word_array::hex::words_to_hex(word_span)
}

#[cfg(feature: "blake_hash")]
fn test_blake2s_basic() {
    println!("=============================================================");
    println!("Test 1: Basic Blake2s");
    println!("=============================================================");
    
    // Test 1: Empty input
    let mut state = Default::default();
    let empty_hash = hash_finalize(state, array![], 0, 0);
    println!("\nTest 1 (empty):");
    println!("  Blake2s output: {}", to_hex(empty_hash.span()));
    let [a, b, c, d, _, _, _, _] = empty_hash;
    println!("  Output u32s: [{}, {}, {}, {}]", a, b, c, d);
    
    // Test 2: "abc" = 0x616263 (3 bytes)
    // In little-endian u32 format: bytes 61,62,63 -> u32 0x00636261 (3 bytes)
    let mut state = Default::default();
    let abc_hash = hash_finalize(state, array![], 0x636261, 3);
    println!("\nTest 2 (abc):");
    println!("  Input: 0x616263");
    println!("  Blake2s output: {}", to_hex(abc_hash.span()));
    let [a, b, c, d, _, _, _, _] = abc_hash;
    println!("  Output u32s: [{}, {}, {}, {}]", a, b, c, d);
    
    // Test 5: 16 bytes sequence (0x00, 0x01, ..., 0x0f)
    // In little-endian: [03020100, 07060504, 0b0a0908, 0f0e0d0c]
    let seq = array![0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c];
    let mut state = Default::default();
    let seq_hash = hash_finalize(state, seq, 0, 0);
    println!("\nTest 5 (bytes 0-15):");
    println!("  Input: 0x000102030405060708090a0b0c0d0e0f");
    println!("  Blake2s output: {}", to_hex(seq_hash.span()));
    let [a, b, c, d, _, _, _, _] = seq_hash;
    println!("  Output u32s: [{}, {}, {}, {}]", a, b, c, d);
}

use core::box::BoxImpl;
use address::{Address, AddressTrait, AddressType};
use hasher::{HashOutput, initialize_hash_function, thash_btc};
use word_array::WordSpanTrait;

#[cfg(feature: "blake_hash")]
fn test_thash() {
    println!("\n=============================================================");
    println!("Test 2: thash (Tweakable Hash)");
    println!("=============================================================");
    
    // Use deterministic seeds: 0x00, 0x01, ..., 0x0f (in big-endian)
    let pk_seed: HashOutput = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
    // Test data: 0x10, 0x11, ..., 0x1f (in big-endian)
    let test_data = array![0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];
    
    let ctx = initialize_hash_function(pk_seed);
    
    // Test 1: Zero address
    let mut addr: Address = Default::default();
    let result = thash_btc(ctx, @addr, test_data.span());
    println!("\nZero address:");
    println!("  pk_seed: {}", to_hex(pk_seed.span()));
    println!("  thash output: {}", to_hex(result.span()));
    let [a, b, c, d] = result;
    println!("  Output u32s: [{}, {}, {}, {}]", a, b, c, d);
    
    // Test 2: Layer 1
    addr = Default::default();
    addr.set_hypertree_layer(1);
    let result = thash_btc(ctx, @addr, test_data.span());
    println!("\nLayer 1:");
    println!("  thash output: {}", to_hex(result.span()));
    let [a, b, c, d] = result;
    println!("  Output u32s: [{}, {}, {}, {}]", a, b, c, d);
    
    // Test 3: Tree addr 0x123
    addr = Default::default();
    addr.set_hypertree_addr(0x123);
    let result = thash_btc(ctx, @addr, test_data.span());
    println!("\nTree addr 0x123:");
    println!("  thash output: {}", to_hex(result.span()));
    let [a, b, c, d] = result;
    println!("  Output u32s: [{}, {}, {}, {}]", a, b, c, d);
    
    // Test 4: WOTS type
    addr = Default::default();
    addr.set_address_type(AddressType::WOTS);
    let result = thash_btc(ctx, @addr, test_data.span());
    println!("\nWOTS type:");
    println!("  thash output: {}", to_hex(result.span()));
    let [a, b, c, d] = result;
    println!("  Output u32s: [{}, {}, {}, {}]", a, b, c, d);
    
    // Test 5: Complex
    addr = Default::default();
    addr.set_hypertree_layer(2);
    addr.set_hypertree_addr(0xABC);
    addr.set_address_type(AddressType::HASHTREE);
    addr.set_keypair(5);
    let result = thash_btc(ctx, @addr, test_data.span());
    println!("\nComplex:");
    println!("  thash output: {}", to_hex(result.span()));
    let [a, b, c, d] = result;
    println!("  Output u32s: [{}, {}, {}, {}]", a, b, c, d);
}

#[executable]
fn test_consistency(_args: TestArgs) {
    println!("SPHINCS+ BTC Consistency Test Suite (Cairo)");
    println!("=============================================================");
    println!("Testing Cairo implementation components");
    println!("Compare outputs with Python test_consistency.py");
    println!("=============================================================");
    
    test_blake2s_basic();
    test_thash();
    
    println!("\n=============================================================");
    println!("Tests complete!");
    println!("=============================================================");
}

#[cfg(or(feature: "blake_hash", feature: "debug"))]
fn check_result(_res: bool) {
    // Skip signature verification in blake_hash or debug mode
}

#[cfg(not(or(feature: "blake_hash", feature: "debug")))]
fn check_result(res: bool) {
    assert(res, 'invalid signature');
}
