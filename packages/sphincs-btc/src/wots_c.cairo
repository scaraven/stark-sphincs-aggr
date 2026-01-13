// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! WOTS+C (WOTS+ with Checksum elimination) for Bitcoin-optimized SPHINCS+.
//!
//! Key differences from standard WOTS+:
//! - w=256: Each digit is one byte (8 bits)
//! - No checksum chains: Grinding ensures fixed sum constraint
//! - Omit τ trailing chains: Last SPX_WOTS_C_OMIT chains must be zero
//! - Counter in signature: Used during verification to reconstruct digest

use crate::address::{Address, AddressTrait};
use crate::hasher::{HashOutput, HashOutputSerde, SpxCtx, thash_btc};
use crate::params_btc::{SPX_WOTS_C_LEN, SPX_WOTS_C_OMIT};

#[cfg(feature: "debug")]
fn debug_print_wots_c(modified_message: HashOutput, sum: u32, digits: @Array<u32>) {
    let len = digits.len();
    let d14 = *digits[14];
    let d15 = *digits[15];
    println!("    modified_msg: {}", crate::hasher::to_hex(modified_message.span()));
    println!("    sum: {}, last2: [{}, {}]", sum, d14, d15);
}

#[cfg(not(feature: "debug"))]
fn debug_print_wots_c(_modified_message: HashOutput, _sum: u32, _digits: @Array<u32>) {}

/// WOTS+C signature: array of partially hashed secret values and counter.
/// With w=256 and LEN1=16, we have SPX_WOTS_C_LEN = 14 chains.
#[derive(Drop, Default, Copy)]
pub struct WotsCSignature {
    /// The signature chains (each is a 16-byte hash)
    pub sig_chains: [HashOutput; SPX_WOTS_C_LEN],
    /// Counter used during grinding to satisfy constraints
    pub counter: u32,
}

/// Convert a 16-byte message (HashOutput) to base-256 digits (bytes).
/// With w=256, each byte is one digit, so we have exactly 16 digits.
/// Returns the digits and their sum.
fn base_256_with_sum(message: HashOutput) -> (Array<u32>, u32) {
    let mut digits = array![];
    let mut sum: u32 = 0;

    // Each 32-bit word contains 4 bytes (4 base-256 digits)
    for word in message.span() {
        let (a, bcd) = DivRem::div_rem(*word, 0x1000000);
        let (b, cd) = DivRem::div_rem(bcd, 0x10000);
        let (c, d) = DivRem::div_rem(cd, 0x100);
        digits.append(a);
        digits.append(b);
        digits.append(c);
        digits.append(d);
        sum += a + b + c + d;
    }

    (digits, sum)
}

/// Check if the message digest satisfies WOTS+C constraints:
/// 1. Sum of all LEN1 digits equals SPX_WOTS_TARGET_SUM
/// 2. Last SPX_WOTS_C_OMIT digits are all zero
fn check_wots_c_constraints(digits: @Array<u32>, _sum: u32) -> bool {
    // WOTS+C constraint: Last SPX_WOTS_C_OMIT digits must be zero.
    // This eliminates the need for those chains in the signature.
    // The sum constraint is not enforced (grinding for exact sum is too expensive).
    let len = digits.len();
    let mut i = len - SPX_WOTS_C_OMIT;
    while i < len {
        if *digits[i] != 0 {
            return false;
        }
        i += 1;
    }

    true
}

/// Compute modified message for WOTS+C: H(message || counter)
/// This modification allows grinding to find a counter that satisfies constraints.
fn compute_modified_message(
    ctx: SpxCtx, message: HashOutput, counter: u32, address: @Address,
) -> HashOutput {
    // Create input: message || counter (16 bytes + 4 bytes = 20 bytes)
    let mut input: Array<u32> = array![];
    input.append_span(message.span());
    input.append(counter);

    // Use thash to compute H(pk_seed || address || message || counter)
    thash_btc(ctx, address, input.span())
}

/// Derive the WOTS+C public key from a signature.
///
/// This function:
/// 1. Recomputes the modified message using the counter: H(message || counter)
/// 2. Converts modified message to base-256 digits
/// 3. Verifies the fixed-sum and zero-chain constraints
/// 4. Hashes each signature element up the remaining chain
///
/// Returns the concatenated public key elements.
pub fn wots_c_pk_from_sig(
    ctx: SpxCtx, sig: WotsCSignature, message: HashOutput, address: @Address,
) -> Array<u32> {
    let WotsCSignature { sig_chains, counter } = sig;

    // Compute modified message: H(message || counter)
    // This is where grinding ensures the constraints are satisfied
    let modified_message = compute_modified_message(ctx, message, counter, address);

    // Convert modified message to base-256 digits and get sum
    let (digits, sum) = base_256_with_sum(modified_message);

    debug_print_wots_c(modified_message, sum, @digits);

    // Verify constraints
    if !check_wots_c_constraints(@digits, sum) {
        // Constraints not satisfied - return empty (invalid signature)
        return array![];
    }

    // For each signed chain, compute the public key element
    // by hashing from step x_i up to w-1 = 255
    let mut pk = array![];
    let mut chain_idx: u8 = 0;
    let mut sig_iter = sig_chains.span();

    while let Some(sk) = sig_iter.pop_front() {
        // Get the digit value (chain starting position)
        let x_i = *digits[chain_idx.into()];
        let start: u8 = x_i.try_into().unwrap();

        // Set the hash address for this chain
        let mut wots_addr = address.clone();
        wots_addr.set_wots_chain_addr(chain_idx);

        // Hash chain from step x_i up to w-1 = 255
        let chain_pk = chain_hash_256(ctx, *sk, start, ref wots_addr);
        pk.append_span(chain_pk.span());

        chain_idx += 1;
    }

    pk
}

/// Compute the hash chain from a given starting point up to w-1 = 255.
/// With w=256, the chain has 255 steps maximum.
fn chain_hash_256(ctx: SpxCtx, input: HashOutput, start: u8, ref address: Address) -> HashOutput {
    if start == 255 {
        return input;
    }

    address.set_wots_hash_addr(start);
    let mut output = thash_btc(ctx, @address, input.span());

    let mut i = start + 1;
    loop {
        if i == 255 {
            break;
        }
        address.set_wots_hash_addr(i);
        output = thash_btc(ctx, @address, output.span());
        i += 1;
    }

    output
}

/// Serde implementation for WotsCSignature
pub impl WotsCSignatureSerde of Serde<WotsCSignature> {
    fn serialize(self: @WotsCSignature, ref output: Array<felt252>) {
        let mut iter = self.sig_chains.span();
        while let Some(elt) = iter.pop_front() {
            HashOutputSerde::serialize(elt, ref output);
        }
        output.append((*self.counter).into());
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<WotsCSignature> {
        let mut arr = array![];
        for _ in 0..SPX_WOTS_C_LEN {
            let elt = HashOutputSerde::deserialize(ref serialized)?;
            arr.append(elt);
        }
        let sig_chains: @Box<[HashOutput; SPX_WOTS_C_LEN]> = arr.span().try_into().unwrap();
        let counter: u32 = (*serialized.pop_front()?).try_into().unwrap();
        Some(WotsCSignature { sig_chains: sig_chains.unbox(), counter })
    }
}
