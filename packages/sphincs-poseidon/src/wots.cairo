// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! WOTS+ one-time signature scheme.
//! See https://research.dorahacks.io/2022/10/26/hash-based-post-quantum-signatures-1/ for an
//! overview.
//! See also https://www.di-mgt.com.au/pqc-03-winternitz.html

use core::traits::DivRem;
use crate::address::{Address, AddressTrait};
use crate::hasher::{HashOutput, HashOutputSerde, SpxCtx, thash_4};
use crate::params_128s::SPX_WOTS_LEN;

/// WOTS+ signature: array of partially hashed private keys.
pub type WotsSignature = [HashOutput; SPX_WOTS_LEN];

pub impl WotsSignatureSerde of Serde<WotsSignature> {
    fn serialize(self: @WotsSignature, ref output: Array<felt252>) {
        let mut iter = self.span();
        while let Some(elt) = iter.pop_front() {
            HashOutputSerde::serialize(elt, ref output);
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<WotsSignature> {
        let mut arr = array![];
        for i in 0..SPX_WOTS_LEN {
            let elt = HashOutputSerde::deserialize(ref serialized).expect(i.into());
            arr.append(elt);
        }
        let res: @Box<[HashOutput; SPX_WOTS_LEN]> = arr.span().try_into().unwrap();
        Some(res.unbox())
    }
}

pub impl WotsSignatureDefault of Default<WotsSignature> {
    fn default() -> WotsSignature {
        [Default::default(); SPX_WOTS_LEN]
    }
}

/// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
pub fn wots_pk_from_sig(
    ctx: SpxCtx, sig: WotsSignature, message: Array<u32>, address: @Address,
) -> Array<felt252> {

    let mut lengths = base_w_128s(message.span());
    add_checksum_128s(ref lengths);

    let mut sig_iter = sig.span();
    let mut lengths_iter = lengths.span();

    // Use 2nd LSB for chain id
    let mut chain_idx: u32 = 0;
    let mut pk = array![];

    while let Some(len) = lengths_iter.pop_front() {
        let sk = sig_iter.pop_front().unwrap();
        let chain_pk = chain_hash_128s(ctx, *sk, *len, address, chain_idx);
        pk.append(chain_pk);

        chain_idx += 0x100;
    }

    // pk is of length 35?
    pk
}

/// Computes the WOTS+ checksum over a message (in base_w) and appends it to the end.
pub fn add_checksum_128s(ref message_w: Array<u32>) {
    let mut csum: u32 = 0;

    let mut msg_iter = message_w.span();
    while let Some(elt_w) = msg_iter.pop_front() {
        csum += 15 - *elt_w; // SPX_WOTS_W - 1 - elt_w
    }

    // Convert checksum to base_w.
    // For 128s the size of checksum is 12 bits.
    // We shift the checksum left by 4 bits to make sure expected empty zero bits are the least
    // significant bits.
    let (e, fg) = DivRem::div_rem(csum, 0x100);
    let (f, g) = DivRem::div_rem(fg, 0x10);
    message_w.append_span(array![e, f, g].span());
}

/// Compute the H^{steps}(input) hash chain given the chain length (start) and return the last
/// digest.
pub fn chain_hash_128s(
    ctx: SpxCtx, input: HashOutput, length: u32, address: @Address, chain_idx: u32,
) -> HashOutput {
    if length == 15 {
        return input;
    }

    let mut wots_addr = address.clone();
    wots_addr.set_wots_addr(chain_idx + length);

    let mut output = thash_4(ctx, @wots_addr, input);

    for i in length + 1..15 { // SPX_WOTS_W - 1
        wots_addr.set_wots_addr(chain_idx + i);
        output = thash_4(ctx, @wots_addr, output);
    }
    output
}

/// Split input into chunks of 4 bits each for 128s parameter set (W=16).
pub fn base_w_128s(mut input: Span<u32>) -> Array<u32> {
    let mut output = array![];
    while let Some(word) = input.pop_front() {
        // Interpret 32-bit word as [ab cd ef gh]
        let (a, bcdefgh) = DivRem::div_rem(*word, 0x10000000);
        let (b, cdefgh) = DivRem::div_rem(bcdefgh, 0x1000000);
        let (c, defgh) = DivRem::div_rem(cdefgh, 0x100000);
        let (d, efgh) = DivRem::div_rem(defgh, 0x10000);
        let (e, fgh) = DivRem::div_rem(efgh, 0x1000);
        let (f, gh) = DivRem::div_rem(fgh, 0x100);
        let (g, h) = DivRem::div_rem(gh, 0x10);
        output.append_span(array![a, b, c, d, e, f, g, h].span());
    }
    output
}