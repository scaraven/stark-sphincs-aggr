// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! FORS (Forest of Random Subsets) for Bitcoin-optimized SPHINCS+.
//! Standard FORS implementation without +C optimization.

use crate::address::{Address, AddressTrait, AddressType};
use crate::hasher::{HashOutput, HashOutputSerde, SpxCtx, compute_root, thash_btc};
use crate::params_btc::{SPX_FORS_BASE_OFFSET, SPX_FORS_HEIGHT, SPX_FORS_TREES};
use crate::word_array::{WordSpan, WordSpanTrait};

/// FORS tree signature.
#[derive(Drop, Copy, Default)]
pub struct ForsTreeSignature {
    pub sk_seed: HashOutput,
    pub auth_path: [HashOutput; SPX_FORS_HEIGHT],
}

/// FORS signature: k trees with full auth paths.
pub type ForsSignature = [ForsTreeSignature; SPX_FORS_TREES];

/// Convert FORS mhash to leaf indices.
/// For Bitcoin params: k=10 trees, a=14 height
/// Total bits needed: 10 * 14 = 140 bits = 17.5 bytes (use 18 bytes)
fn message_to_indices_btc(mut mhash: WordSpan) -> Array<u32> {
    let mut indices = array![];
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;

    while let Some((word, num_bytes)) = mhash.pop_front() {
        let mut remaining = word;
        let mut bytes_left = num_bytes;

        while bytes_left > 0 {
            // Extract one byte (big-endian)
            let shift = (bytes_left - 1) * 8;
            let byte_val = if shift == 24 {
                remaining / 0x1000000
            } else if shift == 16 {
                (remaining / 0x10000) % 0x100
            } else if shift == 8 {
                (remaining / 0x100) % 0x100
            } else {
                remaining % 0x100
            };

            acc = acc * 0x100 + byte_val;
            acc_bits += 8;

            // Extract 14-bit indices when we have enough bits
            while acc_bits >= 14 && indices.len() < SPX_FORS_TREES {
                let shift_amount = acc_bits - 14;
                let divisor: u32 = if shift_amount == 0 {
                    1
                } else {
                    let mut d: u32 = 1;
                    let mut i: u32 = 0;
                    while i < shift_amount {
                        d *= 2;
                        i += 1;
                    }
                    d
                };
                let index = acc / divisor;
                let mask = divisor - 1;
                acc = acc & mask;
                acc_bits -= 14;
                indices.append(index % 0x4000); // Ensure 14-bit value (max 16383)
            }

            bytes_left -= 1;
        }
    }

    indices
}

/// Derive FORS public key from signature.
pub fn fors_pk_from_sig(
    ctx: SpxCtx, sig: ForsSignature, mhash: WordSpan, address: @Address,
) -> HashOutput {
    let mut fors_tree_addr = address.clone();
    fors_tree_addr.set_address_type(AddressType::FORSTREE);

    // Compute indices from message hash
    let mut indices = message_to_indices_btc(mhash);

    let mut idx_offset: u32 = 0;
    let mut roots: Array<u32> = array![];

    let mut sig_iter = sig.span();
    let mut tree_idx: usize = 0;

    while let Some(tree_sig) = sig_iter.pop_front() {
        let ForsTreeSignature { sk_seed, auth_path } = *tree_sig;

        // Get leaf index for this tree (or 0 if we ran out of indices)
        let leaf_idx = if tree_idx < indices.len() {
            *indices[tree_idx]
        } else {
            0
        };

        fors_tree_addr.set_tree_index(idx_offset + leaf_idx);

        // Derive the leaf hash from the secret key seed
        let leaf = thash_btc(ctx, @fors_tree_addr, sk_seed.span());

        // Compute root using auth path
        let root = compute_root(ctx, @fors_tree_addr, leaf, auth_path.span(), leaf_idx, idx_offset);
        roots.append_span(root.span());

        idx_offset += SPX_FORS_BASE_OFFSET;
        tree_idx += 1;
    }

    // Hash horizontally across all tree roots
    let mut fors_pk_addr = address.clone();
    fors_pk_addr.set_address_type(AddressType::FORSPK);

    thash_btc(ctx, @fors_pk_addr, roots.span())
}

/// Serde for ForsTreeSignature
impl ForsTreeSignatureSerde of Serde<ForsTreeSignature> {
    fn serialize(self: @ForsTreeSignature, ref output: Array<felt252>) {
        HashOutputSerde::serialize(self.sk_seed, ref output);
        for h in self.auth_path.span() {
            HashOutputSerde::serialize(h, ref output);
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<ForsTreeSignature> {
        let sk_seed = HashOutputSerde::deserialize(ref serialized)?;
        let mut auth = array![];
        for _ in 0..SPX_FORS_HEIGHT {
            let h = HashOutputSerde::deserialize(ref serialized)?;
            auth.append(h);
        }
        let auth_path: @Box<[HashOutput; SPX_FORS_HEIGHT]> = auth.span().try_into().unwrap();
        Some(ForsTreeSignature { sk_seed, auth_path: auth_path.unbox() })
    }
}

/// Serde for ForsSignature
pub impl ForsSignatureSerde of Serde<ForsSignature> {
    fn serialize(self: @ForsSignature, ref output: Array<felt252>) {
        for sig in self.span() {
            ForsTreeSignatureSerde::serialize(sig, ref output);
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<ForsSignature> {
        let mut sigs = array![];
        for _ in 0..SPX_FORS_TREES {
            let sig = ForsTreeSignatureSerde::deserialize(ref serialized)?;
            sigs.append(sig);
        }
        let result: @Box<ForsSignature> = sigs.span().try_into().unwrap();
        Some(result.unbox())
    }
}
