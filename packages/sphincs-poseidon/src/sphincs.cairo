// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT
use crate::address::{Address, AddressTrait, AddressType};
use crate::fors::{ForsSignature, fors_pk_from_sig};
use crate::hasher::{
    HashOutput, compute_root, hash_message_128s, initialize_hash_function, thash, felt252_to_u32_array
};
use crate::params_128s::{SPX_D, SPX_TREE_HEIGHT};
use crate::word_array::{WordSpan, WordSpanTrait};
use crate::wots::{WotsSignature, WotsSignatureDefault, WotsSignatureSerde, wots_pk_from_sig};

#[derive(Drop, Serde, Default, Copy)]
pub struct SphincsSignature {
    pub randomizer: HashOutput,
    pub fors_sig: ForsSignature,
    pub wots_merkle_sig_list: [WotsMerkleSignature; SPX_D],
}

#[derive(Drop, Serde, Default, Copy)]
pub struct SphincsPublicKey {
    pub pk_seed: HashOutput,
    pub pk_root: HashOutput,
}

#[derive(Drop, Serde, Default, Copy)]
pub struct WotsMerkleSignature {
    pub wots_sig: WotsSignature,
    pub auth_path: [HashOutput; SPX_TREE_HEIGHT],
}

#[derive(Drop)]
pub struct XMessageDigest {
    pub mhash: WordSpan,
    pub tree_address: u64,
    pub leaf_idx: u16,
}

/// Verify a signature for Sphincs+ instantiated with 128s parameters.
pub fn verify_128s(message: WordSpan, sig: SphincsSignature, pk: SphincsPublicKey) -> bool {
    let SphincsSignature { randomizer, fors_sig, wots_merkle_sig_list } = sig;
    let SphincsPublicKey { pk_seed, pk_root } = pk;

    // Seed the hash function state.
    let ctx = initialize_hash_function(pk_seed);

    // Initialize address
    let mut tree_addr: Address = Default::default();
    tree_addr.set_address_type(AddressType::HASHTREE);

    // Compute the extended message digest which is `mhash || tree_idx || leaf_idx`.
    let digest = hash_message_128s(randomizer, pk_seed, pk_root, message);

    // Split the digest into the message hash, tree address and leaf index.
    let XMessageDigest {
        mhash, mut tree_address, mut leaf_idx,
    } = split_xdigest_128s(digest);

    let mut wots_addr: Address = Default::default();
    wots_addr.set_address_type(AddressType::WOTS);
    wots_addr.set_hypertree_addr(tree_address);
    wots_addr.set_keypair(leaf_idx);

    // Compute FORS public key (root) from the signature.
    let mut root = fors_pk_from_sig(ctx, fors_sig, mhash, @wots_addr);

    let mut layer: u8 = 0;
    let mut wots_merkle_sig_iter = wots_merkle_sig_list.span();

    while let Some(WotsMerkleSignature { wots_sig, auth_path }) = wots_merkle_sig_iter.pop_front() {
        tree_addr.set_hypertree_layer(layer);
        tree_addr.set_hypertree_addr(tree_address);

        wots_addr = tree_addr.clone();
        wots_addr.set_address_type(AddressType::WOTS);
        wots_addr.set_keypair(leaf_idx);

        let mut wots_pk_addr = wots_addr.clone();
        wots_pk_addr.set_address_type(AddressType::WOTSPK);

        // The WOTS public key is only correct if the signature was correct.
        // Initially, root is the FORS pk, but on subsequent iterations it is
        // the root of the subtree below the currently processed subtree.

        // Convert the root into an array of u32
        let mut root_u32: u256 = root.into();
        let mut root_u32_array: Array<u32> = array![];
        // Split u256 into array of u32
        for _ in 0..4_usize {
            let (part, remainder) = DivRem::div_rem(root_u32, 0x100000000);
            root_u32 = part;
            root_u32_array.append(remainder.try_into().unwrap());
        }

        let wots_pk = wots_pk_from_sig(ctx, *wots_sig, root_u32_array, @wots_addr);

        // Compute the leaf node using the WOTS public key.
        let leaf = thash(ctx, @wots_pk_addr, wots_pk.span());

        // Compute the root node of this subtree.
        // Auth path has fixed length, so we don't need to assert tree height.
        root = compute_root(ctx, @tree_addr, leaf, auth_path.span(), leaf_idx.into(), 0);

        // Update the indices for the next layer.
        let (q, r) = DivRem::div_rem(tree_address, 0x200); // 1 << tree_height = 2^9 = 0x200
        tree_address = q;
        leaf_idx = r.try_into().unwrap();
        layer += 1;
    }

    // Check if the root node equals the root node in the public key.
    return root == pk_root;
}

/// Split the extended message digest into the message hash, tree address and leaf index.
/// Note, we work backwards from the least significant bits rather than forwards.
fn split_xdigest_128s(digest: felt252) -> XMessageDigest {
    // Split felt252 into u32 words, big-endian
    let [a, b, c, d, e, f, g, h] = felt252_to_u32_array(digest);
    println!("Digest words: {:?}", [a, b, c, d, e, f, g, h]);

    // Work backwards, take last 9 bits from h as leaf index
    let (h_rem, leaf_idx) = DivRem::div_rem(h, 0x200);
    let leaf_idx = leaf_idx.try_into().unwrap();

    // Take the next 54 bits as tree address from h, g
    // h[16:32] + g[0:32] + f[0:6] = 54 bits
    let (_f_div , f_mod) = DivRem::div_rem(f, 0x40); // 6 bits
    let tree_address: u64 = (h_rem.into() / 0x80 + g.into() * 0x10000 + f_mod.into() *  0x1000000000000);

    // f[8:32] + e + d + c + b + a[0:16] = message hash
    // next 21 bytes
    let (_, a_mod) = DivRem::div_rem(a, 0x10000); // take first 16 bits
    let (b_rem, b_mod) = DivRem::div_rem(b, 0x10000);
    let (c_rem, c_mod) = DivRem::div_rem(c, 0x10000);
    let (d_rem, d_mod) = DivRem::div_rem(d, 0x10000);
    let (e_rem, e_mod) = DivRem::div_rem(e, 0x10000);
    let (f_rem, f_mod) = DivRem::div_rem(f, 0x10000);
    let arr: Array<u32> = array![a_mod * 0x10000 + b_rem, 
                                b_mod * 0x10000 + c_rem,
                                c_mod * 0x10000 + d_rem,
                                d_mod * 0x10000 + e_rem, 
                                e_mod * 0x10000 + f_rem];

    let mhash = WordSpanTrait::new(arr.span(), f_mod / 0x100, 1);

    XMessageDigest { mhash, tree_address, leaf_idx }
}

#[cfg(test)]
mod tests {
    use crate::word_array::hex::words_to_hex;
    use super::*;

    #[test]
    fn test_split_xdigest_128s() {
        let digest = 0x5f6f74792de379a6337bbad9e4a1621e38c5e3827d8ae84c41501d68e961;
        let xdigest = split_xdigest_128s(digest);
        assert_eq!(xdigest.leaf_idx, 0x161);
        assert_eq!(xdigest.tree_address, 0xae84c41501d68);
        assert_eq!(words_to_hex(xdigest.mhash), "5f6f74792de379a6337bbad9e4a1621e38c5e3827d");
    }
}
