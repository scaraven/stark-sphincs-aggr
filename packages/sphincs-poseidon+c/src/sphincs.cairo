// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT
use crate::address::{Address, AddressTrait, AddressType};
use crate::fors::{ForsSignature, fors_pk_from_sig};
use crate::hasher::{
    HashOutput, SpxCtx, felt252_to_u32_array, hash_message_128s, initialize_hash_function, thash,
    partial_seed_4, compute_root_with_pctx,
};
use crate::params_128s::{SPX_D, SPX_TREE_HEIGHT};
use crate::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};
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
    pub counter: felt252, // Used in WOTS+C
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
    let ctx = initialize_hash_function(pk.pk_seed);
    verify_128s_with_ctx(ctx, message, sig, pk)
}

/// Verify a signature using a pre-initialized hash context.
/// This allows sharing the context across multiple signatures in batch verification.
pub fn verify_128s_with_ctx(
    ctx: SpxCtx, message: WordSpan, sig: SphincsSignature, pk: SphincsPublicKey,
) -> bool {
    let SphincsSignature { randomizer, fors_sig, wots_merkle_sig_list } = sig;
    let SphincsPublicKey { pk_seed, pk_root } = pk;

    // Initialize address
    let mut tree_addr: Address = Default::default();
    tree_addr.set_address_type(AddressType::HASHTREE);

    // Compute the extended message digest which is `mhash || tree_idx || leaf_idx`.
    let digest = hash_message_128s(randomizer, pk_seed, pk_root, message);

    // Split the digest into the message hash, tree address and leaf index.
    let XMessageDigest { mhash, mut tree_address, mut leaf_idx } = split_xdigest_128s(digest);

    debug_print_header(tree_address, leaf_idx);

    let mut wots_addr: Address = Default::default();
    wots_addr.set_address_type(AddressType::WOTS);
    wots_addr.set_hypertree_addr(tree_address);
    wots_addr.set_keypair(leaf_idx);

    // Compute FORS public key (root) from the signature.
    let mut root = fors_pk_from_sig(ctx, fors_sig, mhash, @wots_addr);

    debug_print_fors_root(root);

    let mut layer: u8 = 0;
    let mut wots_merkle_sig_iter = wots_merkle_sig_list.span();

    while let Some(WotsMerkleSignature { wots_sig, counter, auth_path }) = wots_merkle_sig_iter.pop_front() {
        debug_print_layer(layer, tree_address, leaf_idx, *counter, root);

        tree_addr.set_hypertree_layer(layer);
        tree_addr.set_hypertree_addr(tree_address);

        wots_addr = tree_addr;
        wots_addr.set_address_type(AddressType::WOTS);
        wots_addr.set_keypair(leaf_idx);

        let mut wots_pk_addr = wots_addr;
        wots_pk_addr.set_address_type(AddressType::WOTSPK);

        // The WOTS public key is only correct if the signature was correct.
        // Initially, root is the FORS pk, but on subsequent iterations it is
        // the root of the subtree below the currently processed subtree.

        // Create digest from root as modified message for WOTS+ signature verification.
        let root_digest = thash(ctx, @wots_pk_addr, array![root, *counter].span());

        // Convert the root into an array of u32
        let mut root_u32: u256 = root_digest.into();
        let mut root_u32_array: Array<u32> = array![];
        // Split u256 into array of u32
        for _ in 0..4_usize {
            let (part, remainder) = DivRem::div_rem(root_u32, 0x100000000);
            root_u32 = part;
            root_u32_array.append(remainder.try_into().unwrap());
        }

        let wots_pk = wots_pk_from_sig(ctx, *wots_sig, root_u32_array, @wots_addr);

        debug_print_wots_pk(wots_pk.len());

        // Compute the leaf node using the WOTS public key.
        let leaf = thash(ctx, @wots_pk_addr, wots_pk.span());

        debug_print_leaf(leaf);

        // Compute the root node of this subtree using optimized partial context.
        // Pre-absorb pk_seed + a0-a3 (constant within this tree traversal).
        let [a0, a1, a2, a3, _, _] = tree_addr.into_field_components();
        let tree_pctx = partial_seed_4(ctx, a0, a1, a2, a3);
        root = compute_root_with_pctx(
            tree_pctx, @tree_addr, leaf, auth_path.span(), leaf_idx.into(), 0,
        );

        debug_print_computed_root(root);

        // Update the indices for the next layer.
        let (q, r) = DivRem::div_rem(tree_address, 0x800); // 1 << tree_height = 2^11 = 0x800
        tree_address = q;
        leaf_idx = r.try_into().unwrap();
        layer += 1;
    }

    debug_print_final(root, pk_root);

    // Check if the root node equals the root node in the public key.
    return root == pk_root;
}

/// Verify multiple SPHINCS+ signatures in batch.
/// Returns true if ALL signatures are valid, false if ANY signature is invalid.
/// Optimized to share the hash context across all signatures since they use the same pk_seed.
pub fn verify_128s_batch(
    sig_msg_pairs: Span<(SphincsSignature, WordArray)>, pk: SphincsPublicKey,
) -> bool {
    // Initialize context once for all signatures (shared pk_seed).
    let ctx = initialize_hash_function(pk.pk_seed);

    let mut iter = sig_msg_pairs;

    for (sig, message) in iter {
        let valid = verify_128s_with_ctx(ctx, message.span(), *sig, pk);
        if !valid {
            return false;
        }
    }
    true
}

/// Split the extended message digest into the message hash, tree address and leaf index.
/// Note, we work backwards from the least significant bits rather than forwards.
///
/// For sphincs-poseidon+c params (SPX_DGST_BYTES = 22):
///   Digest layout (from LSB):
///     bits  0-10  : leaf_idx       (SPX_LEAF_BITS = 11)
///     bits 11-15  : unused         (SPX_LEAF_BYTES*8 - SPX_LEAF_BITS = 5)
///     bits 16-37  : tree_address   (SPX_TREE_BITS = 22)
///     bits 38-39  : unused         (SPX_TREE_BYTES*8 - SPX_TREE_BITS = 2)
///     bits 40-175 : mhash          (SPX_FORS_MSG_BYTES = 17 bytes = 136 bits)
///     bits 176+   : 0 (digest fits in 176 bits)
///
///   In the 8 u32 words [a,b,c,d,e,f,g,h] (a=MSB, h=LSB):
///     a = 0, b = 0  (zero, beyond 176-bit digest)
///     c < 2^16      (only lower 16 bits used, holds mhash bytes 15-16)
///     d             (mhash bytes 11-14)
///     e             (mhash bytes 7-10)
///     f             (mhash bytes 3-6)
///     g[8:32]       (mhash bytes 0-2)
///     g[6:8]        (2 unused tree bits)
///     g[0:6]        (tree_address bits 16-21, upper 6 bits)
///     h[16:32]      (tree_address bits  0-15, lower 16 bits)
///     h[11:16]      (5 unused leaf bits)
///     h[0:11]       (leaf_idx)
fn split_xdigest_128s(digest: felt252) -> XMessageDigest {
    // Split felt252 into u32 words, big-endian (a = most significant, h = least significant)
    let [_a, _b, c, d, e, f, g, h] = felt252_to_u32_array(digest);

    // --- leaf_idx: lower 11 bits of h (SPX_LEAF_BITS = 11, divisor = 2^11 = 0x800) ---
    let (h_rem, leaf_idx) = DivRem::div_rem(h, 0x800);
    let leaf_idx = leaf_idx.try_into().unwrap();

    // h_rem = h[11:32] (21 bits). Skip h[11:16] (5 unused bits, SPX_LEAF_BYTES*8 - SPX_LEAF_BITS).
    // h_tree = h[16:32] = lower 16 bits of tree_address.
    let h_tree = h_rem / 0x20; // drop 5 bits → bits 16-31 of h

    // --- tree_address: 22 bits (SPX_TREE_BITS) spanning g[0:6] and h[16:32] ---
    // g[0:6] = upper 6 bits of tree_address; g[6:8] = 2 unused bits; g[8:32] = 3 mhash bytes.
    let (g_div, g_tree) = DivRem::div_rem(g, 0x40); // g_tree = g[0:6], g_div = g[6:32]
    // Skip g[6:8] (2 unused bits, SPX_TREE_BYTES*8 - SPX_TREE_BITS).
    let (g_mhash, _) = DivRem::div_rem(g_div, 0x4); // g_mhash = g[8:32] (24 bits, 3 bytes)

    // tree_address: g_tree (bits 16-21) as high part, h_tree (bits 0-15) as low part.
    let tree_address: u64 = g_tree.into() * 0x10000 + h_tree.into();

    // --- mhash: 17 bytes = 136 bits (SPX_FORS_MSG_BYTES = 17) ---
    // Sources (from MSB to LSB of mhash):
    //   g[8:32] = 3 bytes  (g_mhash, 24 bits)
    //   f       = 4 bytes
    //   e       = 4 bytes
    //   d       = 4 bytes
    //   c[0:16] = 2 bytes  (c < 2^16 for a 176-bit digest)
    //
    // Pack into 4 full u32 words + 1 last byte using an 8-bit sliding boundary:
    //   word0 = g_mhash[3B] || f[top 1B]
    //   word1 = f[bot 3B]   || e[top 1B]
    //   word2 = e[bot 3B]   || d[top 1B]
    //   word3 = d[bot 3B]   || c[top 1B]
    //   last  = c[bot 1B]
    let (f_high, f_low) = DivRem::div_rem(f, 0x1000000); // f_high=top byte, f_low=bottom 3 bytes
    let (e_high, e_low) = DivRem::div_rem(e, 0x1000000);
    let (d_high, d_low) = DivRem::div_rem(d, 0x1000000);
    let (c_high, c_bot) = DivRem::div_rem(c, 0x100); // c < 2^16: c_high=top byte, c_bot=bottom byte

    let arr: Array<u32> = array![
        g_mhash * 0x100 + f_high, // g[8:32] (3B) || f[top 1B]
        f_low * 0x100 + e_high, // f[bot 3B]   || e[top 1B]
        e_low * 0x100 + d_high, // e[bot 3B]   || d[top 1B]
        d_low * 0x100 + c_high, // d[bot 3B]   || c[top 1B]
    ];

    let mhash = WordSpanTrait::new(arr.span(), c_bot, 1);

    XMessageDigest { mhash, tree_address, leaf_idx }
}

// Debug helper functions - only active when debug feature is enabled
#[cfg(feature: "debug")]
fn felt252_to_hex(value: felt252) -> ByteArray {
    let arr = felt252_to_u32_array(value);
    let word_span = WordSpanTrait::new(arr.span(), 0, 0);
    crate::word_array::hex::words_to_hex(word_span)
}

#[cfg(feature: "debug")]
fn debug_print_header(tree_address: u64, leaf_idx: u16) {
    println!("=== SPHINCS+ Poseidon Verification ===");
    println!("tree_address: {}", tree_address);
    println!("leaf_idx: {}", leaf_idx);
}

#[cfg(not(feature: "debug"))]
fn debug_print_header(_tree_address: u64, _leaf_idx: u16) {}

#[cfg(feature: "debug")]
fn debug_print_fors_root(root: felt252) {
    println!("FORS root: {}", felt252_to_hex(root));
}

#[cfg(not(feature: "debug"))]
fn debug_print_fors_root(_root: felt252) {}

#[cfg(feature: "debug")]
fn debug_print_layer(layer: u8, tree_address: u64, leaf_idx: u16, counter: felt252, root: felt252) {
    println!("--- Layer {} ---", layer);
    println!("  tree_address: {}", tree_address);
    println!("  leaf_idx: {}", leaf_idx);
    println!("  counter: {}", counter);
    println!("  message (root): {}", felt252_to_hex(root));
}

#[cfg(not(feature: "debug"))]
fn debug_print_layer(_layer: u8, _tree_address: u64, _leaf_idx: u16, _counter: felt252, _root: felt252) {}

#[cfg(feature: "debug")]
fn debug_print_wots_pk(len: usize) {
    println!("  wots_pk len: {}", len);
}

#[cfg(not(feature: "debug"))]
fn debug_print_wots_pk(_len: usize) {}

#[cfg(feature: "debug")]
fn debug_print_leaf(leaf: felt252) {
    println!("  leaf: {}", felt252_to_hex(leaf));
}

#[cfg(not(feature: "debug"))]
fn debug_print_leaf(_leaf: felt252) {}

#[cfg(feature: "debug")]
fn debug_print_computed_root(root: felt252) {
    println!("  computed root: {}", felt252_to_hex(root));
}

#[cfg(not(feature: "debug"))]
fn debug_print_computed_root(_root: felt252) {}

#[cfg(feature: "debug")]
fn debug_print_final(root: felt252, pk_root: felt252) {
    println!("=== Final Comparison ===");
    println!("computed root: {}", felt252_to_hex(root));
    println!("expected pk_root: {}", felt252_to_hex(pk_root));
    println!("match: {}", root == pk_root);
}

#[cfg(not(feature: "debug"))]
fn debug_print_final(_root: felt252, _pk_root: felt252) {}

#[cfg(test)]
mod tests {
    use crate::word_array::hex::words_to_hex;
    use super::*;

    #[test]
    fn test_split_xdigest_128s() {
        // Constructed for sphincs-poseidon+c params (22-byte = 176-bit digest):
        //   SPX_LEAF_BITS=11, SPX_TREE_BITS=22, SPX_FORS_MSG_BYTES=17
        //
        // Digest layout (LSB first):
        //   h[0:11]  = leaf_idx    = 0x7FF
        //   h[11:16] = 0           (5 unused leaf bits)
        //   h[16:32] = 0xFFFF      (tree_address bits  0-15)
        //   g[0:6]   = 0x3F        (tree_address bits 16-21)  => tree_address = 0x3FFFFF
        //   g[6:8]   = 0           (2 unused tree bits)
        //   g[8:32]  = 0x151617    (mhash bytes 0-2)
        //   f        = 0x11121314  (mhash bytes 3-6)
        //   e        = 0x07080910  (mhash bytes 7-10)
        //   d        = 0x03040506  (mhash bytes 11-14)
        //   c        = 0x0102      (mhash bytes 15-16)
        //
        // word values: a=0, b=0, c=0x0102, d=0x03040506, e=0x07080910,
        //              f=0x11121314, g=0x1516173F, h=0xFFFF07FF
        // felt252 hex: 0x01020304050607080910111213141516173FFFFF07FF
        let digest = 0x01020304050607080910111213141516173FFFFF07FF;
        let xdigest = split_xdigest_128s(digest);
        assert_eq!(xdigest.leaf_idx, 0x7FF);
        assert_eq!(xdigest.tree_address, 0x3FFFFF);
        // mhash packing (8-bit boundary slide):
        //   word0 = g[8:32](3B) || f[top 1B] = 0x151617 || 0x11 = 0x15161711
        //   word1 = f[bot 3B]   || e[top 1B] = 0x121314 || 0x07 = 0x12131407
        //   word2 = e[bot 3B]   || d[top 1B] = 0x080910 || 0x03 = 0x08091003
        //   word3 = d[bot 3B]   || c[top 1B] = 0x040506 || 0x01 = 0x04050601
        //   last  = c[bot 1B]               = 0x02
        assert_eq!(words_to_hex(xdigest.mhash), "1516171112131407080910030405060102");
    }
}
