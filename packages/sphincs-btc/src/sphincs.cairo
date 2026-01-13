// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! Bitcoin-optimized SPHINCS+ verification.
//!
//! Parameters:
//! - h=32 (total tree height)
//! - d=4 (number of hypertree layers)
//! - k=10 (FORS trees)
//! - a=14 (FORS tree height)
//! - w=256 (Winternitz parameter)
//! - n=16 (hash output bytes)

use crate::address::{Address, AddressTrait, AddressType};
use crate::fors::{ForsSignature, ForsSignatureSerde, fors_pk_from_sig};
use crate::hasher::{
    HashOutput, HashOutputSerde, compute_root, hash_message_btc, initialize_hash_function,
    thash_btc,
};
use crate::params_btc::{SPX_D, SPX_DGST_BYTES, SPX_TREE_HEIGHT};
use crate::word_array::{WordArrayTrait, WordSpan, WordSpanTrait};
use crate::wots_c::{WotsCSignature, WotsCSignatureSerde, wots_c_pk_from_sig};

/// SPHINCS+ BTC signature structure.
#[derive(Drop, Default, Copy)]
pub struct SphincsSignature {
    /// Random value used for message hashing
    pub randomizer: HashOutput,
    /// FORS signature
    pub fors_sig: ForsSignature,
    /// WOTS+C Merkle signatures for each hypertree layer
    pub wots_merkle_sig_list: [WotsCMerkleSignature; SPX_D],
}

/// SPHINCS+ public key.
#[derive(Drop, Default, Copy)]
pub struct SphincsPublicKey {
    pub pk_seed: HashOutput,
    pub pk_root: HashOutput,
}

/// WOTS+C Merkle signature for one hypertree layer.
#[derive(Drop, Default, Copy)]
pub struct WotsCMerkleSignature {
    pub wots_sig: WotsCSignature,
    pub auth_path: [HashOutput; SPX_TREE_HEIGHT],
}

/// Extended message digest after hashing.
#[derive(Drop)]
pub struct XMessageDigest {
    pub mhash: WordSpan,
    pub tree_address: u32,
    pub leaf_idx: u8,
}

/// Verify a Bitcoin-optimized SPHINCS+ signature.
pub fn verify_btc(message: WordSpan, sig: SphincsSignature, pk: SphincsPublicKey) -> bool {
    let SphincsSignature { randomizer, fors_sig, wots_merkle_sig_list } = sig;
    let SphincsPublicKey { pk_seed, pk_root } = pk;

    // Seed the hash function state
    let ctx = initialize_hash_function(pk_seed);

    // Initialize address
    let mut tree_addr: Address = Default::default();
    tree_addr.set_address_type(AddressType::HASHTREE);

    // Compute the extended message digest: mhash || tree_idx || leaf_idx
    let digest = hash_message_btc(randomizer, pk_seed, pk_root, message, SPX_DGST_BYTES);

    // Split the digest into components
    let XMessageDigest { mhash, mut tree_address, mut leaf_idx } = split_xdigest_btc(digest.span());

    debug_print_header(tree_address, leaf_idx);

    let mut wots_addr: Address = Default::default();
    wots_addr.set_address_type(AddressType::WOTS);
    wots_addr.set_hypertree_addr(tree_address.into());
    wots_addr.set_keypair(leaf_idx.into());

    // Compute FORS public key (root) from the signature
    let mut root = fors_pk_from_sig(ctx, fors_sig, mhash, @wots_addr);

    debug_print_fors_root(root);

    let mut layer: u8 = 0;
    let mut wots_merkle_sig_iter = wots_merkle_sig_list.span();

    while let Some(WotsCMerkleSignature { wots_sig, auth_path }) = wots_merkle_sig_iter.pop_front() {
        tree_addr.set_hypertree_layer(layer);
        tree_addr.set_hypertree_addr(tree_address.into());

        wots_addr = tree_addr.clone();
        wots_addr.set_address_type(AddressType::WOTS);
        wots_addr.set_keypair(leaf_idx.into());

        let mut wots_pk_addr = wots_addr.clone();
        wots_pk_addr.set_address_type(AddressType::WOTSPK);

        debug_print_layer(layer, tree_address, leaf_idx, root, *wots_sig.counter);

        // Derive WOTS+C public key from signature
        // root is the message being signed (FORS pk at layer 0, subtree root otherwise)
        let wots_pk = wots_c_pk_from_sig(ctx, *wots_sig, root, @wots_addr);

        debug_print_wots_pk_len(wots_pk.len());

        // Compute the leaf node using the WOTS public key
        let leaf = thash_btc(ctx, @wots_pk_addr, wots_pk.span());

        debug_print_leaf(leaf);

        // Compute the root of this subtree
        root = compute_root(ctx, @tree_addr, leaf, auth_path.span(), leaf_idx.into(), 0);

        debug_print_computed_root(root);

        // Update indices for the next layer
        // With tree_height=8, each subtree has 256 leaves
        let (q, r) = DivRem::div_rem(tree_address, 0x100); // 2^8 = 256
        tree_address = q;
        leaf_idx = r.try_into().unwrap();
        layer += 1;
    }

    // Check if the root node equals the root in the public key
    debug_print_final(root, pk_root);
    root == pk_root
}

// Debug helper functions - only active when debug feature is enabled
#[cfg(feature: "debug")]
fn debug_print_header(tree_address: u32, leaf_idx: u8) {
    println!("=== SPHINCS+ BTC Verification ===");
    println!("tree_address: {}", tree_address);
    println!("leaf_idx: {}", leaf_idx);
}

#[cfg(not(feature: "debug"))]
fn debug_print_header(_tree_address: u32, _leaf_idx: u8) {}

#[cfg(feature: "debug")]
fn debug_print_fors_root(root: HashOutput) {
    println!("FORS root: {}", crate::hasher::to_hex(root.span()));
}

#[cfg(not(feature: "debug"))]
fn debug_print_fors_root(_root: HashOutput) {}

#[cfg(feature: "debug")]
fn debug_print_layer(layer: u8, tree_address: u32, leaf_idx: u8, root: HashOutput, counter: u32) {
    println!("--- Layer {} ---", layer);
    println!("  tree_address: {}", tree_address);
    println!("  leaf_idx: {}", leaf_idx);
    println!("  message (root): {}", crate::hasher::to_hex(root.span()));
    println!("  counter: {}", counter);
}

#[cfg(not(feature: "debug"))]
fn debug_print_layer(_layer: u8, _tree_address: u32, _leaf_idx: u8, _root: HashOutput, _counter: u32) {}

#[cfg(feature: "debug")]
fn debug_print_wots_pk_len(len: usize) {
    println!("  wots_pk len: {}", len);
}

#[cfg(not(feature: "debug"))]
fn debug_print_wots_pk_len(_len: usize) {}

#[cfg(feature: "debug")]
fn debug_print_leaf(leaf: HashOutput) {
    println!("  leaf: {}", crate::hasher::to_hex(leaf.span()));
}

#[cfg(not(feature: "debug"))]
fn debug_print_leaf(_leaf: HashOutput) {}

#[cfg(feature: "debug")]
fn debug_print_computed_root(root: HashOutput) {
    println!("  computed root: {}", crate::hasher::to_hex(root.span()));
}

#[cfg(not(feature: "debug"))]
fn debug_print_computed_root(_root: HashOutput) {}

#[cfg(feature: "debug")]
fn debug_print_final(root: HashOutput, pk_root: HashOutput) {
    println!("=== Final Comparison ===");
    println!("computed root: {}", crate::hasher::to_hex(root.span()));
    println!("expected pk_root: {}", crate::hasher::to_hex(pk_root.span()));
    println!("match: {}", root == pk_root);
}

#[cfg(not(feature: "debug"))]
fn debug_print_final(_root: HashOutput, _pk_root: HashOutput) {}

/// Split the extended message digest into components.
/// For BTC params: mhash (18 bytes) || tree_addr (3 bytes) || leaf_idx (1 byte)
fn split_xdigest_btc(mut digest: WordSpan) -> XMessageDigest {
    let (mut words, last_word, _) = digest.into_components();

    // Extended digest is 22 bytes:
    // - mhash: 18 bytes (FORS message hash for k=10, a=14)
    // - tree_address: 3 bytes (24 bits for h=32, d=4: 3 layers * 8 bits = 24 bits)
    // - leaf_idx: 1 byte (8 bits for tree_height=8)

    // Last word structure (2 bytes): high byte is part of tree_addr, low byte is leaf_idx
    let leaf_idx: u8 = (last_word % 0x100).try_into().unwrap();
    let tree_addr_lo: u8 = ((last_word / 0x100) % 0x100).try_into().unwrap();

    // Second to last full word contains more of tree_address
    let w5 = *words.pop_back().unwrap();
    let tree_addr_mid: u16 = (w5 % 0x10000).try_into().unwrap();
    let mhash_partial = w5 / 0x10000; // Top 2 bytes belong to mhash

    // tree_address = tree_addr_mid (16 bits) << 8 + tree_addr_lo (8 bits)
    let tree_address: u32 = tree_addr_mid.into() * 0x100 + tree_addr_lo.into();

    // mhash is first 18 bytes:
    // 4 full words (16 bytes) + 2 bytes from the partial word
    let mhash = WordSpanTrait::new(words, mhash_partial, 2);

    XMessageDigest { mhash, tree_address, leaf_idx }
}

/// Serde for WotsCMerkleSignature
impl WotsCMerkleSignatureSerde of Serde<WotsCMerkleSignature> {
    fn serialize(self: @WotsCMerkleSignature, ref output: Array<felt252>) {
        WotsCSignatureSerde::serialize(self.wots_sig, ref output);
        for h in self.auth_path.span() {
            HashOutputSerde::serialize(h, ref output);
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<WotsCMerkleSignature> {
        let wots_sig = WotsCSignatureSerde::deserialize(ref serialized)?;
        let mut auth = array![];
        for _ in 0..SPX_TREE_HEIGHT {
            let h = HashOutputSerde::deserialize(ref serialized)?;
            auth.append(h);
        }
        let auth_path: @Box<[HashOutput; SPX_TREE_HEIGHT]> = auth.span().try_into().unwrap();
        Some(WotsCMerkleSignature { wots_sig, auth_path: auth_path.unbox() })
    }
}

/// Serde for SphincsPublicKey
impl SphincsPublicKeySerde of Serde<SphincsPublicKey> {
    fn serialize(self: @SphincsPublicKey, ref output: Array<felt252>) {
        HashOutputSerde::serialize(self.pk_seed, ref output);
        HashOutputSerde::serialize(self.pk_root, ref output);
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<SphincsPublicKey> {
        let pk_seed = HashOutputSerde::deserialize(ref serialized)?;
        let pk_root = HashOutputSerde::deserialize(ref serialized)?;
        Some(SphincsPublicKey { pk_seed, pk_root })
    }
}

/// Serde for SphincsSignature
impl SphincsSignatureSerde of Serde<SphincsSignature> {
    fn serialize(self: @SphincsSignature, ref output: Array<felt252>) {
        HashOutputSerde::serialize(self.randomizer, ref output);
        ForsSignatureSerde::serialize(self.fors_sig, ref output);
        for wms in self.wots_merkle_sig_list.span() {
            WotsCMerkleSignatureSerde::serialize(wms, ref output);
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<SphincsSignature> {
        let randomizer = HashOutputSerde::deserialize(ref serialized)?;
        let fors_sig = ForsSignatureSerde::deserialize(ref serialized)?;
        let mut wots_list = array![];
        for _ in 0..SPX_D {
            let wms = WotsCMerkleSignatureSerde::deserialize(ref serialized)?;
            wots_list.append(wms);
        }
        let wots_merkle_sig_list: @Box<[WotsCMerkleSignature; SPX_D]> = wots_list.span().try_into().unwrap();
        Some(SphincsSignature { randomizer, fors_sig, wots_merkle_sig_list: wots_merkle_sig_list.unbox() })
    }
}
