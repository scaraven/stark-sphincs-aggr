//! BIP-340 Schnorr signature verification using Garaga EC operations.
//!
//! Replaces starknet secp256k1 syscalls with Garaga's circuit-based EC operations,
//! enabling standalone Stwo proving via `#[executable]` mode.
use crate::sha256;
use core::circuit::u384;
use garaga::core::circuit::into_u256_unchecked;
use garaga::ec_ops::{G1PointTrait, msm_g1};
use garaga::basic_field_ops::{is_even_u384, neg_mod_p};
use garaga::utils::u384_eq_zero;
use garaga::definitions::{Zero, get_curve_order_modulus, G1Point, get_n, get_G};

const TWO_POW_32: u128 = 0x100000000;
const TWO_POW_64: u128 = 0x10000000000000000;
const TWO_POW_96: u128 = 0x1000000000000000000000000;

/// Converts a u256 to 8 big-endian u32 words.
#[inline(always)]
fn u256_to_u32_be_words(v: u256) -> [u32; 8] {
    let h = v.high;
    let l = v.low;
    let w0: u32 = (h / TWO_POW_96).try_into().unwrap();
    let w1: u32 = ((h / TWO_POW_64) % TWO_POW_32).try_into().unwrap();
    let w2: u32 = ((h / TWO_POW_32) % TWO_POW_32).try_into().unwrap();
    let w3: u32 = (h % TWO_POW_32).try_into().unwrap();
    let w4: u32 = (l / TWO_POW_96).try_into().unwrap();
    let w5: u32 = ((l / TWO_POW_64) % TWO_POW_32).try_into().unwrap();
    let w6: u32 = ((l / TWO_POW_32) % TWO_POW_32).try_into().unwrap();
    let w7: u32 = (l % TWO_POW_32).try_into().unwrap();
    [w0, w1, w2, w3, w4, w5, w6, w7]
}

/// secp256k1 field prime.
const SECP256K1_P: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

/// secp256k1 curve index in Garaga.
const SECP256K1_INDEX: usize = 2;

#[derive(Drop, Debug, PartialEq)]
struct SchnorrSignatureInternal {
    pub rx: u384,
    pub s: u256,
    pub e: u256,
}

#[derive(Drop, PartialEq)]
struct SchnorrSignatureWithHintInternal {
    signature: SchnorrSignatureInternal,
    msm_hint: Span<felt252>,
}

/// Computes BIP0340/challenge tagged hash.
///
/// References:
///   BIP-340:
///   https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
///   reference implementation:
///   https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py
///
/// ## Acknowledgements: This has been adapted from
/// https://github.com/keep-starknet-strange/alexandria/blob/main/packages/btc/src/bip340.cairo
///
/// #### Arguments:
/// * `rx`: `u256` - The x-coordinate of the R point from the signature.
/// * `px`: `u256` - The x-coordinate of the public key.
/// * `m`: `Array<u32>` - Full u32 words of the message (big-endian).
/// * `m_last_word`: `u32` - Last partial word (0 if aligned).
/// * `m_last_word_len`: `u32` - Number of bytes in last word (0-3).
///
/// #### Returns:
/// * `u256` - `sha256(tag) || sha256(tag) || bytes(rx) || bytes(px) || m` as u256 where tag =
/// "BIP0340/challenge".
fn hash_challenge(
    rx: u256, px: u256, m: Array<u32>, m_last_word: u32, m_last_word_len: u32,
) -> u256 {
    let mut hasher: sha256::HashState = Default::default();
    sha256::hash_init(ref hasher);

    // Block 1: BIP0340/challenge tag (sha256("BIP0340/challenge") doubled = 16 words)
    // Precomputed: sha256("BIP0340/challenge") = 7bb52d7a 9fef5832 3eb1bf7a 407db382 d2f3f2d8 1bb1224f 49fe518f 6d48d37c
    sha256::hash_update_block(
        ref hasher,
        [
            0x7bb52d7a, 0x9fef5832, 0x3eb1bf7a, 0x407db382, 0xd2f3f2d8, 0x1bb1224f, 0x49fe518f,
            0x6d48d37c, 0x7bb52d7a, 0x9fef5832, 0x3eb1bf7a, 0x407db382, 0xd2f3f2d8, 0x1bb1224f,
            0x49fe518f, 0x6d48d37c,
        ],
    );

    // Block 2: rx (8 words) + px (8 words)
    let [r0, r1, r2, r3, r4, r5, r6, r7] = u256_to_u32_be_words(rx);
    let [p0, p1, p2, p3, p4, p5, p6, p7] = u256_to_u32_be_words(px);
    sha256::hash_update_block(
        ref hasher, [r0, r1, r2, r3, r4, r5, r6, r7, p0, p1, p2, p3, p4, p5, p6, p7],
    );

    // Finalize with message
    let [x0, x1, x2, x3, x4, x5, x6, x7] = sha256::hash_finalize(hasher, m, m_last_word, m_last_word_len);

    let high: u128 = x0.into() * TWO_POW_96 + x1.into() * TWO_POW_64 + x2.into() * TWO_POW_32
        + x3.into();
    let low: u128 = x4.into() * TWO_POW_96 + x5.into() * TWO_POW_64 + x6.into() * TWO_POW_32
        + x7.into();
    u256 { high, low }
}

/// Verifies a BIP-340 Schnorr signature using Garaga's EC operations.
///
/// #### Arguments
/// * `pk`: `G1Point` - The public key point.
/// * `rx`: `u256` - The x-coordinate of the R point from the signature.
/// * `s`: `u256` - The scalar component of the signature.
/// * `m`: `Array<u32>` - Full u32 words of the message (big-endian).
/// * `m_last_word`: `u32` - Last partial word (0 if aligned).
/// * `m_last_word_len`: `u32` - Number of bytes in last word (0-3).
/// * `msm_hint`: `Span<felt252>` - Precomputed hint data for Garaga's msm_g1.
///
/// #### Returns
/// * `bool` - `true` if the signature is valid, `false` otherwise.
pub fn verify(
    pk: G1Point,
    rx: u256,
    s: u256,
    m: Array<u32>,
    m_last_word: u32,
    m_last_word_len: u32,
    msm_hint: Span<felt252>,
) -> bool {
    let px = into_u256_unchecked(pk.x);

    // BIP-340 bound checks
    if px >= SECP256K1_P || rx >= SECP256K1_P {
        return false;
    };

    // e = int(hash_BIP0340/challenge(bytes(rx) || bytes(px) || m)) mod n
    let n: u256 = get_n(SECP256K1_INDEX);
    let e = hash_challenge(rx, px, m, m_last_word, m_last_word_len) % n;

    // Build garaga SchnorrSignatureWithHint and delegate verification.
    // Garaga checks: s, e are in [1, n-1], pk is on curve with even y,
    // computes R = s*G - e*P, and verifies R.x == rx with even R.y.

    let rx: u384 = rx.into();
    let signature = SchnorrSignatureInternal { rx, s, e };
    let sig_with_hint = SchnorrSignatureWithHintInternal { signature, msm_hint };

    is_valid_schnorr_signature_assuming_hash(sig_with_hint, pk, SECP256K1_INDEX)
}

/// Verifies a Schnorr signature with associated hints, assuming the hash challenge is correct.
///
/// # Important Assumption
/// **This function assumes that the hash `e` has been correctly derived from `x_R` and the message
/// by the caller.** It does not compute or verify the hash derivation itself. The caller is
/// responsible for ensuring that `e = H(x_R || message)` (or the appropriate hash construction for
/// their protocol) before calling this function.
///
/// # Arguments
/// * `signature`: `SchnorrSignatureWithHint` - The signature and verification data bundle
/// containing:
///     - rx: The x-coordinate of the R point
///     - s: The s component of the signature
///     - e: The challenge hash (assumed to be correctly computed by the caller)
///     - msm_hint: Hint for multi-scalar multiplication
/// * `public_key`: `G1Point` - The public key to verify against.
/// * `curve_id`: `usize` - The id of the curve. (0 for BN254, 1 for BLS12_381, 2 for SECP256K1, 3
/// for SECP256R1, 4 for ED25519, 5 for GRUMPKIN)
///
/// # Algorithm
/// The Schnorr signature verification checks if the signature (R, s) is valid for a given challenge
/// hash e and public key P:
/// 1. Verify that all inputs (rx, s, e) are non-zero and less than the curve order n
/// 2. Verify that the public key P is on the curve and has even y-coordinate (BIP340 requirement,
/// see
/// https://github.com/bitcoin/bips/blob/58ffd93812ff25e87d53d1f202fbb389fdfb85bb/bip-0340/reference.py#L71)
/// 3. Compute sG - eP where G is the generator point (using MSM)
/// 4. Verify that the result equals R (matching x-coordinate and even y-coordinate)
/// 5. The signature is valid if all checks pass
///
/// This implements the verification equation: sG - eP = R
/// Which proves the signer knew the private key x where P = xG, given that e was correctly derived.
/// Returns false if the signature is invalid.
pub fn is_valid_schnorr_signature_assuming_hash(
    signature: SchnorrSignatureWithHintInternal, public_key: G1Point, curve_id: usize,
) -> bool {
    let SchnorrSignatureWithHintInternal { signature, msm_hint } = signature;
    let SchnorrSignatureInternal { rx, s, e } = signature;

    let n: u256 = get_n(curve_id);

    if u384_eq_zero(rx)
        || s >= n
        || s == 0
        || e >= n
        || e == 0
        || is_even_u384(public_key.y) == false {
        return false;
    }

    let pk_on_curve = public_key.is_on_curve_excluding_infinity(curve_id);

    if pk_on_curve == false {
        return false;
    }

    let n_modulus = get_curve_order_modulus(curve_id);

    let e_neg: u256 = neg_mod_p(e.into(), n_modulus).try_into().unwrap();

    let points = array![get_G(curve_id), public_key].span();
    let scalars = array![s, e_neg].span();

    let res = msm_g1(points, scalars, curve_id, msm_hint);

    let ry_l0_f252: felt252 = res.y.limb0.into();
    let ry_l0_u128: u128 = ry_l0_f252.try_into().unwrap();

    if res.is_zero() || res.x != rx || (ry_l0_u128 % 2) != 0 {
        return false;
    }

    true
}
