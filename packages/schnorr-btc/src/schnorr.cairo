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
/// * `m`: `ByteArray` - The message for which the signature is being verified.
///
/// #### Returns:
/// * `u256` - `sha256(tag) || sha256(tag) || bytes(rx) || bytes(px) || m` as u256 where tag =
/// "BIP0340/challenge".
fn hash_challenge(rx: u256, px: u256, m: ByteArray) -> u256 {
    // Precomputed sha256("BIP0340/challenge") || sha256("BIP0340/challenge")
    let mut ba: ByteArray = Default::default();
    // let ba = arr!
    ba.append_word(0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d3, 31);
    ba.append_word(0x7c7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48, 31);
    ba.append_word(0xd37c, 2);
    // bytes(rx)
    ba.append_word(rx.high.into(), 16);
    ba.append_word(rx.low.into(), 16);
    // bytes(px)
    ba.append_word(px.high.into(), 16);
    ba.append_word(px.low.into(), 16);
    // m
    ba.append(@m);

    let mut hasher: sha256::HashState = Default::default();
    sha256::hash_init(ref hasher);
    let [x0, x1, x2, x3, x4, x5, x6, x7] = sha256::hash_finalize(hasher, ba);

    let high: u128 = x0.into() * TWO_POW_96 + x1.into() * TWO_POW_64 + x2.into() * TWO_POW_32
        + x3.into();
    let low: u128 = x4.into() * TWO_POW_96 + x5.into() * TWO_POW_64 + x6.into() * TWO_POW_32
        + x7.into();
    u256 { high, low }
}

/// Verifies a BIP-340 Schnorr signature using Garaga's EC operations.
///
/// #### Arguments
/// * `pk`: `u256` - The public key point x coordinate.
/// * `rx`: `u256` - The x-coordinate of the R point from the signature.
/// * `s`: `u256` - The scalar component of the signature.
/// * `m`: `ByteArray` - The message for which the signature is being verified.
/// * `msm_hint`: `Span<felt252>` - Precomputed hint data for Garaga's msm_g1.
///
/// #### Returns
/// * `bool` - `true` if the signature is valid, `false` otherwise.
pub fn verify(pk: G1Point, rx: u256, s: u256, m: ByteArray, msm_hint: Span<felt252>) -> bool {
    let px = into_u256_unchecked(pk.x);
    
    // BIP-340 bound checks
    if px >= SECP256K1_P || rx >= SECP256K1_P {
        return false;
    };

    // e = int(hash_BIP0340/challenge(bytes(rx) || bytes(px) || m)) mod n
    let n: u256 = get_n(SECP256K1_INDEX);
    let e = hash_challenge(rx, px, m) % n;

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
