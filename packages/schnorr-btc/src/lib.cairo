pub mod schnorr;
mod sha256;

use garaga::definitions::G1Point;

#[derive(Drop, Serde)]
pub struct Args {
    /// BIP-340 public key (full point with even y-coordinate).
    pub pk: G1Point,
    /// BIP-340 signature r (x-coordinate of R).
    pub rx: u256,
    /// BIP-340 signature s.
    pub s: u256,
    /// Message.
    pub message: ByteArray,
    /// Precomputed MSM hint for Garaga's EC operations.
    pub msm_hint: Array<felt252>,
}

#[executable]
fn main(args: Args) {
    let Args { pk, rx, s, message, msm_hint } = args;
    let res = schnorr::verify(pk, rx, s, message, msm_hint.span());
    check_result(res);
}

#[executable]
fn main_multi(args: Array<Args>) {
    for arg in args {
        let Args { pk, rx, s, message, msm_hint } = arg;
        let res = schnorr::verify(pk, rx, s, message, msm_hint.span());
        check_result(res);
    }
}

#[cfg(feature: "debug")]
fn check_result(res: bool) {
    println!("Verification result: {}", res);
}

#[cfg(not(feature: "debug"))]
fn check_result(res: bool) {
    assert(res, 'Signature verification failed');
}
