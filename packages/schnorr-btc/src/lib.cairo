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
    /// Message as array of full u32 words (big-endian).
    pub message: Array<u32>,
    /// Last partial word of the message (0 if message is word-aligned).
    pub message_last_word: u32,
    /// Number of bytes in the last partial word (0-3).
    pub message_last_word_len: u32,
    /// Precomputed MSM hint for Garaga's EC operations.
    pub msm_hint: Array<felt252>,
}

#[executable]
fn main(args: Args) {
    let Args { pk, rx, s, message, message_last_word, message_last_word_len, msm_hint } = args;
    let res = schnorr::verify(pk, rx, s, message, message_last_word, message_last_word_len, msm_hint.span());
    check_result(res);
}

#[executable]
fn main_multi(args: Array<Args>) {
    for arg in args {
        let Args { pk, rx, s, message, message_last_word, message_last_word_len, msm_hint } = arg;
        let res = schnorr::verify(pk, rx, s, message, message_last_word, message_last_word_len, msm_hint.span());
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
