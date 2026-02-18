pub mod schnorr;
mod sha256;

use garaga::definitions::G1Point;
use schnorr::SchnorrSignatureWithHintInternal;

#[derive(Drop, Serde)]
pub struct Args {
    /// BIP-340 public key (full point with even y-coordinate).
    pub px: u256,
    pub py: u256,
    /// BIP-340 signature with MSM hint in garaga serialization format.
    pub sig: SchnorrSignatureWithHintInternal,
    /// Message as array of full u32 words (big-endian).
    pub message: Array<u32>,
    /// Last partial word of the message (0 if message is word-aligned).
    pub message_last_word: u32,
    /// Number of bytes in the last partial word (0-3).
    pub message_last_word_len: u32,
}

#[executable]
fn main(args: Args) {
    let Args { px, py, sig, message, message_last_word, message_last_word_len } = args;
    let pk = G1Point { x: px.into(), y: py.into() };
    let res = schnorr::verify(pk, sig, message, message_last_word, message_last_word_len);
    check_result(res);
}

#[executable]
fn main_multi(args: Array<Args>) {
    for arg in args {
        let Args { px, py, sig, message, message_last_word, message_last_word_len } = arg;
        let pk = G1Point { x: px.into(), y: py.into() };
        let res = schnorr::verify(pk, sig, message, message_last_word, message_last_word_len);
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
