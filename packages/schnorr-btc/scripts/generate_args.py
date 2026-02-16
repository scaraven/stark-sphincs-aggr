#!/usr/bin/env python3
"""
Generate BIP-340 Schnorr signature test vectors for schnorr-btc Cairo package.

Produces args.json with serialized (pk, sig_with_hint, message) in garaga's
Serde format, suitable for consumption by the Cairo executable.
"""

import argparse
import hashlib
import json
import os
import secrets
import struct
import sys

from garaga.curves import CURVES, CurveID
from garaga.hints.io import bigint_split, split_128
from garaga.starknet.tests_and_calldata_generators.signatures import SchnorrSignature


# secp256k1 parameters
CURVE_ID = CurveID.SECP256K1
CURVE = CURVES[CURVE_ID.value]
P = CURVE.p
N = CURVE.n
GX = CURVE.Gx
GY = CURVE.Gy


def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def int_to_bytes32(x: int) -> bytes:
    """Convert integer to 32-byte big-endian."""
    return x.to_bytes(32, "big")


def lift_x(x: int) -> tuple[int, int]:
    """Lift x-coordinate to a point on secp256k1 with even y."""
    if x >= P:
        raise ValueError("x >= p")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("x is not on curve")
    if y % 2 != 0:
        y = P - y
    return (x, y)


def point_mul(k: int, px: int, py: int) -> tuple[int, int]:
    """Scalar multiplication on secp256k1 using double-and-add."""
    # Use garaga's G1Point for this
    pt = G1Point(px, py, CurveID.SECP256K1)
    result = pt.scalar_mul(k)
    return (result.x, result.y)


def point_add(x1: int, y1: int, x2: int, y2: int) -> tuple[int, int]:
    """Point addition on secp256k1."""
    p1 = G1Point(x1, y1, CurveID.SECP256K1)
    p2 = G1Point(x2, y2, CurveID.SECP256K1)
    result = p1.add(p2)
    return (result.x, result.y)


def bip340_sign(privkey: int, message: bytes) -> dict:
    """
    Sign a message using BIP-340 Schnorr.

    Returns dict with rx, s, e, px, py (all ints).
    """
    # Compute public key
    Px, Py = point_mul(privkey, GX, GY)

    # Ensure even y
    d = privkey if Py % 2 == 0 else N - privkey
    # Recompute with corrected key
    if Py % 2 != 0:
        Py = P - Py

    # Generate deterministic nonce (BIP-340 style)
    # aux_rand for extra randomness
    aux_rand = secrets.token_bytes(32)
    t = bytes(a ^ b for a, b in zip(int_to_bytes32(d), tagged_hash("BIP0340/aux", aux_rand)))
    rand = tagged_hash("BIP0340/nonce", t + int_to_bytes32(Px) + message)
    k_prime = int.from_bytes(rand, "big") % N
    if k_prime == 0:
        raise ValueError("k' is zero")

    Rx, Ry = point_mul(k_prime, GX, GY)

    # Ensure even y for R
    k = k_prime if Ry % 2 == 0 else N - k_prime
    if Ry % 2 != 0:
        Ry = P - Ry

    # Compute challenge
    e_bytes = tagged_hash(
        "BIP0340/challenge",
        int_to_bytes32(Rx) + int_to_bytes32(Px) + message,
    )
    e = int.from_bytes(e_bytes, "big") % N

    # Compute s
    s = (k + e * d) % N

    return {
        "rx": Rx,
        "s": s,
        "e": e,
        "px": Px,
        "py": Py,
    }


def serialize_u384(value: int) -> list[int]:
    """Serialize a u384 as 4 felt252 limbs (96-bit each, little-endian limb order)."""
    limbs = bigint_split(value, 4, 2**96)
    return list(limbs)


def serialize_u256(value: int) -> list[int]:
    """Serialize a u256 as (low_128, high_128)."""
    low, high = split_128(value)
    return [low, high]


def serialize_g1point(x: int, y: int) -> list[int]:
    """Serialize a G1Point as x(u384=4 limbs) + y(u384=4 limbs)."""
    return serialize_u384(x) + serialize_u384(y)


def serialize_message(msg_bytes: bytes) -> tuple[list[int], int, int]:
    """
    Split message bytes into big-endian u32 words.

    Returns (words, last_word, last_word_len).
    """
    words = []
    full_words = len(msg_bytes) // 4
    remainder = len(msg_bytes) % 4

    for i in range(full_words):
        w = struct.unpack(">I", msg_bytes[i * 4 : (i + 1) * 4])[0]
        words.append(w)

    last_word = 0
    last_word_len = remainder
    if remainder > 0:
        remaining_bytes = msg_bytes[full_words * 4 :]
        for b in remaining_bytes:
            last_word = (last_word << 8) | b

    return words, last_word, last_word_len


def generate_msm_hint(rx: int, s: int, e: int, px: int, py: int) -> list[int]:
    """
    Generate MSM hint using garaga's SchnorrSignature.

    Returns the msm_hint as a list of felt252 values.
    """
    sig = SchnorrSignature(
        rx=rx,
        s=s,
        e=e,
        curve_id=CURVE_ID,
    )
    pk = G1Point(px, py, CURVE_ID)

    # serialize_with_hints returns the full calldata including signature fields
    # Format: rx(4) + s(2) + e(2) + msm_hint_len + msm_hint(...)
    # When prepend_public_key=True: pk(8) + rx(4) + s(2) + e(2) + msm_hint_len + msm_hint(...)
    calldata = sig.serialize_with_hints(pk, prepend_public_key=False)

    # Skip the signature fields: rx(4 limbs) + s(2) + e(2) = 8 felts
    # The rest is length-prefixed msm_hint
    msm_hint_with_len = calldata[8:]

    return msm_hint_with_len


def generate_single_args(privkey: int, message: bytes) -> list[int]:
    """
    Generate a single Args serialization.

    Format (garaga Serde):
      pk: G1Point = x(u384=4) + y(u384=4)                     = 8 felts
      sig: SchnorrSignatureWithHintInternal =
        signature: SchnorrSignatureInternal =
          rx(u384=4) + s(u256=2) + e(u256=2)                   = 8 felts
        msm_hint: Array<felt252> = len + data                   = 1 + N felts
      message: Array<u32> = len + words                         = 1 + M felts
      message_last_word: u32                                    = 1 felt
      message_last_word_len: u32                                = 1 felt
    """
    sig_data = bip340_sign(privkey, message)
    rx, s, e = sig_data["rx"], sig_data["s"], sig_data["e"]
    px, py = sig_data["px"], sig_data["py"]

    result = []

    # 1. pk: G1Point
    result.extend(serialize_g1point(px, py))

    # 2. sig.signature: SchnorrSignatureInternal (rx, s, e)
    result.extend(serialize_u384(rx))
    result.extend(serialize_u256(s))
    result.extend(serialize_u256(e))

    # 3. sig.msm_hint: Array<felt252> (length-prefixed)
    msm_hint = generate_msm_hint(rx, s, e, px, py)
    result.extend(msm_hint)

    # 4. message: Array<u32>
    words, last_word, last_word_len = serialize_message(message)
    result.append(len(words))
    result.extend(words)

    # 5. message_last_word + message_last_word_len
    result.append(last_word)
    result.append(last_word_len)

    return result


def generate_multi_args(privkeys: list[int], messages: list[bytes]) -> list[int]:
    """Generate Array<Args> serialization: length prefix + concatenated single args."""
    assert len(privkeys) == len(messages)
    result = [len(privkeys)]
    for pk, msg in zip(privkeys, messages):
        result.extend(generate_single_args(pk, msg))
    return result


def main():
    parser = argparse.ArgumentParser(description="Generate Schnorr BIP-340 test vectors")
    parser.add_argument("-n", "--num-signatures", type=int, default=1, help="Number of signatures")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file (default: ../args.json)")
    parser.add_argument("--multi", action="store_true", help="Use main_multi format (Array<Args>)")
    args = parser.parse_args()

    # Deterministic key generation from seed
    rng = secrets.SystemRandom()
    # Use hashlib for deterministic derivation
    privkeys = []
    messages = []
    for i in range(args.num_signatures):
        seed_bytes = hashlib.sha256(f"schnorr-btc-privkey-{args.seed}-{i}".encode()).digest()
        privkey = int.from_bytes(seed_bytes, "big") % (N - 1) + 1
        privkeys.append(privkey)

        msg = f"test message {i}".encode()
        messages.append(msg)

    if args.num_signatures == 1 and not args.multi:
        result = generate_single_args(privkeys[0], messages[0])
    else:
        result = generate_multi_args(privkeys, messages)

    # Convert to hex strings
    hex_result = [hex(v) for v in result]

    output_path = args.output or os.path.join(os.path.dirname(__file__), "..", "args.json")
    with open(output_path, "w") as f:
        json.dump(hex_result, f, indent=2)

    print(f"Generated {args.num_signatures} signature(s) -> {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
