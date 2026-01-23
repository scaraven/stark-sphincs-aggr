"""
A small wrapper around the `poseidon-hash` PyPI package that exposes a simple
function `poseidon_hash(elements: list[int]) -> int` which returns the hashed
field element as an `int`.

This module tries to use the library's provided `parameters.case_simple()` helper
when available (to obtain a ready-made instance). If that fails it falls back to
constructing a Poseidon instance from parameters and hashing the input.

Requires: `pip install poseidon-hash` (see the PyPI package for details).
"""
from typing import List

try:
    import poseidon
except Exception as e:
    raise ImportError(
        "The `poseidon-hash` package is required. Install it with `pip install poseidon-hash`."
    )


def poseidon_hash(elements: List[int]) -> int:
    """Hash a list of integer field elements and return the digest as an int.

    The function is intentionally permissive: it will attempt to use a
    pre-generated instance if `poseidon.parameters.case_simple()` is available.
    If the pre-generated instance expects a particular length it will pad the
    input with zeros where sensible. If all else fails it constructs a basic
    Poseidon instance and uses that.

    Note: Poseidon is defined over a prime field; this wrapper treats input
    elements as Python integers that fit within the field used by the
    library's parameters.
    """
    # try to use a ready-made instance (if provided by the package)
    try:
        # some distributions expose parameters.case_simple() that returns
        # (poseidon_instance, t) as a convenience. Use it when available.
        if hasattr(poseidon, "parameters") and hasattr(poseidon.parameters, "case_simple"):
            poseidon_inst, t = poseidon.parameters.case_simple()
            # poseidon implementations sometimes accept t or t-1 sized inputs.
            # If input length is less than required, pad with zeros to t-1.
            if len(elements) == t or len(elements) == t - 1:
                digest = poseidon_inst.run_hash(elements)
            elif len(elements) < t:
                padded = elements + [0] * ((t - 1) - len(elements))
                digest = poseidon_inst.run_hash(padded)
            else:
                # If input is longer than supported by this instance explicitly
                # raise an informative error rather than silently truncating.
                raise ValueError(
                    f"Input length {len(elements)} is longer than supported by the pre-generated instance (t={t})."
                )
            return int(digest)
    except Exception:
        # fall through to a more general construction below
        pass

    # fallback: construct a Poseidon instance with conservative choices
    # - use the library's prime parameter if available
    # - security level 128, alpha 5 (common values)
    try:
        prime = getattr(poseidon.parameters, "prime_255", None) or getattr(poseidon.parameters, "prime", None)
    except Exception:
        prime = None

    # input_rate / t: choose a width large enough to accomodate the inputs
    # (a simple choice is to set t = len(elements) + 1 so preimage size is t-1)
    t = len(elements) + 1

    if prime is None:
        # If the package does not expose parameters in the expected place,
        # try to construct using the top-level Poseidon class directly.
        P = poseidon.Poseidon( None, 128, 5, len(elements), t)
    else:
        P = poseidon.Poseidon(prime, 128, 5, len(elements), t)

    digest = P.run_hash(elements)
    return int(digest)


__all__ = ["poseidon_hash"]
