#!/usr/bin/env python3
"""
Calculate the size of a Cairo args file in bytes.

Reports:
  - Element count (number of felt252 values)
  - Felt252 size: elements x 32 bytes (Cairo serialisation cost)
  - Packed size: sum of ceil(bit_length/8) per value (minimal wire size)
"""

import argparse
import json
import math
from pathlib import Path


def analyse(path: Path) -> None:
    with open(path) as f:
        data = json.load(f)

    if not isinstance(data, list):
        print(f"Error: expected a JSON array, got {type(data).__name__}")
        return

    values = [int(x, 16) if isinstance(x, str) else int(x) for x in data]
    num_elements = len(values)

    felt252_bytes = num_elements * 32
    packed_bytes = sum(math.ceil(v.bit_length() / 8) if v > 0 else 1 for v in values)

    print(f"File:          {path}")
    print(f"Elements:      {num_elements:,}")
    print(f"Felt252 size:  {felt252_bytes:,} bytes  ({felt252_bytes / 1024:.2f} KB)")
    print(f"Packed size:   {packed_bytes:,} bytes  ({packed_bytes / 1024:.2f} KB)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Calculate Cairo args file size in bytes")
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Path(s) to args JSON file(s)",
    )
    args = parser.parse_args()

    for i, path_str in enumerate(args.files):
        if i > 0:
            print()
        analyse(Path(path_str))


if __name__ == "__main__":
    main()
