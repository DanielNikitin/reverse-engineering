#!/usr/bin/env python3
from pathlib import Path
import hashlib
import struct
import sys

MAGIC = 0xFAB11BAF
VERSION = 39
XOR_KEY = 0xA5C3F19D
HEADER_SIZE = 0x17C
DESCRIPTOR_SIZE = 12
CANONICAL_DESCRIPTOR_ORDER = [
    22,
    11,
    0,
    2,
    5,
    16,
    7,
    27,
    6,
    29,
    15,
    30,
    23,
    4,
    12,
    19,
    20,
    26,
    13,
    18,
    14,
    17,
    8,
    3,
    10,
    21,
    28,
    25,
    1,
    9,
    24,
]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "global-metadata.dat").resolve()
    if not source.is_file():
        raise RuntimeError(f"file not found: {source}")

    data = bytearray(source.read_bytes())
    if len(data) < HEADER_SIZE:
        raise RuntimeError("metadata file is too small")
    if u32(data, 0) != MAGIC:
        raise RuntimeError(f"invalid metadata magic: 0x{u32(data, 0):08X}")
    if u32(data, 4) != VERSION:
        raise RuntimeError(
            f"metadata version is {u32(data, 4)}, expected 39; use the original v39 file"
        )

    for offset in range(8, HEADER_SIZE, 4):
        struct.pack_into("<I", data, offset, u32(data, offset) ^ XOR_KEY)

    protected_descriptors = [
        bytes(data[8 + index * DESCRIPTOR_SIZE : 8 + (index + 1) * DESCRIPTOR_SIZE])
        for index in range(len(CANONICAL_DESCRIPTOR_ORDER))
    ]
    for canonical_index, protected_index in enumerate(CANONICAL_DESCRIPTOR_ORDER):
        destination = 8 + canonical_index * DESCRIPTOR_SIZE
        data[destination : destination + DESCRIPTOR_SIZE] = protected_descriptors[
            protected_index
        ]

    valid = 0
    descriptors = []
    for offset in range(8, HEADER_SIZE, DESCRIPTOR_SIZE):
        section_offset, section_size, section_count = struct.unpack_from(
            "<III", data, offset
        )
        section_end = section_offset + section_size
        ok = (
            section_offset >= HEADER_SIZE
            and section_offset <= len(data)
            and section_size <= len(data)
            and section_end >= section_offset
            and section_end <= len(data)
            and section_count < 0x40000000
        )
        descriptors.append(
            (offset, section_offset, section_size, section_count, section_end, ok)
        )
        valid += int(ok)

    if valid != len(descriptors):
        raise RuntimeError(
            f"header decryption validation failed: {valid}/{len(descriptors)} sections"
        )

    destination = source.with_name("global-metadata-termocheat.dat")
    destination.write_bytes(data)

    print(f"Input : {source}")
    print(f"Output: {destination}")
    print(f"Size  : {len(data)} bytes")
    print(f"Key   : 0x{XOR_KEY:08X}")
    print(f"Sections: {valid}/{len(descriptors)} OK")
    print(f"SHA-256: {sha256(data)}")
    print()
    for header_offset, section_offset, size, count, end, _ in descriptors:
        print(
            f"+0x{header_offset:03X} offset=0x{section_offset:08X} "
            f"size=0x{size:08X} count={count} end=0x{end:08X}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
