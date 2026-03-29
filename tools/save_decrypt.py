"""Crimson Desert — Save File Decryptor / Encryptor

Decrypts .save files (ChaCha20 + HMAC-SHA256 + LZ4), dumps the raw
reflection-serialized payload, and optionally searches for strings.

Usage:
    python save_decrypt.py <save_file>                      # Decrypt + dump info
    python save_decrypt.py <save_file> --search "Brown Dog"  # Search for string
    python save_decrypt.py <save_file> -o decrypted.bin      # Decrypt to file
    python save_decrypt.py --encrypt decrypted.bin -o new.save  # Re-encrypt

Acknowledgements:
    - ChaCha20 key derivation, HMAC scheme, and header format
      reverse-engineered by LukeFZ: https://github.com/LukeFZ/pycrimson
    - PARC reflection format insights from pycrimson and
      MrIkso/CrimsonDesertTools .hexpat templates
"""

import argparse
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256

import lz4.block

# ── Save file header ────────────────────────────────────────────────

HEADER_SIZE = 0x80  # 128 bytes

HEADER_STRUCT = struct.Struct("<4s H H I I H I I")
#                              magic ver hsz unk0 flags unk2 decomp_sz comp_sz
# Followed by: 16-byte nonce, 32-byte HMAC, 54-byte reserved


def parse_header(data: bytes) -> dict:
    """Parse the 128-byte SAVE header. Returns a dict of all fields."""
    assert len(data) >= HEADER_SIZE, f"File too small ({len(data)} bytes)"
    fields = HEADER_STRUCT.unpack_from(data, 0)
    offset = HEADER_STRUCT.size  # 26
    nonce = data[offset : offset + 16]
    offset += 16
    hmac_sig = data[offset : offset + 32]
    offset += 32
    reserved = data[offset : offset + (HEADER_SIZE - offset)]
    return {
        "magic": fields[0],
        "version": fields[1],
        "header_size": fields[2],
        "unknown0": fields[3],
        "flags": fields[4],
        "unknown2": fields[5],
        "decompressed_size": fields[6],
        "compressed_size": fields[7],
        "nonce": nonce,
        "hmac": hmac_sig,
        "reserved": reserved,
    }


def build_header(
    version: int,
    flags: int,
    decompressed_size: int,
    compressed_size: int,
    nonce: bytes,
    hmac_sig: bytes,
) -> bytes:
    """Build a 128-byte SAVE header."""
    buf = bytearray(HEADER_SIZE)
    HEADER_STRUCT.pack_into(
        buf, 0,
        b"SAVE", version, HEADER_SIZE, 0, flags, 0,
        decompressed_size, compressed_size,
    )
    offset = HEADER_STRUCT.size
    buf[offset : offset + 16] = nonce
    offset += 16
    buf[offset : offset + 32] = hmac_sig
    return bytes(buf)


# ── Key derivation (from pycrimson by LukeFZ) ──────────────────────

_SAVE_BASE_KEY = bytes.fromhex(
    "C41B8E730DF259A637CC04E9B12F9668DA107A853E61F9224DB80AD75C13EF90"
)[:31]

_VERSION_PREFIXES = {
    1: b'^Qgbrm/.#@`zsr]\\@rvfal#"',
    2: b"^Pearl--#Abyss__@!!",
}


def derive_save_key(version: int) -> bytes:
    """Derive the 32-byte ChaCha20 key for a given save version."""
    prefix = _VERSION_PREFIXES.get(version)
    if prefix is None:
        raise ValueError(f"Unsupported save version {version}")

    key_material = prefix + b"PRIVATE_HMAC_SECRET_CHECK"
    key = bytes(a ^ b for a, b in zip(_SAVE_BASE_KEY, key_material)) + b"\x00"
    assert len(key) == 32, f"Key length {len(key)}, expected 32"
    return key


# ── ChaCha20 ────────────────────────────────────────────────────────

def chacha20_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """ChaCha20 encrypt or decrypt (symmetric)."""
    cipher = Cipher(ChaCha20(key, nonce), mode=None)
    return cipher.encryptor().update(data)


# ── Decrypt / Encrypt ───────────────────────────────────────────────

def decrypt_save(file_data: bytes, verify_hmac: bool = True) -> tuple[dict, bytes]:
    """Decrypt a .save file.

    Returns (header_dict, plaintext_bytes).
    The plaintext is the decompressed PARC reflection data.
    """
    hdr = parse_header(file_data)
    assert hdr["magic"] == b"SAVE", f"Bad magic: {hdr['magic']}"

    key = derive_save_key(hdr["version"])
    encrypted = file_data[HEADER_SIZE : HEADER_SIZE + hdr["compressed_size"]]

    decrypted = chacha20_crypt(encrypted, key, hdr["nonce"])

    if verify_hmac:
        h = HMAC(key, SHA256())
        h.update(decrypted)
        h.verify(hdr["hmac"])

    is_compressed = (hdr["flags"] & 0x02) != 0
    if is_compressed and hdr["compressed_size"] != hdr["decompressed_size"]:
        plaintext = lz4.block.decompress(
            decrypted, uncompressed_size=hdr["decompressed_size"]
        )
    else:
        plaintext = decrypted

    return hdr, plaintext


def encrypt_save(plaintext: bytes, version: int = 2) -> bytes:
    """Encrypt plaintext PARC data into a .save file."""
    import secrets

    compressed = lz4.block.compress(plaintext, store_size=False)
    key = derive_save_key(version)
    nonce = secrets.token_bytes(16)

    h = HMAC(key, SHA256())
    h.update(compressed)
    hmac_sig = h.finalize()

    encrypted = chacha20_crypt(compressed, key, nonce)

    header = build_header(
        version=version,
        flags=0x02,  # COMPRESSED
        decompressed_size=len(plaintext),
        compressed_size=len(compressed),
        nonce=nonce,
        hmac_sig=hmac_sig,
    )
    return header + encrypted


# ── Analysis helpers ────────────────────────────────────────────────

def search_strings(data: bytes, query: str, context: int = 64) -> list[dict]:
    """Search for a string (case-insensitive) in binary data.

    Returns a list of match dicts with offset, context bytes, and ascii preview.
    """
    query_lower = query.lower().encode("utf-8")
    query_upper = query.upper().encode("utf-8")
    data_lower = data.lower()
    matches = []
    start = 0
    while True:
        idx = data_lower.find(query_lower, start)
        if idx == -1:
            break
        ctx_start = max(0, idx - context)
        ctx_end = min(len(data), idx + len(query_lower) + context)
        chunk = data[ctx_start:ctx_end]
        ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        matches.append({
            "offset": idx,
            "hex_offset": f"0x{idx:08X}",
            "raw_bytes": chunk.hex(),
            "ascii": ascii_preview,
        })
        start = idx + 1
    return matches


def dump_structure_summary(data: bytes):
    """Print a high-level summary of the decrypted save data structure."""
    print(f"\n{'='*60}")
    print(f"DECRYPTED SAVE DATA SUMMARY")
    print(f"{'='*60}")
    print(f"Size: {len(data):,} bytes ({len(data)/1024:.1f} KB)")

    # Check for reflection header magic
    if len(data) >= 4:
        magic32 = struct.unpack_from("<I", data, 0)[0]
        print(f"First 4 bytes (uint32 LE): {magic32} (0x{magic32:08X})")
        print(f"First 16 bytes hex: {data[:16].hex()}")
        ascii_start = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:64])
        print(f"First 64 bytes ascii: {ascii_start}")

    # Count printable ASCII vs binary
    printable = sum(1 for b in data if 32 <= b < 127)
    print(f"Printable ASCII bytes: {printable:,} ({100*printable/len(data):.1f}%)")

    # Find all readable strings >= 4 chars
    strings = []
    current = []
    for i, b in enumerate(data):
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings.append((i - len(current), "".join(current)))
            current = []
    if len(current) >= 4:
        strings.append((len(data) - len(current), "".join(current)))

    print(f"Readable strings (>=4 chars): {len(strings)}")
    if strings:
        print(f"\nFirst 50 strings:")
        for offset, s in strings[:50]:
            print(f"  0x{offset:08X}: {s[:120]}")

    # Search for known keywords
    print(f"\n--- Keyword Search ---")
    keywords = [
        "Brown Dog", "brown dog", "BrownDog",
        "pet", "Pet", "mercenary", "Mercenary",
        "dog", "Dog", "Boardhound", "boardhound",
        "companion", "Companion",
        "MercenarySaveData", "PetSaveData",
        "StringId", "stringId", "LocalString",
        "4296547843964976",  # Brown Dog localization string ID
    ]
    for kw in keywords:
        results = search_strings(data, kw, context=32)
        if results:
            print(f"\n  '{kw}' — {len(results)} match(es):")
            for m in results[:3]:
                print(f"    {m['hex_offset']}: ...{m['ascii']}...")


# ── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Crimson Desert save file decryptor/encryptor"
    )
    parser.add_argument("input", help="Path to .save file (or decrypted file with --encrypt)")
    parser.add_argument("-o", "--output", help="Output path for decrypted/encrypted data")
    parser.add_argument("--search", help="Search for a string in decrypted data")
    parser.add_argument("--encrypt", action="store_true",
                        help="Encrypt mode: takes decrypted input, produces .save")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip HMAC verification during decrypt")
    parser.add_argument("--header-only", action="store_true",
                        help="Only parse and display the header")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress summary output (use with -o)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    file_data = input_path.read_bytes()

    # ── Encrypt mode ──
    if args.encrypt:
        output_path = Path(args.output) if args.output else input_path.with_suffix(".save")
        encrypted = encrypt_save(file_data)
        output_path.write_bytes(encrypted)
        print(f"Encrypted {len(file_data):,} bytes -> {output_path} ({len(encrypted):,} bytes)")
        return

    # ── Decrypt mode ──
    hdr = parse_header(file_data)

    print(f"{'='*60}")
    print(f"SAVE FILE HEADER")
    print(f"{'='*60}")
    print(f"File:              {input_path}")
    print(f"File size:         {len(file_data):,} bytes")
    print(f"Magic:             {hdr['magic']}")
    print(f"Version:           {hdr['version']}")
    print(f"Header size:       {hdr['header_size']} (0x{hdr['header_size']:X})")
    print(f"Flags:             0x{hdr['flags']:08X} ({'COMPRESSED' if hdr['flags'] & 2 else 'RAW'})")
    print(f"Decompressed size: {hdr['decompressed_size']:,} bytes")
    print(f"Compressed size:   {hdr['compressed_size']:,} bytes")
    print(f"Compression ratio: {hdr['compressed_size']/max(1,hdr['decompressed_size'])*100:.1f}%")
    print(f"Nonce:             {hdr['nonce'].hex()}")
    print(f"HMAC-SHA256:       {hdr['hmac'].hex()}")

    key = derive_save_key(hdr["version"])
    print(f"Derived key:       {key.hex()}")

    if args.header_only:
        return

    print(f"\nDecrypting...")
    try:
        hdr, plaintext = decrypt_save(file_data, verify_hmac=not args.no_verify)
        print(f"Decryption successful! HMAC {'skipped' if args.no_verify else 'verified'}.")
    except Exception as e:
        print(f"Decryption FAILED: {e}", file=sys.stderr)
        if not args.no_verify:
            print("Retrying with --no-verify...", file=sys.stderr)
            try:
                hdr, plaintext = decrypt_save(file_data, verify_hmac=False)
                print("Decryption succeeded (HMAC mismatch — key may be wrong for this version)")
            except Exception as e2:
                print(f"Still failed: {e2}", file=sys.stderr)
                sys.exit(1)

    # Write output
    if args.output:
        output_path = Path(args.output)
        output_path.write_bytes(plaintext)
        print(f"Wrote {len(plaintext):,} bytes to {output_path}")

    # Search
    if args.search:
        print(f"\nSearching for '{args.search}'...")
        matches = search_strings(plaintext, args.search)
        if matches:
            print(f"Found {len(matches)} match(es):")
            for m in matches:
                print(f"  {m['hex_offset']}: {m['ascii']}")
        else:
            print("No matches found.")

    # Structure summary
    if not args.quiet:
        dump_structure_summary(plaintext)


if __name__ == "__main__":
    main()
