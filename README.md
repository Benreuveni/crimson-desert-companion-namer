# Crimson Desert — Companion Namer

Rename your mercenaries (pets, mounts, companions) in **Crimson Desert** save files.

The game doesn't expose a way to name your companions, so this tool patches the
`_mercenaryName` field in `MercenarySaveData` directly. It handles all the fiddly
details of PARC reflection serialization — bitmap bits, offset fixups, and
size-prefixed strings — so you don't have to.

## Requirements

- Python 3.10+
- `cryptography` — for ChaCha20 / HMAC-SHA256 save encryption
- `lz4` — for LZ4 block decompression/compression

```
pip install cryptography lz4
```

## Quick Start

```bash
# 1. Back up your save file first!
cp save.save save.save.bak

# 2. List all mercenaries and their current names
python tools/save_pet_rename.py save.save --list

# 3. Rename a specific mercenary (by MercNo)
python tools/save_pet_rename.py save.save --rename 615 "Rex" -o patched.save

# 4. Or just run it without flags for interactive mode
python tools/save_pet_rename.py save.save
```

## Workflow: Identifying Unknown Mercenaries

Mercenary IDs aren't visible in-game, so use this workflow to figure out
which ID maps to which companion:

1. **Label everything** — `--rename-all` tags each mercenary as `M_<no>`
2. **Load the game** and note which label appears on which companion
3. **Set real names** — `--rename-multi 1027=Kraken 615=Grendel`
4. **Clean up** — `--clear-unnamed` removes leftover `M_<no>` labels

```bash
python tools/save_pet_rename.py save.save --rename-all -o labeled.save
# ... play, take notes ...
python tools/save_pet_rename.py labeled.save --rename-multi 1027=Kraken 615=Grendel -o named.save
python tools/save_pet_rename.py named.save --clear-unnamed -o final.save
```

## Interactive Mode

Run the script with just a save file (no action flags) to get an interactive menu:

```
Actions:
  1) Label all mercenaries (M_<no>)
  2) Rename specific mercenaries
  3) Clean up auto-labels (M_<no> only)
  4) Clear ALL custom names
  q) Quit
```

## CLI Reference

| Flag | Description |
|------|-------------|
| `--list` | List all mercenaries with IDs, names, and tags |
| `--rename ID NAME` | Rename a single mercenary |
| `--rename-multi ID=NAME ...` | Rename multiple mercenaries |
| `--rename-all` | Auto-label all mercenaries as `M_<no>` |
| `--clear ID [ID ...]` | Clear names for specific mercenary IDs |
| `--clear-unnamed` | Clear only auto-generated `M_<no>` labels |
| `--clear-all` | Clear all custom mercenary names |
| `-o PATH` | Output file (defaults to a suffixed copy of the input) |

## How It Works

Save files are encrypted with ChaCha20 and authenticated with HMAC-SHA256,
then LZ4-compressed. Inside, the data uses Pearl Abyss's PARC reflection
serialization — a binary format with per-object bitmaps indicating which
fields are present, and a global offset table that must be kept in sync.

The tool:
1. Decrypts and decompresses the save file
2. Parses the PARC reflection layout to locate `MercenarySaveData` objects
3. Patches the `_mercenaryName` field (sets/clears bitmap bits, inserts/removes string data)
4. Fixes up **all** offsets in the object info table and inline `value_offset` fields
5. Re-compresses, re-signs, and re-encrypts

## Acknowledgements

This tool stands on the shoulders of the Crimson Desert modding community:

- **[LukeFZ/pycrimson](https://github.com/LukeFZ/pycrimson)** — Reverse-engineered the
  save file encryption scheme (ChaCha20 key derivation, HMAC, header format)
- **[MrIkso/CrimsonDesertTools](https://github.com/MrIkso/CrimsonDesertTools)** — PARC
  reflection format documentation via .hexpat templates
- **[lazorr410/crimson-desert-unpacker](https://github.com/lazorr410/crimson-desert-unpacker)** —
  PAZ archive extraction tools
- **[Jominiumiumium/CrimsonDesert_Item_hider](https://github.com/Jominiumiumium/CrimsonDesert_Item_hider)** —
  Item/equipment modding research

## License

MIT
