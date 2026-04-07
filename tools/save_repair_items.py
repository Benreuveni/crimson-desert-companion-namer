"""Crimson Desert — Broken Item Repair Tool

Repairs "damaged" / "broken" items in save files by restoring their
_endurance (durability) from 0 to max (65535).

Strategy: in-place u16 patching (no size changes, no offset fixup needed).
  1. Decrypt save → parse PARC reflection layout
  2. Navigate to all ItemSaveData instances (inventory + equipment)
  3. For each with _endurance == 0, overwrite with 0xFFFF (65535)
  4. Re-compress (LZ4) → HMAC-SHA256 → ChaCha20 encrypt → write .save

Usage:
    python save_repair_items.py <save_file> --list
    python save_repair_items.py <save_file> --list-all
    python save_repair_items.py <save_file> --repair -o repaired.save
    python save_repair_items.py <save_file> --repair --endurance 1000 -o repaired.save

Acknowledgements:
    - Save encryption reverse-engineered by LukeFZ (pycrimson)
    - PARC reflection format from pycrimson + MrIkso/CrimsonDesertTools
    - Item structure research from potter420/crimson-rs
    - Item database from NattKh/CRIMSON-DESERT-SAVE-EDITOR
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from save_decrypt import decrypt_save, encrypt_save
from save_pet_rename import (
    parse_reflection_layout,
    _skip_property_value,
    _skip_object,
)


MAX_ENDURANCE = 0xFFFF  # 65535


# ── PARC navigation helpers ─────────────────────────────────────────

def _parse_top_header(data, off, layout):
    """Parse a top-level PARC object header.
    Returns (bitmap_bytes, properties_start_offset).
    """
    ser_ver = layout['ser_ver']
    bmp_len = struct.unpack_from('<H', data, off)[0]; off += 2
    bmp = data[off:off + bmp_len]; off += bmp_len
    if ser_ver >= 0xA:
        off += 1
    if ser_ver >= 5:
        no_tags = data[off]; off += 1
        if not no_tags and ser_ver >= 6:
            tc = struct.unpack_from('<H', data, off)[0]; off += 2
            for _ in range(tc):
                off += 2
                tl = struct.unpack_from('<I', data, off)[0]; off += 4
                off += tl
    return bmp, off


def _parse_nested_hdr(data, off, layout):
    """Parse a nested PARC object header (inside OBJECT_ARRAY or OBJECT).
    Returns (bitmap_bytes, type_index, properties_start_offset).
    """
    ser_ver = layout['ser_ver']
    bmp_len = struct.unpack_from('<H', data, off)[0]; off += 2
    bmp = data[off:off + bmp_len]; off += bmp_len
    ti = struct.unpack_from('<H', data, off)[0]; off += 2
    if ser_ver >= 0xB:
        off += 1 + 8
    elif ser_ver >= 8:
        off += 4
    else:
        off += 2
    vo = struct.unpack_from('<I', data, off)[0]; off += 4
    off = vo
    if ser_ver >= 0xA:
        off += 1
    if ser_ver >= 5:
        no_tags = data[off]; off += 1
        if not no_tags and ser_ver >= 6:
            tc = struct.unpack_from('<H', data, off)[0]; off += 2
            for _ in range(tc):
                off += 2
                tl = struct.unpack_from('<I', data, off)[0]; off += 4
                off += tl
    return bmp, ti, off


def _parse_arr_hdr(data, off, layout):
    """Parse OBJECT_ARRAY header. Returns (element_count, first_element_offset)."""
    ser_ver = layout['ser_ver']
    if ser_ver >= 0xF:
        ef = data[off]; off += 1
        if ef == 1:
            return 0, off
    cnt = struct.unpack_from('<I', data, off)[0]; off += 4
    hn = False
    if ser_ver >= 0xE:
        hn = data[off] == 1; off += 1
    if ser_ver >= 0xB:
        off += 8
    elif ser_ver >= 8:
        off += 4
    elif ser_ver >= 4:
        off += 2
    if ser_ver >= 0xB:
        uc = struct.unpack_from('<i', data, off)[0]; off += 4
        if uc > 0:
            off += uc * 8
            if hn:
                off += uc * 4
    return cnt, off


def _is_present(bmp, pi, prop, layout):
    """Check whether property pi is serialized (not using default)."""
    ser_ver = layout['ser_ver']
    if ser_ver >= 9 and (prop['flags'] & 0x82):
        return False
    bs = ((bmp[pi // 8] >> (pi & 7)) & 1) == 1 if pi // 8 < len(bmp) else False
    return bs or prop['prop_type'] in (3, 6, 7, 9, 10)


def _skip_n(data, off, layout, type_info, n, bmp):
    """Skip the first n properties of a type, respecting bitmap."""
    for pi in range(n):
        p = type_info['properties'][pi]
        if _is_present(bmp, pi, p, layout):
            off = _skip_property_value(data, off, p, layout)
    return off


# ── ItemSaveData field extraction ───────────────────────────────────

def _parse_item_nested(data, off, layout, item_type):
    """Parse a nested ItemSaveData object (header + properties).
    Returns dict with extracted field values and offsets.
    """
    bmp, ti, poff = _parse_nested_hdr(data, off, layout)
    return _extract_item_fields(data, poff, layout, item_type, bmp)


def _extract_item_fields(data, off, layout, item_type, bmp):
    """Walk ItemSaveData properties, extracting key fields."""
    result = {}
    for pi, prop in enumerate(item_type['properties']):
        if not _is_present(bmp, pi, prop, layout):
            if prop['name'] == '_endurance':
                result['endurance'] = None
                result['endurance_offset'] = None
            elif prop['name'] == '_sharpness':
                result['sharpness'] = None
                result['sharpness_offset'] = None
            continue

        n = prop['name']
        pt = prop['prop_type']
        if n == '_saveVersion' and pt == 0:
            result['save_version'] = struct.unpack_from('<I', data, off)[0]
        elif n == '_itemNo' and pt == 0:
            result['item_no'] = struct.unpack_from('<Q', data, off)[0]
        elif n == '_itemKey' and pt == 0:
            result['item_key'] = struct.unpack_from('<I', data, off)[0]
        elif n == '_slotNo' and pt == 0:
            result['slot_no'] = struct.unpack_from('<H', data, off)[0]
        elif n == '_stackCount' and pt == 0:
            result['stack_count'] = struct.unpack_from('<Q', data, off)[0]
        elif n == '_enchantLevel' and pt == 0:
            result['enchant_level'] = struct.unpack_from('<H', data, off)[0]
        elif n == '_endurance' and pt == 0:
            result['endurance'] = struct.unpack_from('<H', data, off)[0]
            result['endurance_offset'] = off
        elif n == '_sharpness' and pt == 0:
            result['sharpness'] = struct.unpack_from('<H', data, off)[0]
            result['sharpness_offset'] = off

        off = _skip_property_value(data, off, prop, layout)

    _sz = struct.unpack_from('<I', data, off)[0]; off += 4
    result['object_end'] = off
    return result


# ── High-level navigation ───────────────────────────────────────────

def find_all_items(data, layout):
    """Locate every ItemSaveData in inventory and equipment containers."""
    types = layout['types']
    tmap = {t['name']: i for i, t in enumerate(types)}

    item_t = types[tmap['ItemSaveData']]
    inv_t = types[tmap['InventorySaveData']]
    invelem_t = types[tmap['InventoryElementSaveData']]
    equip_t = types[tmap['EquipmentSaveData']]
    eqslot_t = types[tmap['EquipSlotElementSaveData']]

    items = []
    for info in layout['infos']:
        ti = info['type_index']
        if ti >= len(types):
            continue
        tn = types[ti]['name']
        try:
            if tn == 'InventorySaveData':
                items.extend(_nav_inventory(
                    data, info['offset'], layout, inv_t, invelem_t, item_t))
            elif tn == 'EquipmentSaveData':
                items.extend(_nav_equipment(
                    data, info['offset'], layout, equip_t, eqslot_t, item_t))
        except Exception as e:
            print(f"  WARN: {tn} at 0x{info['offset']:X}: {e}", file=sys.stderr)

    return items


def _nav_inventory(data, obj_off, layout, inv_t, invelem_t, item_t):
    """InventorySaveData → _inventorylist → InventoryElementSaveData
    → _itemList → ItemSaveData
    """
    items = []
    bmp, off = _parse_top_header(data, obj_off, layout)

    # prop[0] _inventorylist is an OBJECT_ARRAY of InventoryElementSaveData
    elem_cnt, elem_off = _parse_arr_hdr(data, off, layout)

    for i in range(elem_cnt):
        try:
            ebmp, eti, eprops = _parse_nested_hdr(data, elem_off, layout)

            inv_key = None
            p = eprops
            # prop[0] _inventoryKey (u16)
            if _is_present(ebmp, 0, invelem_t['properties'][0], layout):
                inv_key = struct.unpack_from('<H', data, p)[0]
                p = _skip_property_value(data, p, invelem_t['properties'][0], layout)
            # prop[1] _varyExpandSlotCount (u16) — skip
            if _is_present(ebmp, 1, invelem_t['properties'][1], layout):
                p = _skip_property_value(data, p, invelem_t['properties'][1], layout)
            # prop[2] _itemList (OBJECT_ARRAY of ItemSaveData)
            icnt, ioff = _parse_arr_hdr(data, p, layout)
            for j in range(icnt):
                try:
                    it = _parse_item_nested(data, ioff, layout, item_t)
                    it['source'] = 'inventory'
                    it['inventory_key'] = inv_key
                    items.append(it)
                except Exception as e:
                    print(f"  WARN: inv[{i}] item[{j}]: {e}", file=sys.stderr)
                ioff = _skip_object(data, ioff, layout)
        except Exception as e:
            print(f"  WARN: inv_elem[{i}]: {e}", file=sys.stderr)
        elem_off = _skip_object(data, elem_off, layout)

    return items


def _nav_equipment(data, obj_off, layout, equip_t, eqslot_t, item_t):
    """EquipmentSaveData → _list → EquipSlotElementSaveData → _item → ItemSaveData"""
    items = []
    bmp, off = _parse_top_header(data, obj_off, layout)

    # Skip props [0] _equipCacheSequenceNo and [1] _lastEquipShieldItemKey
    off = _skip_n(data, off, layout, equip_t, 2, bmp)

    # prop[2] _list (OBJECT_ARRAY of EquipSlotElementSaveData)
    scnt, soff = _parse_arr_hdr(data, off, layout)

    for i in range(scnt):
        try:
            sbmp, sti, sprops = _parse_nested_hdr(data, soff, layout)
            # prop[0] _item (OBJECT, prop_type=4 → ItemSaveData)
            if _is_present(sbmp, 0, eqslot_t['properties'][0], layout):
                try:
                    it = _parse_item_nested(data, sprops, layout, item_t)
                    it['source'] = 'equipment'
                    it['equip_slot'] = i
                    items.append(it)
                except Exception as e:
                    print(f"  WARN: equip slot[{i}] item: {e}", file=sys.stderr)
        except Exception as e:
            print(f"  WARN: equip_slot[{i}]: {e}", file=sys.stderr)
        soff = _skip_object(data, soff, layout)

    return items


# ── Display helpers ─────────────────────────────────────────────────

INVENTORY_NAMES = {
    0: "General",   1: "Equipment",  2: "Consumable",
    3: "Material",  4: "Quest",      5: "Pearl",
    6: "Storage",   7: "Trade",
}


def _fmt_dur(val):
    if val is None:
        return "default"
    if val == 0:
        return "0 [BROKEN]"
    if val == MAX_ENDURANCE:
        return f"{val} (max)"
    return str(val)


def _print_item(idx, it):
    key = it.get('item_key', 0)
    ino = it.get('item_no', 0)
    dur = _fmt_dur(it.get('endurance'))
    shrp = _fmt_dur(it.get('sharpness'))
    ench = it.get('enchant_level', 0)
    stk = it.get('stack_count', 1)
    src = it.get('source', '?')

    if src == 'inventory':
        ik = it.get('inventory_key')
        loc = INVENTORY_NAMES.get(ik, f"inv={ik}") if ik is not None else "inv=?"
    else:
        loc = f"slot={it.get('equip_slot', '?')}"

    stk_str = f" x{stk}" if stk and stk > 1 else ""
    print(f"  [{idx:3d}] key=0x{key:08X}  no={ino:<14d}  "
          f"endurance={dur:<16s}  sharpness={shrp:<12s}  "
          f"+{ench}  {src}/{loc}{stk_str}")


def print_item_list(items, show_all=False):
    broken = [it for it in items if it.get('endurance') == 0]
    low = [it for it in items
           if it.get('endurance') is not None
           and 0 < it.get('endurance', MAX_ENDURANCE) <= 100]

    print(f"\n{'='*90}")
    print(f"ITEM SCAN: {len(items)} total, {len(broken)} broken (endurance=0), "
          f"{len(low)} low durability")
    print(f"{'='*90}")

    if show_all:
        for i, it in enumerate(items):
            _print_item(i, it)
        return

    if broken:
        print(f"\nBROKEN ITEMS ({len(broken)}):")
        for i, it in enumerate(broken):
            _print_item(i, it)
    else:
        print("\nNo broken items found.")

    if low:
        print(f"\nLOW DURABILITY (endurance <= 100): {len(low)} items")
        for i, it in enumerate(low):
            _print_item(i, it)


# ── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Crimson Desert — Broken Item Repair Tool",
        epilog="Restores durability of broken/damaged items in save files.",
    )
    parser.add_argument("input", help="Path to .save file")
    parser.add_argument("--list", action="store_true",
                        help="List broken and low-durability items")
    parser.add_argument("--list-all", action="store_true",
                        help="List ALL items in inventory and equipment")
    parser.add_argument("--repair", action="store_true",
                        help="Repair all broken items (endurance=0)")
    parser.add_argument("--repair-sharpness", action="store_true",
                        help="Also restore sharpness for items with sharpness=0")
    parser.add_argument("--endurance", type=int, default=MAX_ENDURANCE,
                        help=f"Endurance value to restore to (default: {MAX_ENDURANCE})")
    parser.add_argument("-o", "--output",
                        help="Output path for patched .save file")
    args = parser.parse_args()

    input_path = Path(args.input)
    file_data = input_path.read_bytes()

    print("Decrypting save file...")
    hdr, plaintext = decrypt_save(file_data)
    print(f"  Decrypted: {len(plaintext):,} bytes  (ver={hdr['version']})")

    print("Parsing reflection layout...")
    layout = parse_reflection_layout(plaintext)
    print(f"  Types: {layout['type_count']}, Objects: {layout['obj_count']}, "
          f"SerVer: {layout['ser_ver']}")

    print("Scanning for items...")
    items = find_all_items(plaintext, layout)
    broken = [it for it in items if it.get('endurance') == 0]
    print(f"  Found {len(items)} items, {len(broken)} broken")

    if args.list or args.list_all:
        print_item_list(items, show_all=args.list_all)
        return

    if not args.repair:
        print_item_list(items)
        return

    # ── Repair ──
    if not broken:
        sharp_broken = [it for it in items if it.get('sharpness') == 0
                        and it.get('sharpness_offset') is not None]
        if not (args.repair_sharpness and sharp_broken):
            print("\nNo broken items to repair!")
            return

    target = min(args.endurance, MAX_ENDURANCE)
    patched = bytearray(plaintext)
    repaired = 0

    print(f"\nRepairing items (endurance → {target})...")
    for it in items:
        if it.get('endurance') == 0 and it.get('endurance_offset') is not None:
            struct.pack_into('<H', patched, it['endurance_offset'], target)
            repaired += 1
            print(f"  Fixed: key=0x{it.get('item_key', 0):08X}  "
                  f"no={it.get('item_no', 0)}  endurance 0 → {target}")

        if (args.repair_sharpness
                and it.get('sharpness') == 0
                and it.get('sharpness_offset') is not None):
            struct.pack_into('<H', patched, it['sharpness_offset'], target)
            print(f"  Fixed: key=0x{it.get('item_key', 0):08X}  "
                  f"sharpness 0 → {target}")

    if repaired == 0:
        print("  No items needed endurance repair.")
        return

    # Validate: only endurance bytes should have changed
    diff = sum(1 for a, b in zip(patched, plaintext) if a != b)
    print(f"\n  Patched {diff} bytes in {repaired} items "
          f"(expected {repaired * 2} bytes changed)")

    out_path = (Path(args.output) if args.output
                else input_path.with_name(
                    f"{input_path.stem}_repaired{input_path.suffix}"))

    print("Encrypting and saving...")
    encrypted = encrypt_save(bytes(patched), version=hdr['version'])
    out_path.write_bytes(encrypted)
    print(f"  Wrote: {out_path} ({len(encrypted):,} bytes)")
    print(f"\n  Repaired {repaired} items. Copy the output file to your save folder.")


if __name__ == "__main__":
    main()
