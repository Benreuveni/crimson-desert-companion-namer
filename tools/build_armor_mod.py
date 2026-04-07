"""Build a JSON patch mod that allows Kliff to equip Damiane armor.

Scans iteminfo.pabgb for items whose tribe_gender_list contains only
Damiane-exclusive hashes, then generates a mod-manager-compatible JSON
file that replaces those hashes with Kliff's equivalents.

Armor types (--types):
  plate   — PlateArmor, Plate_Boots, Pure_White_Plate  (~92 patches, KNOWN WORKING)
  leather — Leather_Armor, Leather_Boots, Leather_Cloak, Leather_Gloves
  fabric  — Fabric_Armor, Fabric_Cloak, Skirt_Fabric, Greyfur_Fabric

Default: plate only. Use --types plate,leather to combine.
Use --all-types to patch everything (risky — may crash).
NPC/faction items (Demeniss, Uniform, etc.) are always excluded.

Requires: lz4  (pip install lz4)

Usage:
    python build_armor_mod.py <game_dir> --build-split          # RECOMMENDED: build all split mods
    python build_armor_mod.py <game_dir> --list                 # Preview what gets patched
    python build_armor_mod.py <game_dir> --types plate          # Plate only (single file)
    python build_armor_mod.py <game_dir> --test <name>          # Test single item/category

The mod must be split into multiple files because the game's mod loader
crashes when a single mod patches too wide a range of offsets within
iteminfo.pabgb. Each split file patches a contiguous region.

Output (--build-split):
    ../mods/kliff_plate.json        — plate armor (23 items)
    ../mods/kliff_leather_a.json    — leather items 1-12
    ../mods/kliff_leather_b.json    — leather items 13-17
    ../mods/kliff_fabric.json       — fabric armor
"""

import json
import os
import struct
import sys

import lz4.block

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paz_parse import parse_pamt

GAME_PAZ_FOLDER = "0008"

DAMIANE_TO_KLIFF = {
    0x26BE971F: 0xFC66D914,
    0xF96C1DD4: 0xBFA1F64B,
    0x8BF46446: 0x13FB2B6E,
    0xABFCD791: 0xD0A2E1EF,
    0x6CC4A721: 0xFE7169E2,
}

DAMIANE_HASHES = set(DAMIANE_TO_KLIFF.keys())

ALL_PREFIXES = ("DamianOnly_", "Demian_", "Damian_")

# Substrings that indicate NPC/faction items — always excluded
NPC_INDICATORS = (
    "Demeniss", "Uniform", "_Npc", "Npc_",
    "Enemy_", "Monster_", "Boss_",
)

# Specific items that cause CTD when patched (likely referenced by NPCs/cutscenes)
EXCLUDED_ITEMS = {
    "Demian_Leather_Gloves_II",  # crashes even in isolation
}

# Armor type categories — use --types to select which to include
ARMOR_CATEGORIES = {
    "plate":          ("PlateArmor", "Plate_Boots", "Pure_White_Plate"),
    "leather":        ("Leather_Armor", "Leather_Boots", "Leather_Cloak", "Leather_Gloves"),
    "leather-armor":  ("Leather_Armor",),
    "leather-boots":  ("Leather_Boots",),
    "leather-cloak":  ("Leather_Cloak",),
    "leather-gloves": ("Leather_Gloves",),
    "fabric":         ("Fabric_Armor", "Fabric_Cloak", "Skirt_Fabric", "Greyfur_Fabric"),
}
ALL_CATEGORY_NAMES = list(ARMOR_CATEGORIES.keys())


# ── Binary reader ───────────────────────────────────────────────────────────

class ParseError(Exception):
    pass


class Reader:
    __slots__ = ("data", "off")

    def __init__(self, data, off=0):
        self.data = data
        self.off = off

    def u8(self):
        v = self.data[self.off]; self.off += 1; return v

    def i8(self):
        v = struct.unpack_from('<b', self.data, self.off)[0]; self.off += 1; return v

    def u16(self):
        v = struct.unpack_from('<H', self.data, self.off)[0]; self.off += 2; return v

    def u32(self):
        v = struct.unpack_from('<I', self.data, self.off)[0]; self.off += 4; return v

    def i64(self):
        v = struct.unpack_from('<q', self.data, self.off)[0]; self.off += 8; return v

    def u64(self):
        v = struct.unpack_from('<Q', self.data, self.off)[0]; self.off += 8; return v

    def f32(self):
        v = struct.unpack_from('<f', self.data, self.off)[0]; self.off += 4; return v

    def f32x3(self):
        v = struct.unpack_from('<3f', self.data, self.off); self.off += 12; return list(v)

    def u32x4(self):
        v = struct.unpack_from('<4I', self.data, self.off); self.off += 16; return list(v)

    def cstring(self):
        n = self.u32()
        s = self.data[self.off:self.off + n].decode('utf-8', errors='replace')
        self.off += n
        return s

    def carray(self, read_fn):
        count = self.u32()
        return [read_fn() for _ in range(count)]

    def coptional(self, read_fn):
        present = self.u8()
        return read_fn() if present else None


# ── Struct readers ──────────────────────────────────────────────────────────

def read_localizable_string(r):
    r.u8(); r.u64(); return r.cstring()

def read_occupied_equip_slot_data(r):
    r.u32(); r.carray(r.u8)

def read_item_icon_data(r):
    r.u32(); r.u8(); r.carray(r.u32)

def read_passive_skill_level(r):
    r.u32(); r.u32()

def read_reserve_slot_target_data(r):
    r.u32(); r.u32()

def read_sub_item(r):
    t = r.u8()
    if t in (0, 3, 9):
        r.u32()
    elif t == 14:
        pass
    else:
        raise ParseError(f"unknown SubItem type: {t} at 0x{r.off - 1:X}")

def read_price_floor(r):
    r.u64(); r.u32(); r.u32()

def read_enchant_stat_data(r):
    r.carray(lambda: (r.u32(), r.i64()))
    r.carray(lambda: (r.u32(), r.i64()))
    r.carray(lambda: (r.u32(), r.i64()))
    r.carray(lambda: (r.u32(), r.i8()))

def read_enchant_data(r):
    r.u16()
    read_enchant_stat_data(r)
    r.carray(lambda: (r.u32(), read_price_floor(r)))
    r.carray(lambda: (r.u32(), r.u32()))

def read_drop_default_data(r):
    r.u16()
    r.carray(r.u32)
    r.carray(lambda: (r.u32(), r.u64()))
    read_sub_item(r)
    r.u8(); r.u8()

def read_sealable_item_info(r):
    tag = r.u8(); r.u32(); r.u64()
    if tag in (0, 1, 3, 4):
        r.u32()
    elif tag == 2:
        r.cstring()
    else:
        raise ParseError(f"unknown SealableItemInfo type: {tag}")

def read_gimmick_visual_prefab_data(r):
    r.u32(); r.f32x3(); r.carray(r.u32); r.carray(r.u32); r.u8()

def read_docking_child_data(r):
    r.u32(); r.u32(); r.u32(); r.cstring(); r.cstring()
    r.u32x4(); r.u16(); r.u32()
    for _ in range(9):
        r.u8()
    r.u32(); r.u8(); r.u8(); r.u8(); r.u8(); r.u8(); r.u8(); r.cstring()

def read_game_event_execute_data(r):
    r.u8(); r.u32(); r.u32(); r.u32()

def read_inventory_change_data(r):
    read_game_event_execute_data(r); r.u16()

def read_page_data(r):
    r.cstring(); r.cstring(); r.u32(); r.u32()

def read_inspect_data(r):
    r.u32(); r.u32(); r.u32(); r.u32(); r.cstring(); r.u32(); r.u32(); r.u8()
    r.u32(); read_localizable_string(r); r.u32(); r.u8(); r.u32(); r.u32()
    r.u8(); r.u32(); r.u8(); r.u8(); r.u32(); r.u32()

def read_inspect_action(r):
    r.u32(); r.u32(); r.cstring(); r.cstring()

def read_sharpness_data(r):
    r.u16(); r.u16(); read_enchant_stat_data(r)

def read_repair_data(r):
    r.u32(); r.u16(); r.u8(); r.u64()

def read_unit_data(r):
    r.cstring(); r.u32(); r.u32()
    read_localizable_string(r); read_localizable_string(r)

def read_money_type_define(r):
    r.u64()
    r.carray(lambda: (r.u32(), read_unit_data(r)))


def read_prefab_data_with_offsets(r):
    r.carray(r.u32)  # prefab_names
    r.carray(r.u16)  # equip_slot_list
    count = r.u32()   # tribe_gender_list count
    tribe_gender = []
    for _ in range(count):
        pos = r.off
        h = r.u32()
        tribe_gender.append({"hash": h, "abs_offset": pos})
    r.u8()  # is_craft_material
    return tribe_gender


def scan_item(r):
    """Parse one ItemInfo entry. Returns (string_key, display_name, item_start, tribe_gender_entries)."""
    start = r.off

    r.u32()  # key
    string_key = r.cstring()
    r.u8()   # is_blocked
    r.u64()  # max_stack_count
    display_name = read_localizable_string(r)  # item_name
    r.u32()  # broken_item_prefix_string
    r.u16()  # inventory_info
    r.u32()  # equip_type_info
    r.carray(lambda: read_occupied_equip_slot_data(r))
    r.carray(r.u32)  # item_tag_list
    r.u32()  # equipable_hash
    r.carray(r.u32)  # consumable_type_list
    r.carray(r.u32)  # item_use_info_list
    r.carray(lambda: read_item_icon_data(r))
    r.u32()  # map_icon_path
    r.u32()  # money_icon_path
    r.u8()   # use_map_icon_alert
    r.u8()   # item_type
    r.u32()  # material_key
    r.u32()  # material_match_info
    read_localizable_string(r)  # item_desc
    read_localizable_string(r)  # item_desc2
    r.u32()  # equipable_level
    r.u16()  # category_info
    r.u32()  # knowledge_info
    r.u8()   # knowledge_obtain_type
    r.u32()  # destroy_effect_info
    r.carray(lambda: read_passive_skill_level(r))
    r.u8()   # use_immediately
    r.u8()   # apply_max_stack_cap
    r.u32()  # extract_multi_change_info
    r.cstring()  # item_memo
    r.cstring()  # filter_type
    r.u32()  # gimmick_info
    r.carray(r.cstring)  # gimmick_tag_list
    r.u32()  # max_drop_result_sub_item_count
    r.u8()   # use_drop_set_target
    r.u8()   # is_all_gimmick_sealable
    r.carray(lambda: read_sealable_item_info(r))
    r.carray(lambda: read_sealable_item_info(r))
    r.carray(lambda: read_sealable_item_info(r))
    r.carray(lambda: read_sealable_item_info(r))
    r.carray(lambda: read_sealable_item_info(r))
    r.carray(r.u32)  # sealable_money_info_list
    r.u8()   # delete_by_gimmick_unlock
    r.u32()  # gimmick_unlock_message_local_string_info
    r.u8()   # can_disassemble
    r.carray(r.u32)  # transmutation_material_gimmick_list
    r.carray(r.u32)  # transmutation_material_item_list
    r.carray(r.u16)  # transmutation_material_item_group_list
    r.u8()   # is_register_trade_market
    r.carray(r.u32)  # multi_change_info_list
    r.u8()   # is_editor_usable
    r.u8()   # discardable
    r.u8()   # is_dyeable
    r.u8()   # is_editable_grime
    r.u8()   # is_destroy_when_broken
    r.u8()   # quick_slot_index
    r.carray(lambda: read_reserve_slot_target_data(r))
    r.u8()   # item_tier
    r.u8()   # is_important_item
    r.u8()   # apply_drop_stat_type
    read_drop_default_data(r)

    prefab_count = r.u32()
    all_tg = []
    for _ in range(prefab_count):
        tg_entries = read_prefab_data_with_offsets(r)
        all_tg.extend(tg_entries)

    r.carray(lambda: read_enchant_data(r))
    r.carray(lambda: read_gimmick_visual_prefab_data(r))
    r.carray(lambda: (r.u32(), read_price_floor(r)))
    r.coptional(lambda: read_docking_child_data(r))
    r.coptional(lambda: read_inventory_change_data(r))
    r.cstring()  # unk_texture_path
    r.carray(lambda: read_page_data(r))
    r.carray(lambda: read_page_data(r))
    r.carray(lambda: read_inspect_data(r))
    read_inspect_action(r)
    read_sub_item(r)
    r.i64()  # cooltime
    r.u8()   # item_charge_type
    read_sharpness_data(r)
    r.u32()  # max_charged_useable_count
    r.carray(r.u16)  # hackable_character_group_info_list
    r.carray(r.u16)  # item_group_info_list
    r.f32()  # discard_offset_y
    r.u8()   # hide_from_inventory_on_pop_item
    r.u8()   # is_shield_item
    r.u8()   # is_tower_shield_item
    r.u8()   # is_wild
    r.u32()  # packed_item_info
    r.u32()  # unpacked_item_info
    r.u32()  # convert_item_info_by_drop_npc
    r.u32()  # look_detail_game_advice_info_wrapper
    r.u32()  # look_detail_mission_info
    r.u8()   # enable_alert_system_to_ui
    r.u8()   # usable_alert
    r.u8()   # is_save_game_data_at_use_item
    r.u8()   # is_logout_at_use_item
    r.u32()  # shared_cool_time_group_name_hash
    r.carray(lambda: (r.u64(), r.u32()))  # item_bundle_data_list
    r.coptional(lambda: read_money_type_define(r))
    r.cstring()  # emoji_texture_id
    r.u8()   # enable_equip_in_clone_actor
    r.u8()   # is_blocked_store_sell
    r.u8()   # is_preorder_item
    r.i64()  # respawn_time_seconds
    r.u16()  # max_endurance
    r.carray(lambda: read_repair_data(r))

    return string_key, display_name, start, all_tg


# ── Helpers ─────────────────────────────────────────────────────────────────

def find_entry(entries, name):
    matches = [e for e in entries if name.lower() in e.path.lower()]
    exact = [e for e in matches
             if os.path.basename(e.path).lower() == name.lower()]
    return exact[0] if exact else (matches[0] if len(matches) == 1 else None)


def extract_raw(entry):
    read_size = entry.comp_size if entry.compressed else entry.orig_size
    with open(entry.paz_file, 'rb') as f:
        f.seek(entry.offset)
        data = f.read(read_size)
    if entry.compressed and entry.compression_type == 2:
        data = lz4.block.decompress(data, uncompressed_size=entry.orig_size)
    return data


def _categorize(name):
    """Return the armor category for an item name, or 'other'."""
    for cat, keywords in ARMOR_CATEGORIES.items():
        if any(kw in name for kw in keywords):
            return cat
    return "other"


def is_damiane_player_item(name, tg_entries, allowed_keywords=None):
    """True if this is a Damiane PLAYER equipment item with patchable hashes.

    allowed_keywords: if set, the item name must contain at least one of these
                      substrings (used for armor-type filtering).
    """
    if not tg_entries:
        return False
    if not name.startswith(ALL_PREFIXES):
        return False
    if name == "Item_Fist_Damian":
        return False
    if name in EXCLUDED_ITEMS:
        return False
    if any(ind in name for ind in NPC_INDICATORS):
        return False
    if allowed_keywords and not any(kw in name for kw in allowed_keywords):
        return False
    hashes = {e["hash"] for e in tg_entries}
    return hashes <= DAMIANE_HASHES and len(hashes) > 0


def hash_hex_le(h):
    return struct.pack('<I', h).hex()


def read_pabgh_offsets(header, item_count):
    """Read the [key, offset] table from the pabgh header.

    Returns list of (key_hash, body_offset) tuples, one per item.
    """
    entries = []
    for i in range(item_count):
        base = 2 + i * 8
        key_hash = struct.unpack_from('<I', header, base)[0]
        body_off = struct.unpack_from('<I', header, base + 4)[0]
        entries.append((key_hash, body_off))
    return entries


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python build_armor_mod.py <game_dir>")
        sys.exit(1)

    game_dir = sys.argv[1]
    paz_dir = os.path.join(game_dir, GAME_PAZ_FOLDER)
    pamt_path = os.path.join(paz_dir, "0.pamt")

    list_mode = "--list" in sys.argv
    test_mode = "--test" in sys.argv
    test_item = None
    if test_mode:
        ti = sys.argv.index("--test")
        if ti + 1 < len(sys.argv) and not sys.argv[ti + 1].startswith("-"):
            test_item = sys.argv[ti + 1]
        else:
            test_item = "DamianOnly_Leather_Boots_II"
        print(f"*** TEST MODE: patching only {test_item} ***")

    # Armor type selection: --types plate,leather,fabric  or  --all-types
    all_types_mode = "--all-types" in sys.argv
    allowed_keywords = None
    if "--types" in sys.argv:
        ti = sys.argv.index("--types")
        if ti + 1 < len(sys.argv):
            requested = [t.strip() for t in sys.argv[ti + 1].split(",")]
            keywords = []
            for cat in requested:
                if cat not in ARMOR_CATEGORIES:
                    print(f"ERROR: Unknown armor type '{cat}'. "
                          f"Available: {', '.join(ALL_CATEGORY_NAMES)}")
                    sys.exit(1)
                keywords.extend(ARMOR_CATEGORIES[cat])
            allowed_keywords = tuple(keywords)
    elif all_types_mode:
        allowed_keywords = None  # no filtering — all Damiane items
    else:
        # Default: plate only (the known-working set, ~92 patches)
        allowed_keywords = ARMOR_CATEGORIES["plate"]

    max_items = None
    if "--max-items" in sys.argv:
        mi = sys.argv.index("--max-items")
        if mi + 1 < len(sys.argv):
            max_items = int(sys.argv[mi + 1])

    skip_items = 0
    if "--skip-items" in sys.argv:
        si = sys.argv.index("--skip-items")
        if si + 1 < len(sys.argv):
            skip_items = int(sys.argv[si + 1])

    allow_items = None
    if "--allow-items" in sys.argv:
        ai = sys.argv.index("--allow-items")
        if ai + 1 < len(sys.argv):
            allow_items = set(int(x) for x in sys.argv[ai + 1].split(","))

    output_name = "kliff_wears_damiane_armor"
    if "--output" in sys.argv:
        oi = sys.argv.index("--output")
        if oi + 1 < len(sys.argv):
            output_name = sys.argv[oi + 1].replace(".json", "")

    print("=" * 70)
    print("KLIFF WEARS DAMIANE ARMOR — Mod Builder v5")
    print("=" * 70)
    if allowed_keywords:
        print(f"  Armor filter: {allowed_keywords}")
    else:
        print(f"  Armor filter: ALL types (--all-types)")
    print(f"  NPC exclusion: ON")
    if max_items:
        print(f"  Max items: {max_items}")
    if skip_items:
        print(f"  Skip items: {skip_items}")
    if allow_items:
        print(f"  Allow items: {sorted(allow_items)}")

    print("\n[1] Parsing PAMT index...")
    entries = parse_pamt(pamt_path, paz_dir=paz_dir)

    print("[2] Extracting iteminfo...")
    body_entry = find_entry(entries, "iteminfo.pabgb")
    header_entry = find_entry(entries, "iteminfo.pabgh")
    body = extract_raw(body_entry)
    header = extract_raw(header_entry)

    item_count = struct.unpack_from('<H', header, 0)[0]
    print(f"    {item_count} items, body {len(body):,} bytes, header {len(header):,} bytes")

    # ── Read pabgh offset table ──
    print("\n[3] Reading pabgh offset table...")
    pabgh_table = read_pabgh_offsets(header, item_count)

    print(f"    First 5 pabgh entries:")
    for i in range(min(5, item_count)):
        kh, bo = pabgh_table[i]
        print(f"      [{i}] key=0x{kh:08X}, body_offset=0x{bo:08X}")

    # ── Sequential parse with pabgh comparison ──
    print("\n[4] Parsing items and comparing offsets with pabgh...")
    r = Reader(body)
    patch_targets = []
    errors = 0
    delta_samples = []

    for i in range(item_count):
        start = r.off
        pabgh_off = pabgh_table[i][1]
        delta = pabgh_off - start

        if i < 5:
            print(f"      [{i}] parse_start=0x{start:08X}, pabgh_offset=0x{pabgh_off:08X}, delta={delta}")

        if i < 20:
            delta_samples.append(delta)

        try:
            string_key, display_name, item_start, tg_entries = scan_item(r)
        except Exception as e:
            errors += 1
            if errors <= 3:
                print(f"    WARN: parse error at item #{i} offset 0x{start:X}: {e}")
            if i + 1 < item_count:
                r.off = pabgh_table[i + 1][1]
            else:
                break
            continue

        if list_mode and is_damiane_player_item(string_key, tg_entries, allowed_keywords=None):
            cat = _categorize(string_key)
            dn = display_name if display_name else ""
            n_hashes = len([e for e in tg_entries if e["hash"] in DAMIANE_HASHES])
            print(f"      {string_key:50s}  [{cat:7s}]  {n_hashes} hashes  {dn}")
            continue

        # --test bypasses the type filter so you can test any single item
        effective_keywords = None if test_mode else allowed_keywords
        if is_damiane_player_item(string_key, tg_entries, allowed_keywords=effective_keywords):
            if test_mode and test_item.lower() not in string_key.lower():
                continue
            if max_items and len(patch_targets) >= max_items:
                continue
            damiane_entries = [e for e in tg_entries if e["hash"] in DAMIANE_HASHES]
            if damiane_entries:
                patch_targets.append({
                    "entry": string_key,
                    "item_start": item_start,
                    "pabgh_offset": pabgh_off,
                    "hashes": damiane_entries,
                })

    # Check if there's a consistent delta
    unique_deltas = set(delta_samples)
    print(f"\n    Delta samples (first 20): {delta_samples}")
    print(f"    Unique deltas: {unique_deltas}")
    if len(unique_deltas) == 1:
        delta = delta_samples[0]
        print(f"    Consistent delta: {delta}")
    else:
        delta = 0
        print(f"    WARNING: inconsistent deltas, using 0")

    if list_mode:
        print(f"\n    Use --types plate,leather,fabric to select categories.")
        print(f"    Default (no flag) builds plate only (~92 patches, known working).")
        return

    # Print full numbered list with offset info before filtering
    print(f"\n    All matching items ({len(patch_targets)}):")
    for idx, t in enumerate(patch_targets):
        marker = ""
        if allow_items and (idx + 1) not in allow_items:
            marker = "  [SKIPPED]"
        min_off = min(h["abs_offset"] for h in t["hashes"])
        max_off = max(h["abs_offset"] for h in t["hashes"])
        print(f"      [{idx+1:2d}] {t['entry']:50s} ({len(t['hashes'])} h) "
              f"offsets 0x{min_off:08X}-0x{max_off:08X}{marker}")

    if allow_items:
        patch_targets = [t for idx, t in enumerate(patch_targets) if (idx + 1) in allow_items]
        print(f"    After --allow-items filter: {len(patch_targets)} items")

    if skip_items:
        skipped = patch_targets[:skip_items]
        patch_targets = patch_targets[skip_items:]
        print(f"    Skipped first {len(skipped)} items: {[s['entry'] for s in skipped]}")

    print(f"    Found {len(patch_targets)} Damiane-exclusive items to patch")
    if errors:
        print(f"    ({errors} parse errors skipped)")

    # ── Self-validate all offsets against raw body bytes ──
    print("\n[5] Self-validating offsets against raw body data...")
    valid = 0
    invalid = 0
    for target in patch_targets:
        for h_entry in target["hashes"]:
            abs_off = h_entry["abs_offset"]
            expected_hash = h_entry["hash"]
            if abs_off + 4 <= len(body):
                actual = struct.unpack_from('<I', body, abs_off)[0]
                if actual == expected_hash:
                    valid += 1
                else:
                    invalid += 1
                    if invalid <= 3:
                        print(f"    MISMATCH: {target['entry']} @ 0x{abs_off:X}: "
                              f"expected 0x{expected_hash:08X}, got 0x{actual:08X}")
            else:
                invalid += 1

    print(f"    Self-validation: {valid} OK, {invalid} MISMATCH")

    if invalid > 0 and valid == 0:
        print("\n    FATAL: ALL offsets fail self-validation.")
        print("    The parser is producing wrong positions. Cannot generate mod.")
        sys.exit(1)

    if invalid > 0:
        print(f"\n    WARNING: {invalid} offsets failed self-validation (will skip those)")

    # ── Structural context validation ──
    # The hash value alone isn't enough — a Damiane hash could appear by coincidence
    # in unrelated data if the parser drifted. Verify structural context:
    #   - 4 bytes before the first hash = u32 count (should match number of hashes)
    #   - 1 byte after the last hash = is_craft_material (should be 0 or 1)
    print("\n[5b] Structural context validation...")
    context_ok = 0
    context_bad = 0
    clean_targets = []
    for target in patch_targets:
        hashes = sorted(target["hashes"], key=lambda e: e["abs_offset"])
        if not hashes:
            continue

        first_off = hashes[0]["abs_offset"]
        last_off = hashes[-1]["abs_offset"]
        passes = True

        # Check count field (u32 right before first hash)
        count_off = first_off - 4
        if count_off >= 0 and count_off + 4 <= len(body):
            stored_count = struct.unpack_from('<I', body, count_off)[0]
            if stored_count != len(hashes):
                print(f"    CONTEXT FAIL: {target['entry']} — "
                      f"count field says {stored_count}, we found {len(hashes)} hashes")
                passes = False
        else:
            passes = False

        # Check is_craft_material (u8 right after last hash)
        craft_off = last_off + 4
        if craft_off < len(body):
            craft_byte = body[craft_off]
            if craft_byte not in (0, 1):
                print(f"    CONTEXT FAIL: {target['entry']} — "
                      f"is_craft_material=0x{craft_byte:02X} (expected 0 or 1)")
                passes = False
        else:
            passes = False

        if passes:
            context_ok += 1
            clean_targets.append(target)
        else:
            context_bad += 1

    print(f"    Context validation: {context_ok} OK, {context_bad} REJECTED")
    if context_bad > 0:
        print(f"    Rejected items had corrupted structural context (parser drift)")
    patch_targets = clean_targets

    # ── Generate JSON patch (v1: absolute offsets only) ──
    print("\n[6] Generating JSON patch (v1: absolute offsets, no entry names)...")
    changes = []
    seen_offsets = {}
    duplicates = 0
    for target in patch_targets:
        for h_entry in target["hashes"]:
            old_hash = h_entry["hash"]
            new_hash = DAMIANE_TO_KLIFF[old_hash]
            abs_off = h_entry["abs_offset"]

            if abs_off + 4 > len(body):
                continue
            actual = struct.unpack_from('<I', body, abs_off)[0]
            if actual != old_hash:
                continue

            if abs_off in seen_offsets:
                duplicates += 1
                print(f"    DUPLICATE offset 0x{abs_off:08X}: "
                      f"{seen_offsets[abs_off]} AND {target['entry']}")
                continue
            seen_offsets[abs_off] = target['entry']

            changes.append({
                "offset": abs_off,
                "original": hash_hex_le(old_hash),
                "patched": hash_hex_le(new_hash),
                "label": f"{target['entry']} tribe 0x{old_hash:08X}->0x{new_hash:08X}",
            })

    if duplicates:
        print(f"    WARNING: {duplicates} duplicate offsets removed (shared tribe_gender_list)")
    else:
        print(f"    No duplicate offsets found")

    # Sort patches by offset — some mod loaders expect ascending order
    changes.sort(key=lambda c: c["offset"])

    # Show offset range diagnostic
    if changes:
        offsets = [c["offset"] for c in changes]
        print(f"    Offset range: 0x{min(offsets):08X} - 0x{max(offsets):08X}")
        # Check for non-monotonic offsets before sorting (were they out of order?)
        print(f"    Patches sorted by offset: {len(changes)} entries")

    MOD_TITLES = {
        "kliff_plate":     "Kliff Wears Damiane Plate",
        "kliff_leather_a": "Kliff Wears Damiane Leather (A)",
        "kliff_leather_b": "Kliff Wears Damiane Leather (B)",
        "kliff_fabric":    "Kliff Wears Damiane Fabric",
    }
    mod_title = MOD_TITLES.get(output_name, f"Kliff Wears Damiane Armor — {output_name}")

    mod = {
        "modinfo": {
            "title": mod_title,
            "version": "1.3",
            "author": "Benreuveni",
            "description": (
                f"{mod_title}. "
                "Allows Kliff to equip Damiane-exclusive armor pieces. "
                "Designed for use with a Kliff-to-Damiane model swap mod."
            ),
        },
        "patches": [
            {
                "game_file": "gamedata/binary__/client/bin/iteminfo.pabgb",
                "source_group": GAME_PAZ_FOLDER,
                "changes": changes,
            }
        ],
    }

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mods")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{output_name}.json")

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(mod, f, indent=4)

    print(f"\n    Generated {len(changes)} verified patch entries across {len(patch_targets)} items:")
    for idx, target in enumerate(patch_targets):
        n = len([h for h in target["hashes"]
                 if any(c["offset"] == h["abs_offset"] for c in changes)])
        if n:
            print(f"      [{idx+1:2d}] {target['entry']} ({n} hashes)")

    print(f"\n    Mod file: {os.path.abspath(out_path)}")

    # ── Hex dump of first few patches for debugging ──
    print("\n[7] Hex dump verification (first 5 patches):")
    for c in changes[:5]:
        off = c["offset"]
        raw = body[off:off + 16]
        hex_str = ' '.join(f'{b:02x}' for b in raw)
        print(f"    offset=0x{off:08X}: [{hex_str}]")
        print(f"      original={c['original']} patched={c['patched']}")
        print(f"      label={c['label']}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Pabgh delta (pabgh_offset - parse_offset): {delta}")
    print(f"  Self-validated patches: {len(changes)}")
    print(f"  Format: v1 (absolute offsets only, no entry names)")
    print(f"  Game file path: gamedata/binary__/client/bin/iteminfo.pabgb")
    print(f"\n  To install: copy kliff_wears_damiane_armor.json into mod manager Mods/ folder")
    print("=" * 70)


def build_split(game_dir):
    """Generate all split mod files in one command."""
    import subprocess

    builds = [
        ("kliff_plate",     ["--types", "plate"]),
        ("kliff_leather_a", ["--test", "Leather", "--max-items", "12"]),
        ("kliff_leather_b", ["--test", "Leather", "--skip-items", "12"]),
        ("kliff_fabric",    ["--test", "Fabric"]),
    ]

    results = []
    for name, extra_args in builds:
        print(f"\n{'='*70}")
        print(f"  Building {name}...")
        print(f"{'='*70}")
        cmd = [sys.executable, __file__, game_dir, "--output", name] + extra_args
        ret = subprocess.call(cmd)
        results.append((name, ret))

    print(f"\n{'='*70}")
    print("SPLIT BUILD COMPLETE")
    print(f"{'='*70}")
    for name, ret in results:
        status = "OK" if ret == 0 else f"FAILED (exit {ret})"
        print(f"  {name:25s} {status}")
    print(f"\n  Install all .json files from the mods/ folder into your mod manager.")
    print(f"  Overlap warnings are expected and safe — patches target different offsets.")
    print(f"{'='*70}")


def build_combined(game_dir):
    """Build plate + fabric + leather_a as a single mod file."""
    import subprocess, tempfile, glob as globmod

    builds = [
        ("_tmp_plate",     ["--types", "plate"]),
        ("_tmp_leather_a", ["--test", "Leather", "--max-items", "12"]),
        ("_tmp_fabric",    ["--test", "Fabric"]),
    ]

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mods")
    os.makedirs(out_dir, exist_ok=True)

    all_changes = []
    for name, extra_args in builds:
        print(f"\n{'='*70}")
        print(f"  Building {name}...")
        print(f"{'='*70}")
        cmd = [sys.executable, __file__, game_dir, "--output", name] + extra_args
        ret = subprocess.call(cmd)
        if ret != 0:
            print(f"  FAILED building {name}, aborting")
            return

        tmp_path = os.path.join(out_dir, f"{name}.json")
        with open(tmp_path, 'r') as f:
            mod_data = json.load(f)
        changes = mod_data["patches"][0]["changes"]
        all_changes.extend(changes)
        print(f"  Collected {len(changes)} patches from {name}")
        os.remove(tmp_path)

    all_changes.sort(key=lambda c: c["offset"])

    combined = {
        "modinfo": {
            "title": "Kliff Wears Damiane Armor",
            "version": "1.4",
            "author": "Benreuveni",
            "description": (
                "Allows Kliff to equip Damiane-exclusive armor (plate + leather + fabric). "
                "Designed for use with a Kliff-to-Damiane model swap mod."
            ),
        },
        "patches": [
            {
                "game_file": "gamedata/binary__/client/bin/iteminfo.pabgb",
                "source_group": GAME_PAZ_FOLDER,
                "changes": all_changes,
            }
        ],
    }

    out_path = os.path.join(out_dir, "kliff_wears_damiane_armor.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(combined, f, indent=4)

    print(f"\n{'='*70}")
    print("COMBINED BUILD COMPLETE")
    print(f"{'='*70}")
    print(f"  Total patches: {len(all_changes)}")
    print(f"  Output: {os.path.abspath(out_path)}")
    print(f"{'='*70}")


if __name__ == "__main__":
    if "--build-split" in sys.argv:
        if len(sys.argv) < 2:
            print("Usage: python build_armor_mod.py <game_dir> --build-split")
            sys.exit(1)
        build_split(sys.argv[1])
    elif "--build-combined" in sys.argv:
        if len(sys.argv) < 2:
            print("Usage: python build_armor_mod.py <game_dir> --build-combined")
            sys.exit(1)
        build_combined(sys.argv[1])
    else:
        main()
