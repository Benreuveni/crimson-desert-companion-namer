"""Crimson Desert — Pet & Companion Rename Tool

Renames (or clears names of) mercenaries (pets, mounts, companions) by
modifying the _mercenaryName field in MercenarySaveData within save files.

Strategy: binary-level patching with full offset fixup.
  1. Decrypt save → parse PARC reflection layout → locate MercenarySaveData
  2. Set/clear the bitmap bit for _mercenaryName
  3. Insert, replace, or remove the SIZE_PREFIXED string (u32_len + bytes)
  4. Fix up ALL offsets in the object info table and inline value_offsets
  5. Re-compress (LZ4) → HMAC-SHA256 → ChaCha20 encrypt → write .save

Usage:
    python save_pet_rename.py <save_file> --list
    python save_pet_rename.py <save_file> --rename 615 "Rex" -o patched.save
    python save_pet_rename.py <save_file> --rename-multi 1027=Kraken 615=Grendel -o out.save
    python save_pet_rename.py <save_file> --rename-all -o labeled.save
    python save_pet_rename.py <save_file> --clear-unnamed -o cleaned.save
    python save_pet_rename.py <save_file> --clear 615 556 -o cleared.save
    python save_pet_rename.py <save_file> --clear-all -o vanilla.save

Typical workflow:
    1. Back up your save.save
    2. --rename-all -o labeled.save     → labels every mercenary with M_<no>
    3. Load the game, note which M_xxx appears on which character
    4. --rename-multi 1027=Kraken 615=Grendel -o named.save  → set real names
    5. --clear-unnamed -o final.save    → removes leftover M_<no> labels

Acknowledgements:
    - Save file encryption (ChaCha20 key derivation, HMAC, header format)
      reverse-engineered by LukeFZ: https://github.com/LukeFZ/pycrimson
    - PARC reflection serialization format documented via pycrimson and
      community research (MrIkso/CrimsonDesertTools .hexpat templates)
    - PAZ archive tools from lazorr410/crimson-desert-unpacker and
      Jominiumiumium/CrimsonDesert_Item_hider
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from save_decrypt import decrypt_save, encrypt_save


# ── Reflection header parser (minimal, just enough to navigate) ─────

def parse_reflection_layout(data: bytes) -> dict:
    """Parse the reflection data layout and return key positions."""
    off = 0

    # Header
    marker = struct.unpack_from('<H', data, off)[0]; off += 2
    assert marker == 0xFFFF, f"Expected 0xFFFF marker, got 0x{marker:X}"
    meta_ver = struct.unpack_from('<I', data, off)[0]; off += 4
    ref_hash = struct.unpack_from('<Q', data, off)[0]; off += 8
    ser_ver = struct.unpack_from('<I', data, off)[0]; off += 4
    type_count = struct.unpack_from('<H', data, off)[0]; off += 2

    # Parse all types
    types = []
    for ti in range(type_count):
        name_len = struct.unpack_from('<I', data, off)[0]; off += 4
        tname = data[off:off + name_len].decode('utf-8'); off += name_len
        prop_count = struct.unpack_from('<H', data, off)[0]; off += 2
        props = []
        for pi in range(prop_count):
            pname_len = struct.unpack_from('<I', data, off)[0]; off += 4
            pname = data[off:off + pname_len].decode('utf-8'); off += pname_len
            ptname_len = struct.unpack_from('<I', data, off)[0]; off += 4
            ptname = data[off:off + ptname_len].decode('utf-8'); off += ptname_len
            prop_type = struct.unpack_from('<H', data, off)[0]; off += 2
            fixed_size = struct.unpack_from('<H', data, off)[0]; off += 2
            flags = struct.unpack_from('<I', data, off)[0]; off += 4
            props.append({
                'name': pname, 'type_name': ptname,
                'prop_type': prop_type, 'fixed_size': fixed_size, 'flags': flags,
            })
        types.append({'name': tname, 'properties': props})

    # Object names
    name_count = struct.unpack_from('<I', data, off)[0]; off += 4
    for _ in range(name_count):
        slen = struct.unpack_from('<I', data, off)[0]; off += 4
        off += slen

    # Object count + end_offset
    obj_count = struct.unpack_from('<I', data, off)[0]; off += 4
    end_offset_pos = off
    end_offset = struct.unpack_from('<I', data, off)[0]; off += 4

    # Object info table
    info_table_pos = off
    infos = []
    for i in range(obj_count):
        rec_start = off
        ti2 = struct.unpack_from('<H', data, off)[0]; off += 2
        _unk1 = struct.unpack_from('<H', data, off)[0]; off += 2
        _unk2 = struct.unpack_from('<q', data, off)[0]; off += 8
        offset_field_pos = off
        obj_off = struct.unpack_from('<I', data, off)[0]; off += 4
        size_field_pos = off
        obj_sz = struct.unpack_from('<I', data, off)[0]; off += 4
        infos.append({
            'type_index': ti2, 'offset': obj_off, 'size': obj_sz,
            'offset_field_pos': offset_field_pos,
            'size_field_pos': size_field_pos,
        })

    return {
        'meta_ver': meta_ver, 'ser_ver': ser_ver,
        'types': types, 'type_count': type_count,
        'obj_count': obj_count,
        'end_offset_pos': end_offset_pos, 'end_offset': end_offset,
        'info_table_pos': info_table_pos,
        'infos': infos,
        'data_start': off,
    }


# ── Navigate to mercenary objects in the binary ─────────────────────

def find_mercenary_bitmap_positions(data: bytes, layout: dict) -> list:
    """Find the byte positions and MercenaryNo for each MercenarySaveData.

    Returns list of dicts with:
      mercenary_no, bitmap_pos, bitmap_bytes, name_bit_set,
      name_insert_pos (where to insert the string if bit is not set)
    """
    types = layout['types']
    ser_ver = layout['ser_ver']

    # Find type indices
    merc_save_ti = next(i for i, t in enumerate(types) if t['name'].startswith('MercenarySaveData'))
    merc_clan_ti = next(i for i, t in enumerate(types) if t['name'] == 'MercenaryClanSaveData')

    merc_save_type = types[merc_save_ti]
    merc_clan_type = types[merc_clan_ti]

    # _mercenaryName is property index 4
    name_prop_idx = next(i for i, p in enumerate(merc_save_type['properties'])
                         if p['name'] == '_mercenaryName')

    # Find MercenaryClanSaveData in the info table
    clan_info = next(info for info in layout['infos'] if info['type_index'] == merc_clan_ti)
    clan_offset = clan_info['offset']

    # Navigate into MercenaryClanSaveData
    off = clan_offset

    # Read bitmap
    bmp_len = struct.unpack_from('<H', data, off)[0]; off += 2
    bmp = data[off:off + bmp_len]; off += bmp_len

    # ser_ver >= 10: unknown0
    _unk0 = data[off]; off += 1

    # ser_ver >= 5: no_tags flag
    no_tags = data[off]; off += 1
    if not no_tags and ser_ver >= 6:
        tag_count = struct.unpack_from('<H', data, off)[0]; off += 2
        for _ in range(tag_count):
            off += 2  # prop_index
            tag_len = struct.unpack_from('<I', data, off)[0]; off += 4
            off += tag_len

    # MercenaryClanSaveData properties:
    #   0: _list (OBJECT_ARRAY)
    #   1: _mercenaryDataList (OBJECT_ARRAY) <- this is what we want
    #   2: _hyosiMercenarySaveList (OBJECT_ARRAY)
    #   3: _callMercenaryCoolTimeSaveList (OBJECT_ARRAY)
    #   4: _callMercenarySpawnDurationSaveList (OBJECT_ARRAY)
    #   5: _currentFarmUpdateDay (DEFAULT, uint32)
    #   6: _lastFocusCharacterKey (DEFAULT, CharacterKey=4bytes)

    clan_props = merc_clan_type['properties']

    results = []

    for pi, prop in enumerate(clan_props):
        bit_missing = ((bmp[pi // 8] >> (pi & 7)) & 1) == 0

        if ser_ver >= 9 and (prop['flags'] & ((1 << 7) | (1 << 1))):
            continue

        is_array = prop['prop_type'] in (3, 6, 7, 9, 10)
        if not is_array and bit_missing:
            continue

        if prop['name'] == '_mercenaryDataList':
            # This is the OBJECT_ARRAY of MercenarySaveData
            results = _parse_mercenary_array(data, off, layout, merc_save_type, name_prop_idx)
            # Skip past this array to continue
            break

        # Skip other properties to get to _mercenaryDataList
        off = _skip_property_value(data, off, prop, layout)

    return results


def _parse_mercenary_array(data, off, layout, merc_type, name_prop_idx):
    """Parse the _mercenaryDataList OBJECT_ARRAY and extract positions."""
    ser_ver = layout['ser_ver']
    results = []

    # OBJECT_ARRAY header:
    # ser_ver >= 15: u8 empty_flag (if 1, array is empty)
    if ser_ver >= 0xF:
        empty_flag = data[off]; off += 1
        if empty_flag == 1:
            return results

    array_count = struct.unpack_from('<I', data, off)[0]; off += 4

    # ser_ver >= 14: has_named_objects flag
    has_named = False
    if ser_ver >= 0xE:
        has_named = data[off] == 1; off += 1

    # ser_ver >= 11: unknown0 (i64)
    _unk0 = struct.unpack_from('<q', data, off)[0]; off += 8

    # ser_ver >= 11: unk_count + optional arrays
    unk_count = struct.unpack_from('<i', data, off)[0]; off += 4
    if unk_count > 0:
        off += unk_count * 8  # i64 array
        if has_named:
            off += unk_count * 4  # i32 name indices

    # Now parse each MercenarySaveData object
    for idx in range(array_count):
        merc_info = _parse_single_mercenary(data, off, layout, merc_type, name_prop_idx)
        results.append(merc_info)
        off = merc_info['object_end']

    return results


def _parse_single_mercenary(data, off, layout, merc_type, name_prop_idx):
    """Parse one MercenarySaveData and record bitmap/insertion positions."""
    ser_ver = layout['ser_ver']
    props = merc_type['properties']

    # Object metadata (nested, has_metadata=True)
    bitmap_pos = off
    bmp_len = struct.unpack_from('<H', data, off)[0]; off += 2
    bmp = bytearray(data[off:off + bmp_len]); off += bmp_len

    # type_index
    _type_idx = struct.unpack_from('<H', data, off)[0]; off += 2

    # ser_ver >= 11: unknown1 (u8), unknown0 (i64)
    _unk1 = data[off]; off += 1
    _unk0 = struct.unpack_from('<q', data, off)[0]; off += 8

    # value_offset (absolute)
    value_offset_pos = off
    value_offset = struct.unpack_from('<I', data, off)[0]; off += 4

    # Jump to the actual data
    off = value_offset

    # ser_ver >= 10: unknown0
    _unk_a = data[off]; off += 1

    # ser_ver >= 5: no_tags
    no_tags = data[off]; off += 1
    if not no_tags and ser_ver >= 6:
        tag_count = struct.unpack_from('<H', data, off)[0]; off += 2
        for _ in range(tag_count):
            off += 2
            tag_len = struct.unpack_from('<I', data, off)[0]; off += 4
            off += tag_len

    # Read ALL properties, extracting useful fields along the way
    name_bit = (bmp[name_prop_idx // 8] >> (name_prop_idx & 7)) & 1
    merc_no = None
    name_insert_pos = None
    name_current_value = None
    extra = {}

    # Simple DEFAULT fields we want to read (name -> struct format)
    _READ_FIELDS = {
        '_characterKey': '<I',
        '_lastSummoned': '<B',
        '_isMainMercenary': '<B',
        '_isDead': '<B',
        '_isHyosiMercenary': '<B',
        '_currentHp': '<q',
    }

    for pi, prop in enumerate(props):
        bit_missing = ((bmp[pi // 8] >> (pi & 7)) & 1) == 0

        if ser_ver >= 9 and (prop['flags'] & ((1 << 7) | (1 << 1))):
            continue

        is_array = prop['prop_type'] in (3, 6, 7, 9, 10)
        if not is_array and bit_missing:
            if pi == name_prop_idx:
                name_insert_pos = off
            continue

        if prop['name'] == '_mercenaryNo':
            merc_no = struct.unpack_from('<Q', data, off)[0]

        if prop['name'] in _READ_FIELDS and prop['prop_type'] in (0, 2):
            extra[prop['name']] = struct.unpack_from(_READ_FIELDS[prop['name']], data, off)[0]

        if prop['name'] == '_equipItemList':
            arr_off = off
            if ser_ver >= 0xF:
                if data[arr_off] == 1:
                    extra['_equip_count'] = 0
                else:
                    extra['_equip_count'] = struct.unpack_from('<I', data, arr_off + 1)[0]
            else:
                extra['_equip_count'] = struct.unpack_from('<I', data, arr_off)[0]

        if pi == name_prop_idx:
            str_len = struct.unpack_from('<I', data, off)[0]
            name_current_value = data[off + 4:off + 4 + str_len].decode('utf-8', errors='replace')
            name_insert_pos = off

        off = _skip_property_value(data, off, prop, layout)

    # Object size marker (has_metadata=True -> u32 at end)
    _obj_size = struct.unpack_from('<I', data, off)[0]
    obj_end = off + 4

    return {
        'mercenary_no': merc_no,
        'bitmap_pos': bitmap_pos,
        'bitmap_bytes': bytes(bmp),
        'bitmap_len': bmp_len,
        'name_bit_set': bool(name_bit),
        'name_prop_idx': name_prop_idx,
        'name_insert_pos': name_insert_pos,
        'name_current_value': name_current_value,
        'value_offset_pos': value_offset_pos,
        'object_end': obj_end,
        'extra': extra,
    }


def _skip_property_value(data, off, prop, layout):
    """Skip over a property value in the binary data. Returns new offset."""
    ser_ver = layout['ser_ver']
    pt = prop['prop_type']

    if pt == 0:  # DEFAULT
        return off + prop['fixed_size']
    elif pt == 1:  # SIZE_PREFIXED
        str_len = struct.unpack_from('<I', data, off)[0]
        return off + 4 + str_len
    elif pt == 2:  # ENUM
        return off + prop['fixed_size']
    elif pt == 3:  # SIMPLE_ARRAY
        if ser_ver >= 0xF:
            if data[off] == 1:
                return off + 1
            off += 1
        count = struct.unpack_from('<I', data, off)[0]
        return off + 4 + count * prop['fixed_size']
    elif pt in (4,):  # OBJECT
        return _skip_object(data, off, layout)
    elif pt == 5:  # OPTIONAL_OBJECT
        flag = data[off]; off += 1
        if flag == 0:
            return off
        return _skip_object(data, off, layout)
    elif pt in (6, 7):  # OBJECT_ARRAY / OBJECT_PTR_ARRAY
        if ser_ver >= 0xF:
            if data[off] == 1:
                return off + 1
            off += 1
        count = struct.unpack_from('<I', data, off)[0]; off += 4
        has_named = False
        if ser_ver >= 0xE:
            has_named = data[off] == 1; off += 1
        if ser_ver >= 0xB:
            off += 8  # i64
        elif ser_ver >= 8:
            off += 4
        elif ser_ver >= 4:
            off += 2
        if ser_ver >= 0xB:
            unk_count = struct.unpack_from('<i', data, off)[0]; off += 4
            if unk_count > 0:
                off += unk_count * 8
                if has_named:
                    off += unk_count * 4
        for _ in range(count):
            off = _skip_object(data, off, layout)
        return off
    elif pt == 10:  # SIZE_PREFIXED_ARRAY
        if ser_ver >= 0xF:
            if data[off] == 1:
                return off + 1
            off += 1
        count = struct.unpack_from('<I', data, off)[0]; off += 4
        for _ in range(count):
            str_len = struct.unpack_from('<I', data, off)[0]; off += 4
            off += str_len * prop['fixed_size']
        return off
    else:
        raise ValueError(f"Unknown property type {pt}")


def _skip_object(data, off, layout):
    """Skip an inline (nested) object. Returns offset after the object."""
    ser_ver = layout['ser_ver']
    types = layout['types']

    # Bitmap
    bmp_len = struct.unpack_from('<H', data, off)[0]; off += 2
    bmp = data[off:off + bmp_len]; off += bmp_len

    # type_index
    type_idx = struct.unpack_from('<H', data, off)[0]; off += 2

    # Metadata
    if ser_ver >= 0xB:
        off += 1 + 8  # u8 + i64
    elif ser_ver >= 8:
        off += 4
    else:
        off += 2

    # value_offset + seek
    value_offset = struct.unpack_from('<I', data, off)[0]; off += 4
    off = value_offset

    type_info = types[type_idx]

    # u8 unknown (ser_ver >= 10)
    if ser_ver >= 0xA:
        off += 1

    # no_tags
    if ser_ver >= 5:
        no_tags = data[off]; off += 1
        if not no_tags and ser_ver >= 6:
            tag_count = struct.unpack_from('<H', data, off)[0]; off += 2
            for _ in range(tag_count):
                off += 2
                tag_len = struct.unpack_from('<I', data, off)[0]; off += 4
                off += tag_len

    # Properties
    for pi, prop in enumerate(type_info['properties']):
        bit_missing = ((bmp[pi // 8] >> (pi & 7)) & 1) == 0
        if ser_ver >= 9 and (prop['flags'] & ((1 << 7) | (1 << 1))):
            continue
        is_array = prop['prop_type'] in (3, 6, 7, 9, 10)
        if not is_array and bit_missing:
            continue
        off = _skip_property_value(data, off, prop, layout)

    # Size marker
    _size = struct.unpack_from('<I', data, off)[0]; off += 4
    return off


# ── Patching ────────────────────────────────────────────────────────

def patch_mercenary_name(data: bytearray, layout: dict, merc_info: dict, new_name: str) -> bytearray:
    """Patch the save data to set a mercenary's _mercenaryName field.

    Returns the modified data.
    """
    name_bytes = new_name.encode('utf-8')
    name_prop_idx = merc_info['name_prop_idx']

    if merc_info['name_bit_set']:
        # Field already exists — replace the string value
        old_pos = merc_info['name_insert_pos']
        old_len = struct.unpack_from('<I', data, old_pos)[0]
        old_total = 4 + old_len  # u32 + string
        new_total = 4 + len(name_bytes)
        delta = new_total - old_total

        # Replace the string
        new_field = struct.pack('<I', len(name_bytes)) + name_bytes
        data = bytearray(data[:old_pos]) + new_field + bytearray(data[old_pos + old_total:])

    else:
        # Field not present — need to set bitmap bit and insert string
        insert_pos = merc_info['name_insert_pos']
        new_field = struct.pack('<I', len(name_bytes)) + name_bytes
        delta = len(new_field)

        # Set the bitmap bit
        bmp_pos = merc_info['bitmap_pos'] + 2  # skip u16 length
        byte_idx = name_prop_idx // 8
        bit_idx = name_prop_idx & 7
        data[bmp_pos + byte_idx] |= (1 << bit_idx)

        # Insert the string data
        data = bytearray(data[:insert_pos]) + new_field + bytearray(data[insert_pos:])

    if delta == 0:
        return data

    # Fix up all offsets that point past the insertion point
    insertion_point = merc_info['name_insert_pos']

    # 1. Fix end_offset
    old_end = struct.unpack_from('<I', data, layout['end_offset_pos'])[0]
    struct.pack_into('<I', data, layout['end_offset_pos'], old_end + delta)

    # 2. Fix object info table offsets
    for info in layout['infos']:
        pos = info['offset_field_pos']
        # Adjust pos if it's after the insertion point (it's in the header, so it's before)
        old_val = struct.unpack_from('<I', data, pos)[0]
        if old_val > insertion_point:
            struct.pack_into('<I', data, pos, old_val + delta)

        # Fix size for the object that CONTAINS the insertion
        if info['offset'] <= insertion_point < info['offset'] + info['size']:
            size_pos = info['size_field_pos']
            old_size = struct.unpack_from('<I', data, size_pos)[0]
            struct.pack_into('<I', data, size_pos, old_size + delta)

    # 3. Fix inline value_offsets in the data section
    # This is the hard part — we need to find all u32 value_offset fields
    # in nested objects that point past the insertion point.
    # For now, scan through ALL object data and fix value_offsets
    # by re-parsing with offset tracking.
    _fix_inline_offsets(data, layout, insertion_point, delta)

    return data


def _fix_inline_offsets(data: bytearray, layout: dict, insertion_point: int, delta: int):
    """Fix all inline value_offset fields in nested objects."""
    # Re-parse the data to find all value_offset positions
    # For each nested object, its metadata includes a value_offset u32
    # We need to adjust any that point past the insertion point
    ser_ver = layout['ser_ver']
    types = layout['types']

    for info in layout['infos']:
        obj_off = struct.unpack_from('<I', data, info['offset_field_pos'])[0]
        type_info = types[info['type_index']]
        try:
            _fix_offsets_in_object_properties(data, obj_off, type_info, layout, insertion_point, delta, is_top_level=True)
        except Exception:
            pass  # Skip objects that fail to parse


def _fix_offsets_in_object_properties(data, off, type_info, layout, insertion_point, delta, is_top_level=False):
    """Recursively fix value_offsets within an object's properties."""
    ser_ver = layout['ser_ver']
    types = layout['types']

    # Skip object header
    bmp_len = struct.unpack_from('<H', data, off)[0]; off += 2
    bmp = data[off:off + bmp_len]; off += bmp_len

    if not is_top_level:
        type_idx = struct.unpack_from('<H', data, off)[0]; off += 2
        if ser_ver >= 0xB:
            off += 1 + 8
        elif ser_ver >= 8:
            off += 4
        else:
            off += 2

        # Fix value_offset
        vo_pos = off
        vo = struct.unpack_from('<I', data, vo_pos)[0]
        if vo > insertion_point:
            struct.pack_into('<I', data, vo_pos, vo + delta)
            vo += delta
        off += 4
        off = vo

        type_info = types[type_idx]

    # Skip u8 unknown + no_tags
    if ser_ver >= 0xA:
        off += 1
    if ser_ver >= 5:
        no_tags = data[off]; off += 1
        if not no_tags and ser_ver >= 6:
            tag_count = struct.unpack_from('<H', data, off)[0]; off += 2
            for _ in range(tag_count):
                off += 2
                tag_len = struct.unpack_from('<I', data, off)[0]; off += 4
                off += tag_len

    # Process properties
    for pi, prop in enumerate(type_info['properties']):
        bit_missing = ((bmp[pi // 8] >> (pi & 7)) & 1) == 0
        if ser_ver >= 9 and (prop['flags'] & ((1 << 7) | (1 << 1))):
            continue
        is_array = prop['prop_type'] in (3, 6, 7, 9, 10)
        if not is_array and bit_missing:
            continue

        pt = prop['prop_type']
        if pt in (0, 1, 2):
            off = _skip_property_value(data, off, prop, layout)
        elif pt == 3:  # SIMPLE_ARRAY
            off = _skip_property_value(data, off, prop, layout)
        elif pt == 4:  # OBJECT
            _fix_offsets_in_object_properties(data, off, None, layout, insertion_point, delta)
            off = _skip_object_adjusted(data, off, layout)
        elif pt == 5:  # OPTIONAL_OBJECT
            flag = data[off]; off += 1
            if flag != 0:
                _fix_offsets_in_object_properties(data, off, None, layout, insertion_point, delta)
                off = _skip_object_adjusted(data, off, layout)
        elif pt in (6, 7):  # OBJECT_ARRAY
            if ser_ver >= 0xF:
                if data[off] == 1:
                    off += 1
                    continue
                off += 1
            count = struct.unpack_from('<I', data, off)[0]; off += 4
            has_named = False
            if ser_ver >= 0xE:
                has_named = data[off] == 1; off += 1
            if ser_ver >= 0xB:
                off += 8
            elif ser_ver >= 8:
                off += 4
            elif ser_ver >= 4:
                off += 2
            if ser_ver >= 0xB:
                unk_count = struct.unpack_from('<i', data, off)[0]; off += 4
                if unk_count > 0:
                    off += unk_count * 8
                    if has_named:
                        off += unk_count * 4
            for _ in range(count):
                _fix_offsets_in_object_properties(data, off, None, layout, insertion_point, delta)
                off = _skip_object_adjusted(data, off, layout)
        elif pt == 10:  # SIZE_PREFIXED_ARRAY
            off = _skip_property_value(data, off, prop, layout)
        else:
            off = _skip_property_value(data, off, prop, layout)


def _skip_object_adjusted(data, off, layout):
    """Skip a nested object (same as _skip_object but reads potentially-fixed offsets)."""
    return _skip_object(data, off, layout)


# ── Clear (remove) a mercenary name ─────────────────────────────────

def clear_mercenary_name(data: bytearray, layout: dict, merc_info: dict) -> bytearray:
    """Remove the _mercenaryName field from a mercenary (inverse of patch).

    Clears the bitmap bit and removes the string bytes. Returns modified data.
    If the name isn't set, returns data unchanged.
    """
    if not merc_info['name_bit_set']:
        return data

    name_prop_idx = merc_info['name_prop_idx']
    pos = merc_info['name_insert_pos']
    old_len = struct.unpack_from('<I', data, pos)[0]
    old_total = 4 + old_len
    delta = -old_total

    # Clear the bitmap bit
    bmp_pos = merc_info['bitmap_pos'] + 2  # skip u16 length
    byte_idx = name_prop_idx // 8
    bit_idx = name_prop_idx & 7
    data[bmp_pos + byte_idx] &= ~(1 << bit_idx)

    # Remove the string data
    data = bytearray(data[:pos]) + bytearray(data[pos + old_total:])

    # Fix up offsets (same logic as patch, delta is negative)
    insertion_point = pos

    old_end = struct.unpack_from('<I', data, layout['end_offset_pos'])[0]
    struct.pack_into('<I', data, layout['end_offset_pos'], old_end + delta)

    for info in layout['infos']:
        fpos = info['offset_field_pos']
        old_val = struct.unpack_from('<I', data, fpos)[0]
        if old_val > insertion_point:
            struct.pack_into('<I', data, fpos, old_val + delta)

        if info['offset'] <= insertion_point < info['offset'] + info['size']:
            size_pos = info['size_field_pos']
            old_size = struct.unpack_from('<I', data, size_pos)[0]
            struct.pack_into('<I', data, size_pos, old_size + delta)

    _fix_inline_offsets(data, layout, insertion_point, delta)

    return data


# ── Display helpers ──────────────────────────────────────────────────

def _merc_tags(m):
    """Build a tag list for a mercenary."""
    ex = m.get('extra', {})
    tags = []
    if ex.get('_equip_count', '?') == 0:
        tags.append('ANIMAL')
    if ex.get('_lastSummoned') == 1:
        tags.append('ACTIVE')
    if ex.get('_isMainMercenary') == 1:
        tags.append('MAIN')
    if ex.get('_isDead') == 1:
        tags.append('DEAD')
    return tags


def _merc_name_display(m):
    return f'"{m["name_current_value"]}"' if m['name_bit_set'] else '<not set>'


def print_merc_list(mercs):
    """Print the full mercenary list."""
    print(f"\n{'='*90}")
    print("MERCENARY LIST")
    print(f"{'='*90}")
    for i, m in enumerate(mercs):
        ex = m.get('extra', {})
        tags = _merc_tags(m)
        tag_str = f"  [{', '.join(tags)}]" if tags else ""
        print(f"  [{i:2d}] MercNo={m['mercenary_no']:<6d}  charKey={ex.get('_characterKey', '?'):<6}  "
              f"name={_merc_name_display(m):<16s}  equip={ex.get('_equip_count', '?'):<3}  "
              f"summoned={ex.get('_lastSummoned', '?')}  "
              f"main={ex.get('_isMainMercenary', '?')}  dead={ex.get('_isDead', '?')}  "
              f"hp={ex.get('_currentHp', '?')}{tag_str}")


# ── Apply + save helper ─────────────────────────────────────────────

def _apply_renames(plaintext, mercs, pairs, hdr, input_path, output_path=None):
    """Apply a list of (merc_no, new_name) renames and save."""
    patched = bytearray(plaintext)
    for no, name in pairs:
        layout = parse_reflection_layout(bytes(patched))
        mercs_now = find_mercenary_bitmap_positions(bytes(patched), layout)
        target = next(t for t in mercs_now if t['mercenary_no'] == no)
        patched = patch_mercenary_name(patched, layout, target, name)
        print(f"  MercNo={no} -> \"{name}\"")
    out = output_path or input_path.with_name(f"{input_path.stem}_renamed{input_path.suffix}")
    encrypted = encrypt_save(bytes(patched), version=hdr['version'])
    out.write_bytes(encrypted)
    print(f"\n  Wrote: {out} ({len(encrypted):,} bytes)")
    return patched


def _apply_clears(plaintext, mercs_to_clear, hdr, input_path, output_path=None, suffix="_cleared"):
    """Apply clears to a list of mercs and save."""
    patched = bytearray(plaintext)
    for m in mercs_to_clear:
        layout = parse_reflection_layout(bytes(patched))
        mercs_now = find_mercenary_bitmap_positions(bytes(patched), layout)
        target = next(t for t in mercs_now if t['mercenary_no'] == m['mercenary_no'])
        if target['name_bit_set']:
            patched = clear_mercenary_name(patched, layout, target)
            print(f"  MercNo={m['mercenary_no']:<6d}  cleared (was \"{m['name_current_value']}\")")
    out = output_path or input_path.with_name(f"{input_path.stem}{suffix}{input_path.suffix}")
    encrypted = encrypt_save(bytes(patched), version=hdr['version'])
    out.write_bytes(encrypted)
    print(f"\n  Wrote: {out} ({len(encrypted):,} bytes)")
    return patched


# ── Interactive mode ─────────────────────────────────────────────────

def _ask_output_path(input_path, default_suffix):
    """Prompt the user for an output path, with a default suggestion."""
    default = input_path.with_name(f"{input_path.stem}{default_suffix}{input_path.suffix}")
    print(f"\n  Default output: {default}")
    print(f"  Press Enter to accept, or type a path (use '!' to overwrite input file)")
    raw = input("  Output: ").strip()
    if raw == '!':
        return input_path
    if raw:
        return Path(raw)
    return default


def run_interactive(plaintext, hdr, mercs, input_path):
    """Interactive menu when no CLI flags are given."""
    import re

    print_merc_list(mercs)

    while True:
        has_labels = any(m['name_bit_set'] and re.match(r'^M_\d+$', m['name_current_value'] or '')
                         for m in mercs)
        has_any_names = any(m['name_bit_set'] for m in mercs)

        print(f"\n{'─'*50}")
        print("ACTIONS:")
        print("  1) Label all        — set every merc to M_<no> for identification")
        print("  2) Rename           — choose names for individual mercenaries")
        if has_labels:
            print("  3) Clean up labels  — remove M_<no> labels, keep intentional names")
        if has_any_names:
            print("  4) Clear all names  — remove ALL custom names")
        print("  q) Quit")
        print(f"{'─'*50}")

        choice = input("\nSelect an action: ").strip().lower()

        if choice == '1':
            print(f"\nLabeling all {len(mercs)} mercenaries...")
            patched = bytearray(plaintext)
            for i, m in enumerate(mercs):
                label = f"M_{m['mercenary_no']}"
                layout = parse_reflection_layout(bytes(patched))
                mercs_now = find_mercenary_bitmap_positions(bytes(patched), layout)
                target = next(t for t in mercs_now if t['mercenary_no'] == m['mercenary_no'])
                patched = patch_mercenary_name(patched, layout, target, label)
                print(f"  [{i:2d}] MercenaryNo={m['mercenary_no']:<6d} -> \"{label}\"")

            output_path = _ask_output_path(input_path, "_all_named")
            encrypted = encrypt_save(bytes(patched), version=hdr['version'])
            output_path.write_bytes(encrypted)
            print(f"\n  Wrote: {output_path} ({len(encrypted):,} bytes)")
            print("\nLoad this save in-game to see which M_xxx appears on which character.")
            break

        elif choice == '2':
            merc_by_no = {m['mercenary_no']: m for m in mercs}
            pairs = []
            print(f"\nEnter MercNo and new name. Type 'done' when finished.")
            print(f"{'─'*50}")
            while True:
                raw = input("  MercNo (or 'done'): ").strip()
                if raw.lower() == 'done':
                    break
                try:
                    no = int(raw)
                except ValueError:
                    print(f"    Invalid number: \"{raw}\"")
                    continue
                if no not in merc_by_no:
                    print(f"    MercNo {no} not found. Available: {sorted(merc_by_no.keys())}")
                    continue
                m = merc_by_no[no]
                tags = _merc_tags(m)
                tag_str = f" [{', '.join(tags)}]" if tags else ""
                print(f"    Current: {_merc_name_display(m)}{tag_str}")
                new_name = input("    New name: ").strip()
                if not new_name:
                    print("    Skipped.")
                    continue
                pairs.append((no, new_name))
                print(f"    OK: MercNo={no} -> \"{new_name}\"")

            if not pairs:
                print("\nNo renames entered.")
                continue

            print(f"\n{'─'*50}")
            print("SUMMARY — will apply these renames:")
            for no, name in pairs:
                print(f"  MercNo={no} -> \"{name}\"")

            confirm = input("\nProceed? [Y/n]: ").strip().lower()
            if confirm and confirm != 'y':
                print("Cancelled.")
                continue

            output_path = _ask_output_path(input_path, "_renamed")
            print()
            _apply_renames(plaintext, mercs, pairs, hdr, input_path, output_path)
            print("\nDone! Copy the output file to your save folder.")
            break

        elif choice == '3' and has_labels:
            pattern = re.compile(r'^M_\d+$')
            labeled = [m for m in mercs if m['name_bit_set'] and pattern.match(m['name_current_value'] or '')]
            kept = [m for m in mercs if m['name_bit_set'] and not pattern.match(m['name_current_value'] or '')]

            print(f"\nWill clear {len(labeled)} auto-labels.")
            if kept:
                print(f"Keeping {len(kept)} intentional names:")
                for m in kept:
                    print(f"    MercNo={m['mercenary_no']:<6d}  \"{m['name_current_value']}\"")

            confirm = input("\nProceed? [Y/n]: ").strip().lower()
            if confirm and confirm != 'y':
                print("Cancelled.")
                continue

            output_path = _ask_output_path(input_path, "_cleaned")
            print()
            _apply_clears(plaintext, labeled, hdr, input_path, output_path, suffix="_cleaned")
            break

        elif choice == '4' and has_any_names:
            named = [m for m in mercs if m['name_bit_set']]
            print(f"\nWill clear ALL {len(named)} custom names.")
            confirm = input("Proceed? [Y/n]: ").strip().lower()
            if confirm and confirm != 'y':
                print("Cancelled.")
                continue

            output_path = _ask_output_path(input_path, "_cleared")
            print()
            _apply_clears(plaintext, named, hdr, input_path, output_path)
            break

        elif choice == 'q':
            print("Bye!")
            break
        else:
            print("Invalid choice.")


# ── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Crimson Desert — Pet & Companion Rename Tool",
        epilog="Run with no action flags for interactive mode.",
    )
    parser.add_argument("input", help="Path to .save file")
    parser.add_argument("--list", action="store_true", help="List all mercenaries and exit")
    parser.add_argument("--rename", nargs=2, metavar=("MERC_NO", "NAME"),
                        help="Rename a single mercenary by MercenaryNo")
    parser.add_argument("--rename-multi", nargs='+', metavar="MERC_NO=NAME",
                        help="Rename multiple mercenaries, e.g. 1027=Kraken 615=Grendel")
    parser.add_argument("--rename-all", action="store_true",
                        help="Rename ALL mercenaries with traceable names (M_<no>)")
    parser.add_argument("--clear", nargs='+', metavar="MERC_NO", type=int,
                        help="Clear (remove) custom names from specific mercenaries")
    parser.add_argument("--clear-unnamed", action="store_true",
                        help="Clear names matching M_<number> pattern (from --rename-all labeling)")
    parser.add_argument("--clear-all", action="store_true",
                        help="Clear ALL custom mercenary names (restore to game defaults)")
    parser.add_argument("-o", "--output", help="Output path for patched .save file")
    args = parser.parse_args()

    input_path = Path(args.input)
    file_data = input_path.read_bytes()

    print("Decrypting save file...")
    hdr, plaintext = decrypt_save(file_data)
    print(f"  Decrypted: {len(plaintext):,} bytes")

    print("Parsing reflection layout...")
    layout = parse_reflection_layout(plaintext)
    print(f"  Types: {layout['type_count']}, Objects: {layout['obj_count']}")

    print("Locating mercenary data...")
    mercs = find_mercenary_bitmap_positions(plaintext, layout)
    print(f"  Found {len(mercs)} mercenaries")

    has_action = (args.rename or args.rename_multi or args.rename_all
                  or args.clear or args.clear_all or args.clear_unnamed or args.list)

    # ── Interactive mode (no flags) ──
    if not has_action:
        run_interactive(plaintext, hdr, mercs, input_path)
        return

    # ── --list ──
    if args.list:
        print_merc_list(mercs)
        return

    # ── Determine output path ──
    output_path = Path(args.output) if args.output else None

    # ── --clear-unnamed ──
    if args.clear_unnamed:
        import re
        pattern = re.compile(r'^M_\d+$')
        labeled = [m for m in mercs if m['name_bit_set'] and pattern.match(m['name_current_value'] or '')]
        if not labeled:
            print("\nNo M_<number> labels found. Nothing to clear.")
            return
        kept = [m for m in mercs if m['name_bit_set'] and not pattern.match(m['name_current_value'] or '')]
        print(f"\nClearing {len(labeled)} auto-labels (keeping {len(kept)} intentional names)...")
        _apply_clears(plaintext, labeled, hdr, input_path, output_path, suffix="_cleaned")
        if kept:
            print(f"  Kept:")
            for m in kept:
                print(f"    MercNo={m['mercenary_no']:<6d}  \"{m['name_current_value']}\"")

    # ── --clear-all ──
    elif args.clear_all:
        named = [m for m in mercs if m['name_bit_set']]
        if not named:
            print("\nNo mercenaries have custom names. Nothing to clear.")
            return
        print(f"\nClearing names from {len(named)} mercenaries...")
        _apply_clears(plaintext, named, hdr, input_path, output_path)

    # ── --clear <ids> ──
    elif args.clear:
        available = {m['mercenary_no'] for m in mercs}
        for no in args.clear:
            if no not in available:
                print(f"Error: MercenaryNo {no} not found. Available: {sorted(available)}", file=sys.stderr)
                sys.exit(1)
        to_clear = [m for m in mercs if m['mercenary_no'] in args.clear]
        _apply_clears(plaintext, to_clear, hdr, input_path, output_path)

    # ── --rename-all ──
    elif args.rename_all:
        pairs = [(m['mercenary_no'], f"M_{m['mercenary_no']}") for m in mercs]
        print(f"\nLabeling all {len(mercs)} mercenaries...")
        out = output_path or input_path.with_name(f"{input_path.stem}_all_named{input_path.suffix}")
        _apply_renames(plaintext, mercs, pairs, hdr, input_path, out)
        print("\nLoad this save in-game to see which M_xxx appears on which character.")

    # ── --rename-multi ──
    elif args.rename_multi:
        pairs = []
        for item in args.rename_multi:
            if '=' not in item:
                print(f"Error: expected MERC_NO=NAME, got \"{item}\"", file=sys.stderr)
                sys.exit(1)
            no_str, name = item.split('=', 1)
            pairs.append((int(no_str), name))

        available = {m['mercenary_no'] for m in mercs}
        for no, name in pairs:
            if no not in available:
                print(f"Error: MercenaryNo {no} not found. Available: {sorted(available)}", file=sys.stderr)
                sys.exit(1)

        print(f"\nRenaming {len(pairs)} mercenaries...")
        _apply_renames(plaintext, mercs, pairs, hdr, input_path, output_path)
        print("\nDone! Copy this file to your save folder and test in-game.")

    # ── --rename ──
    elif args.rename:
        target_no = int(args.rename[0])
        new_name = args.rename[1]

        target = next((m for m in mercs if m['mercenary_no'] == target_no), None)
        if target is None:
            print(f"\nError: MercenaryNo {target_no} not found.", file=sys.stderr)
            print(f"Available: {[m['mercenary_no'] for m in mercs]}")
            sys.exit(1)

        print(f"\nRenaming MercenaryNo {target_no} to \"{new_name}\"...")
        _apply_renames(plaintext, mercs, [(target_no, new_name)], hdr, input_path, output_path)
        print("\nDone! Copy this file to your save folder and test in-game.")


if __name__ == "__main__":
    main()
