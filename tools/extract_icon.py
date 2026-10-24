"""Extract the RT_GROUP_ICON / RT_ICON resources from a PE file into a .ico.

Usage:  python extract_icon.py <src.exe> <out.ico> [group_index]

Builds a multi-image .ico that PyInstaller (and Windows) can use directly.
"""
from __future__ import annotations

import struct
import sys

import pefile

RT_ICON = 3
RT_GROUP_ICON = 14

# GRPICONDIRENTRY layout (14 bytes):
#  width, height, colorcount, reserved, planes(H), bitcount(H), bytesinres(I), id(H)


def _resource_entries(pe: pefile.PE, rtype: int) -> list[tuple[int, int, bytes]]:
    """Return list of (resource_id, size, data) for a given resource type."""
    out: list[tuple[int, int, bytes]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return out
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != rtype and getattr(entry, "struct", None) is None:
            continue
        if entry.id != rtype:
            continue
        if not hasattr(entry, "directory"):
            continue
        for res in entry.directory.entries:
            rid = res.id if res.id is not None else res.name
            data_entry = res.directory.entries[0]
            off = data_entry.data.struct.OffsetToData
            size = data_entry.data.struct.Size
            out.append((rid, size, pe.get_data(off, size)))
    return out


def build_ico(pe: pefile.PE, group_index: int = 0) -> bytes:
    groups = _resource_entries(pe, RT_GROUP_ICON)
    icons = {rid: data for rid, _size, data in _resource_entries(pe, RT_ICON)}
    if not groups:
        raise SystemExit("No RT_GROUP_ICON resources found")

    # pick requested group (by order), fall back to first
    idx = min(group_index, len(groups) - 1)
    gid, gsize, gdata = groups[idx]

    # parse GRPICONDIR header: reserved(2) type(2) count(2)
    reserved, itype, count = struct.unpack_from("<HHH", gdata, 0)
    entries = []
    off = 6
    for _ in range(count):
        (w, h, ccount, cres, planes, bitcount, bytesinres, icon_id) = struct.unpack_from(
            "<BBBBHHIH", gdata, off
        )
        off += 14
        img = icons.get(icon_id)
        if img is None:
            continue
        entries.append((w, h, ccount, cres, planes, bitcount, bytesinres, icon_id, img))

    if not entries:
        raise SystemExit("Icon group referenced no RT_ICON images")

    # Build ICONDIR + ICONDIRENTRY[] + image blobs
    header = struct.pack("<HHH", 0, 1, len(entries))
    dir_entries = b""
    blobs = b""
    data_offset = 6 + 16 * len(entries)
    for (w, h, ccount, cres, planes, bitcount, bytesinres, icon_id, img) in entries:
        # 0 means 256 in the ICO format
        b_w = 0 if w >= 256 else w
        b_h = 0 if h >= 256 else h
        dir_entries += struct.pack(
            "<BBBBHHII", b_w, b_h, ccount, cres, planes, bitcount,
            len(img), data_offset + len(blobs),
        )
        blobs += img
    return header + dir_entries + blobs


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(2)
    src, out = sys.argv[1], sys.argv[2]
    group_index = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    pe = pefile.PE(src, fast_load=False)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
        ]
    )
    groups = _resource_entries(pe, RT_GROUP_ICON)
    print(f"Found {len(groups)} ICON_GROUP(s) in {src}")
    for i, (gid, gsize, _d) in enumerate(groups):
        print(f"  group[{i}] id={gid} size={gsize}")
    ico = build_ico(pe, group_index)
    with open(out, "wb") as fh:
        fh.write(ico)
    print(f"Wrote {out} ({len(ico)} bytes)")


if __name__ == "__main__":
    main()