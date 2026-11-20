"""Builds a minimal, hand-crafted 32-bit PE with a crafted import table
(process-injection API trio) and embedded decoy strings, so the pipeline
can be exercised end-to-end without a C compiler or any live malware.
Output is inert - it has no entry point logic beyond returning immediately.
"""
import struct
import os

IMAGE_BASE = 0x00400000
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200


def pad(data: bytes, align: int) -> bytes:
    rem = len(data) % align
    if rem:
        data += b"\x00" * (align - rem)
    return data


def build_import_section(dll_names_and_funcs, rva_base):
    """Lay out IMAGE_IMPORT_DESCRIPTOR array + ILT + hint/name table + IAT in one blob."""
    num_dlls = len(dll_names_and_funcs)
    descriptor_size = 20
    descriptors_bytes = b""

    # Reserve space: descriptors, then per-dll (ILT + IAT equal arrays), then names/hints.
    offset = descriptor_size * (num_dlls + 1)
    layout = []
    for dll, funcs in dll_names_and_funcs:
        ilt_offset = offset
        offset += 4 * (len(funcs) + 1)
        iat_offset = offset
        offset += 4 * (len(funcs) + 1)
        layout.append({"dll": dll, "funcs": funcs, "ilt": ilt_offset, "iat": iat_offset})

    name_offsets = {}
    for entry in layout:
        name_offsets[entry["dll"]] = offset
        offset += len(entry["dll"]) + 1
        offset = (offset + 1) & ~1  # word align
        entry["hint_name_offsets"] = []
        for f in entry["funcs"]:
            entry["hint_name_offsets"].append(offset)
            offset += 2 + len(f) + 1  # hint(2) + name + NUL
            offset = (offset + 1) & ~1

    total_size = offset
    blob = bytearray(total_size)

    pos = 0
    for entry in layout:
        struct.pack_into(
            "<IIIII", blob, pos,
            rva_base + entry["ilt"],  # OriginalFirstThunk
            0,                         # TimeDateStamp
            0,                         # ForwarderChain
            rva_base + name_offsets[entry["dll"]],  # Name RVA
            rva_base + entry["iat"],   # FirstThunk
        )
        pos += descriptor_size
    # null terminator descriptor already zeroed

    for entry in layout:
        for i, hn_off in enumerate(entry["hint_name_offsets"]):
            thunk_val = rva_base + hn_off
            struct.pack_into("<I", blob, entry["ilt"] + i * 4, thunk_val)
            struct.pack_into("<I", blob, entry["iat"] + i * 4, thunk_val)
        # trailing zero entries already zeroed by bytearray init

    for entry in layout:
        name_pos = name_offsets[entry["dll"]]
        blob[name_pos:name_pos + len(entry["dll"])] = entry["dll"].encode("ascii")
        for f, hn_off in zip(entry["funcs"], entry["hint_name_offsets"]):
            struct.pack_into("<H", blob, hn_off, 0)  # hint
            name_start = hn_off + 2
            blob[name_start:name_start + len(f)] = f.encode("ascii")

    return bytes(blob)


def build_pe(decoy_strings_ascii, decoy_strings_wide, out_path):
    dos_stub = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    dos_stub = pad(dos_stub, 0x80)

    pe_sig = b"PE\x00\x00"
    machine = 0x014c  # i386
    num_sections = 2
    file_header = struct.pack(
        "<HHIIIHH", machine, num_sections, 0, 0, 0, 0xE0, 0x0102
    )

    section_header_size = 40
    opt_header_size = 0xE0
    headers_size = len(dos_stub) + len(pe_sig) + len(file_header) + opt_header_size + \
        section_header_size * num_sections
    headers_size = pad(b"\x00" * headers_size, FILE_ALIGN)
    headers_total = len(headers_size)

    rdata_rva = SECTION_ALIGN
    strings_blob = (b"\x00".join(s.encode("ascii") for s in decoy_strings_ascii) + b"\x00")
    wide_blob = b"".join((s + "\x00").encode("utf-16-le") for s in decoy_strings_wide)
    data_section_raw = pad(strings_blob + wide_blob, FILE_ALIGN)

    text_rva = rdata_rva + ((len(data_section_raw) + SECTION_ALIGN - 1) // SECTION_ALIGN) * SECTION_ALIGN
    # .text: tiny stub that just returns (0xC3 = RET), referencing nothing - inert.
    code = b"\xC3" + b"\x90" * 15
    text_section_raw = pad(code, FILE_ALIGN)

    import_rva = text_rva + ((len(text_section_raw) + SECTION_ALIGN - 1) // SECTION_ALIGN) * SECTION_ALIGN
    import_blob_raw = build_import_section(
        [("KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "LoadLibraryA"])],
        import_rva,
    )
    import_section_raw = pad(import_blob_raw, FILE_ALIGN)

    # sections: .rdata (strings), .text (code), .idata (imports) - merge idata into rdata's own section for simplicity
    sections = [
        {"name": b".rdata\x00\x00", "rva": rdata_rva, "vsize": len(data_section_raw), "raw": data_section_raw, "characteristics": 0x40000040},
        {"name": b".text\x00\x00\x00", "rva": text_rva, "vsize": len(text_section_raw), "raw": text_section_raw, "characteristics": 0x60000020},
        {"name": b".idata\x00\x00", "rva": import_rva, "vsize": len(import_section_raw), "raw": import_section_raw, "characteristics": 0xC0000040},
    ]
    num_sections = len(sections)

    file_header = struct.pack("<HHIIIHH", machine, num_sections, 0, 0, 0, opt_header_size, 0x0102)

    image_size = import_rva + ((len(import_section_raw) + SECTION_ALIGN - 1) // SECTION_ALIGN) * SECTION_ALIGN

    opt_header = bytearray(opt_header_size)
    struct.pack_into("<H", opt_header, 0, 0x010B)  # magic PE32
    struct.pack_into("<I", opt_header, 16, text_rva)  # AddressOfEntryPoint -> .text
    struct.pack_into("<I", opt_header, 28, IMAGE_BASE)
    struct.pack_into("<I", opt_header, 32, SECTION_ALIGN)
    struct.pack_into("<I", opt_header, 36, FILE_ALIGN)
    struct.pack_into("<H", opt_header, 68, 4)  # Subsystem = console
    struct.pack_into("<I", opt_header, 56, image_size)
    struct.pack_into("<I", opt_header, 60, headers_total)
    struct.pack_into("<I", opt_header, 92, 16)  # NumberOfRvaAndSizes
    # Import data directory (index 1): entry 8 + 1*8
    struct.pack_into("<II", opt_header, 96 + 8, import_rva, len(import_blob_raw))

    headers = bytearray(headers_total)
    pos = 0
    headers[pos:pos + len(dos_stub)] = dos_stub
    pos += len(dos_stub)
    headers[pos:pos + 4] = pe_sig
    pos += 4
    headers[pos:pos + len(file_header)] = file_header
    pos += len(file_header)
    headers[pos:pos + len(opt_header)] = bytes(opt_header)
    pos += len(opt_header)

    raw_ptr = headers_total
    for s in sections:
        s["raw_ptr"] = raw_ptr
        sh = struct.pack(
            "<8sIIIIIIHHI",
            s["name"], s["vsize"], s["rva"], len(s["raw"]), raw_ptr,
            0, 0, 0, 0, s["characteristics"],
        )
        headers[pos:pos + len(sh)] = sh
        pos += len(sh)
        raw_ptr += len(s["raw"])

    out = bytes(headers) + b"".join(s["raw"] for s in sections)
    with open(out_path, "wb") as f:
        f.write(out)
    return out_path


if __name__ == "__main__":
    here = os.path.dirname(__file__)
    out = os.path.join(here, "..", "samples", "synthetic_suspicious.exe")
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    build_pe(
        decoy_strings_ascii=[
            "http://evil-example-c2.test/beacon",
            "185.199.108.153",
            "update-portal-gov-az.test",
            "faktura odenis tesdiqi",
            "nazirlik elaqe formu",
            eicar,
        ],
        decoy_strings_wide=["wide-string-indicator-update-portal-gov-az.test"],
        out_path=out,
    )
    print("wrote", out)
