"""
Minimal PDB symbol extractor — no external dependencies.
Parses PDB 7.0 (MSF) format to extract public symbol RVAs.

Usage:
    python pdb_extract.py <pdb_file> [function_name ...]
"""

import struct
import sys
import os


def read_u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def read_u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


class MSF:
    """Minimal Multi-Stream File (MSF/PDB 7.0) parser."""

    MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"

    def __init__(self, data):
        self.data = data
        if data[:len(self.MAGIC)] != self.MAGIC:
            raise ValueError("Not a valid PDB 7.0 file")

        self.page_size = read_u32(data, 32)
        # free_page_map = read_u32(data, 36)
        self.num_pages = read_u32(data, 40)
        self.directory_size = read_u32(data, 44)
        # unknown = read_u32(data, 48)
        self.directory_map_page = read_u32(data, 52)

        self._read_directory()

    def _get_page(self, page_num):
        offset = page_num * self.page_size
        return self.data[offset:offset + self.page_size]

    def _read_directory(self):
        # Read directory map (page numbers of directory pages)
        dir_map_data = self._get_page(self.directory_map_page)
        num_dir_pages = (self.directory_size + self.page_size - 1) // self.page_size

        dir_page_nums = []
        for i in range(num_dir_pages):
            dir_page_nums.append(read_u32(dir_map_data, i * 4))

        # Read directory
        dir_data = bytearray()
        for pn in dir_page_nums:
            dir_data.extend(self._get_page(pn))

        # Parse directory: number of streams, then stream sizes, then page numbers
        offset = 0
        num_streams = read_u32(dir_data, offset)
        offset += 4

        stream_sizes = []
        for i in range(num_streams):
            size = read_u32(dir_data, offset)
            offset += 4
            stream_sizes.append(size)

        self.streams = []
        for size in stream_sizes:
            if size == 0 or size == 0xFFFFFFFF:
                self.streams.append(b"")
                continue

            num_pages = (size + self.page_size - 1) // self.page_size
            pages = []
            for _ in range(num_pages):
                pages.append(read_u32(dir_data, offset))
                offset += 4

            stream_data = bytearray()
            for pn in pages:
                stream_data.extend(self._get_page(pn))

            self.streams.append(bytes(stream_data[:size]))

    def get_stream(self, index):
        if index < len(self.streams):
            return self.streams[index]
        return b""


def parse_public_symbols(msf):
    """
    Extract public symbols from PDB.

    Stream layout (PDB 7.0):
    - Stream 0: Old MSF directory (ignored)
    - Stream 1: PDB header
    - Stream 2: TPI (Type info)
    - Stream 3: DBI (Debug info)
    - Stream 4: IPI (Id info)

    DBI header tells us which stream contains the public symbol records.
    """

    # DBI stream (stream 3)
    dbi = msf.get_stream(3)
    if len(dbi) < 64:
        print("[!] DBI stream too small")
        return {}

    # DBI Header layout:
    # +0:  VersionSignature (i32)
    # +4:  VersionHeader (u32)
    # +8:  Age (u32)
    # +12: GlobalStreamIndex (u16)  <-- global symbol hash stream
    # +14: BuildNumber (u16)
    # +16: PublicStreamIndex (u16)  <-- public symbol stream
    # +18: PdbDllVersion (u16)
    # +20: SymRecordStream (u16)   <-- symbol record stream
    # +22: PdbDllRbld (u16)
    # +24: ModInfoSize (u32)
    # +28: SectionContributionSize (u32)
    # +32: SectionMapSize (u32)
    # +36: SourceInfoSize (u32)
    # +40: TypeServerMapSize (u32)
    # +44: MFCTypeServerIndex (u32)
    # +48: OptionalDbgHeaderSize (u32)
    # +52: ECSubstreamSize (u32)
    # +56: Flags (u16)
    # +58: Machine (u16)
    # +60: Padding (u32)

    global_stream_idx = read_u16(dbi, 12)
    public_stream_idx = read_u16(dbi, 16)
    sym_record_stream_idx = read_u16(dbi, 20)

    print(f"    DBI: GlobalStream={global_stream_idx}, PublicStream={public_stream_idx}, SymRecordStream={sym_record_stream_idx}")

    # Section headers — needed to convert section:offset to RVA
    # They're in the optional debug header area
    mod_info_size = read_u32(dbi, 24)
    sec_contrib_size = read_u32(dbi, 28)
    sec_map_size = read_u32(dbi, 32)
    source_info_size = read_u32(dbi, 36)
    type_server_size = read_u32(dbi, 40)
    mfc_idx = read_u32(dbi, 44)
    opt_dbg_size = read_u32(dbi, 48)
    ec_size = read_u32(dbi, 52)

    # Optional debug header starts after fixed header (64 bytes) + all sub-streams
    opt_dbg_offset = 64 + mod_info_size + sec_contrib_size + sec_map_size + source_info_size + type_server_size + mfc_idx + ec_size
    # Wait, mfc_idx is MFCTypeServerIndex not a size... let me re-read

    # Actually the sub-streams in order after the 64-byte header:
    # ModInfo, SectionContribution, SectionMap, SourceInfo, TypeServerMap, ECSubstream, OptionalDbgHeader
    opt_dbg_offset = 64 + mod_info_size + sec_contrib_size + sec_map_size + source_info_size + type_server_size + ec_size

    # The optional debug header contains pairs of (u16 stream_index)
    # Entry 5 (index 5) = section header stream
    section_hdr_stream_idx = 0xFFFF
    if opt_dbg_offset + 12 <= len(dbi):
        section_hdr_stream_idx = read_u16(dbi, opt_dbg_offset + 5 * 2)
        print(f"    SectionHeaderStream={section_hdr_stream_idx}")

    # Parse section headers
    sections = []
    if section_hdr_stream_idx != 0xFFFF:
        sec_data = msf.get_stream(section_hdr_stream_idx)
        # IMAGE_SECTION_HEADER = 40 bytes
        num_sec = len(sec_data) // 40
        for i in range(num_sec):
            off = i * 40
            name = sec_data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = read_u32(sec_data, off + 8)
            va = read_u32(sec_data, off + 12)
            sections.append((name, va, vsize))
            # print(f"      Section {i+1}: {name} VA={va:#x} Size={vsize:#x}")

    # Read symbol record stream
    sym_data = msf.get_stream(sym_record_stream_idx)
    if not sym_data:
        print("[!] Symbol record stream is empty")
        return {}

    symbols = {}
    offset = 0
    count = 0

    while offset + 4 <= len(sym_data):
        rec_len = read_u16(sym_data, offset)
        rec_type = read_u16(sym_data, offset + 2)

        if rec_len < 2:
            break

        # S_PUB32 = 0x110E — public symbol with address
        if rec_type == 0x110E and offset + 14 <= len(sym_data):
            flags = read_u32(sym_data, offset + 4)
            sym_offset = read_u32(sym_data, offset + 8)
            sym_section = read_u16(sym_data, offset + 12)

            # Name is null-terminated string after the fixed fields
            name_start = offset + 14
            name_end = sym_data.find(b'\x00', name_start, offset + 2 + rec_len)
            if name_end == -1:
                name_end = offset + 2 + rec_len

            name = sym_data[name_start:name_end].decode('ascii', errors='replace')

            # Convert section:offset to RVA
            rva = sym_offset
            if sym_section > 0 and sym_section <= len(sections):
                sec_va = sections[sym_section - 1][1]
                rva = sec_va + sym_offset

            symbols[name] = rva
            count += 1

        offset += 2 + rec_len
        # Align to 4 bytes
        # offset = (offset + 3) & ~3  # Some PDBs need this, some don't

    print(f"    Found {count} public symbols")
    return symbols


def extract_bytes_at_rva(filepath, rva, count):
    """Read bytes at RVA from a PE file."""
    with open(filepath, "rb") as f:
        data = f.read()

    e_lfanew = read_u32(data, 0x3C)
    coff_offset = e_lfanew + 4
    num_sections = read_u16(data, coff_offset + 2)
    opt_header_size = read_u16(data, coff_offset + 16)
    sections_offset = coff_offset + 20 + opt_header_size

    for i in range(num_sections):
        sec_offset = sections_offset + i * 40
        sec_va = read_u32(data, sec_offset + 12)
        sec_vsize = read_u32(data, sec_offset + 8)
        sec_raw = read_u32(data, sec_offset + 20)

        if sec_va <= rva < sec_va + sec_vsize:
            file_offset = sec_raw + (rva - sec_va)
            return data[file_offset:file_offset + count]

    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pdb_file> [pe_file] [function_name ...]")
        print(f"       {sys.argv[0]} auto")
        sys.exit(1)

    if sys.argv[1] == "auto":
        # Auto mode: use previously dumped PDB + winload.efi from System32
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dump_dir = os.path.join(script_dir, "_dump_temp")
        pdb_file = os.path.join(dump_dir, "winload_prod.pdb")
        pe_file = os.path.join(dump_dir, "winload.efi")

        if not os.path.exists(pe_file):
            # Copy from System32
            src = os.path.join(os.environ["SystemRoot"], "System32", "winload.efi")
            if os.path.exists(src):
                import shutil
                shutil.copy2(src, pe_file)

        target_funcs = [
            "BlImgAllocateImageBuffer",
            "OslFwpKernelSetupPhase1",
            "OslExecuteTransition",
            "BlpArchSwitchContext",
            "ImgArchStartBootApplication",
        ]
    else:
        pdb_file = sys.argv[1]
        pe_file = sys.argv[2] if len(sys.argv) > 2 else None
        target_funcs = sys.argv[3:] if len(sys.argv) > 3 else []

    print(f"[*] PDB file: {pdb_file}")
    if not os.path.exists(pdb_file):
        print(f"[!] PDB file not found!")
        sys.exit(1)

    with open(pdb_file, "rb") as f:
        pdb_data = f.read()

    print(f"[*] PDB size: {len(pdb_data)} bytes")
    print(f"[*] Parsing MSF container...")

    msf = MSF(pdb_data)
    print(f"[*] Page size: {msf.page_size}, Streams: {len(msf.streams)}")

    print(f"[*] Parsing public symbols...")
    symbols = parse_public_symbols(msf)

    if target_funcs:
        print(f"\n[*] Searching for target functions...")
        for func in target_funcs:
            # Try exact match first, then partial
            if func in symbols:
                rva = symbols[func]
                print(f"[+] {func}: RVA = {rva:#X}")

                if pe_file and os.path.exists(pe_file):
                    sig_bytes = extract_bytes_at_rva(pe_file, rva, 24)
                    if sig_bytes:
                        hex_str = " ".join(f"{b:02X}" for b in sig_bytes)
                        rust_arr = ", ".join(f"0x{b:02X}" for b in sig_bytes)
                        print(f"    Bytes: {hex_str}")
                        print(f"    Rust:  &[{rust_arr}],")
            else:
                # Partial match
                matches = [(k, v) for k, v in symbols.items() if func in k]
                if matches:
                    print(f"[~] {func}: {len(matches)} partial matches:")
                    for name, rva in matches[:5]:
                        print(f"    {name}: RVA = {rva:#X}")

                        if pe_file and os.path.exists(pe_file):
                            sig_bytes = extract_bytes_at_rva(pe_file, rva, 24)
                            if sig_bytes:
                                hex_str = " ".join(f"{b:02X}" for b in sig_bytes)
                                rust_arr = ", ".join(f"0x{b:02X}" for b in sig_bytes)
                                print(f"        Bytes: {hex_str}")
                                print(f"        Rust:  &[{rust_arr}],")
                    if len(matches) > 5:
                        print(f"    ... and {len(matches)-5} more")
                else:
                    print(f"[-] {func}: NOT FOUND")
    else:
        # List all symbols
        print(f"\nAll symbols ({len(symbols)}):")
        for name, rva in sorted(symbols.items(), key=lambda x: x[1]):
            print(f"  {rva:#010X}  {name}")


if __name__ == "__main__":
    main()
