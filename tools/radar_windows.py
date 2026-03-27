#!/usr/bin/env python3
"""
Arc Raiders Radar v3.1 — Windows + Physical Memory Reads

Communication via shared memory (named section) avec CommDriver v3.
Lectures mémoire via CR3 page table walking (bypass EAC).

Usage:
  1. Boot via EFI loader (clé USB) OU kdmapper.exe CommDriver.sys
  2. Lancer Arc Raiders
  3. python radar_windows.py
  4. Ouvrir http://localhost:8888
"""

import ctypes
import ctypes.wintypes as wt
import struct
import time
import sys
import os
import json
import math
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

# === Windows API ===
kernel32 = ctypes.windll.kernel32

# Fix return types for 64-bit handles
kernel32.OpenFileMappingW.restype = ctypes.c_void_p
kernel32.OpenFileMappingW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
kernel32.MapViewOfFile.restype = ctypes.c_void_p
kernel32.MapViewOfFile.argtypes = [ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_size_t]
kernel32.UnmapViewOfFile.restype = wt.BOOL
kernel32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p

# Shared memory commands (must match comm.h)
CMD_IDLE          = 0
CMD_FIND_PROCESS  = 1
CMD_READ_MEMORY   = 2
CMD_WRITE_MEMORY  = 3
CMD_GET_PEB       = 4
CMD_PING          = 0xFF

DATA_BUF_SIZE     = 0x10000  # 64KB


class COMM_SHARED(ctypes.Structure):
    """Mirror of the kernel COMM_SHARED struct (pack=1)"""
    _pack_ = 1
    _fields_ = [
        ("ready",        ctypes.c_int32),         # 0
        ("command",      ctypes.c_int32),         # 4
        ("status",       ctypes.c_int32),         # 8
        ("process_name", ctypes.c_char * 260),    # 12
        ("pid",          ctypes.c_uint64),        # 272
        ("cr3",          ctypes.c_uint64),        # 280
        ("address",      ctypes.c_uint64),        # 288
        ("size",         ctypes.c_uint64),        # 296
        ("peb_address",  ctypes.c_uint64),        # 304
        ("image_base",   ctypes.c_uint64),        # 312
        ("data",         ctypes.c_ubyte * DATA_BUF_SIZE),  # 320
    ]


class DriverComm:
    """Communication avec CommDriver v2 via shared memory"""

    def __init__(self):
        self.handle = None
        self.view = None
        self.shared = None
        self.pid = 0
        self.cr3 = 0
        self.base = 0  # Module base for range checks

    def connect(self):
        """Ouvre la section shared memory créée par le driver"""
        FILE_MAP_ALL_ACCESS = 0xF001F

        self.handle = kernel32.OpenFileMappingW(
            FILE_MAP_ALL_ACCESS, False, "Global\\ArcComm"
        )
        if not self.handle:
            err = kernel32.GetLastError()
            raise RuntimeError(
                f"Shared memory 'Global\\ArcComm' introuvable (erreur {err}). "
                "Vérifie que CommDriver.sys est chargé (EFI loader ou kdmapper)."
            )

        self.view = kernel32.MapViewOfFile(
            self.handle, FILE_MAP_ALL_ACCESS, 0, 0,
            ctypes.sizeof(COMM_SHARED)
        )
        if not self.view:
            raise RuntimeError(
                f"MapViewOfFile échoué (erreur {kernel32.GetLastError()})"
            )

        self.shared = COMM_SHARED.from_address(self.view)

        # Vérifier que le driver est prêt
        if self.shared.ready != 1:
            raise RuntimeError("Driver pas prêt (ready != 1)")

        # Ping test
        self.shared.command = CMD_PING
        if not self._wait_completion(500):
            raise RuntimeError("Driver ne répond pas au ping")

        print("[+] Connecté au driver (shared memory)")

    def close(self):
        if self.view:
            kernel32.UnmapViewOfFile(self.view)
        if self.handle:
            kernel32.CloseHandle(self.handle)

    def _wait_completion(self, timeout_ms=2000):
        """Attend que le driver traite la commande (command revient à IDLE)"""
        deadline = time.perf_counter() + timeout_ms / 1000.0
        while time.perf_counter() < deadline:
            if self.shared.command == CMD_IDLE:
                return True
            time.sleep(0.0001)  # 100us
        return False

    def find_process(self, name="PioneerGame.exe"):
        """Trouve le process du jeu"""
        self.shared.process_name = name.encode()[:259]
        self.shared.command = CMD_FIND_PROCESS

        if not self._wait_completion():
            raise RuntimeError(f"Timeout find_process('{name}')")

        if self.shared.status != 0:
            raise RuntimeError(
                f"Process '{name}' non trouvé (0x{self.shared.status & 0xFFFFFFFF:08x})"
            )

        self.pid = self.shared.pid
        self.cr3 = self.shared.cr3
        print(f"[+] {name} PID={self.pid} CR3=0x{self.cr3:x}")
        return self.pid, self.cr3

    def get_peb_and_base(self):
        """Demande au driver de lire le PEB et ImageBase du process cible"""
        self.shared.pid = self.pid
        self.shared.cr3 = self.cr3
        self.shared.command = CMD_GET_PEB

        if not self._wait_completion():
            return None, None

        if self.shared.status != 0:
            return None, None

        return self.shared.peb_address, self.shared.image_base

    def read(self, address, size, debug=False):
        """Lit `size` bytes à `address` dans le process cible (via CR3 physique)"""
        if size > DATA_BUF_SIZE:
            result = b''
            while size > 0:
                chunk = min(size, DATA_BUF_SIZE)
                result += self.read(address, chunk)
                address += chunk
                size -= chunk
            return result

        self.shared.cr3 = self.cr3
        self.shared.address = address
        self.shared.size = size
        self.shared.command = CMD_READ_MEMORY

        if not self._wait_completion():
            if debug:
                print(f"    [DBG] read 0x{address:x} timeout")
            return b'\x00' * size

        if self.shared.status != 0:
            if debug:
                print(f"    [DBG] read 0x{address:x} FAILED status=0x{self.shared.status & 0xFFFFFFFF:08x}")
            return b'\x00' * size

        return bytes(self.shared.data[:size])

    def write(self, address, data):
        """Écrit `data` à `address` dans le process cible (via CR3 physique)"""
        size = len(data)
        if size > DATA_BUF_SIZE:
            return False

        self.shared.cr3 = self.cr3
        self.shared.address = address
        self.shared.size = size
        ctypes.memmove(ctypes.addressof(self.shared) +
                       COMM_SHARED.data.offset, data, size)
        self.shared.command = CMD_WRITE_MEMORY

        if not self._wait_completion():
            return False

        return self.shared.status == 0

    def read_u64(self, addr):
        return struct.unpack('<Q', self.read(addr, 8))[0]

    def read_u32(self, addr):
        return struct.unpack('<I', self.read(addr, 4))[0]

    def read_i32(self, addr):
        return struct.unpack('<i', self.read(addr, 4))[0]

    def read_float(self, addr):
        return struct.unpack('<f', self.read(addr, 4))[0]

    def read_vec3(self, addr):
        return struct.unpack('<fff', self.read(addr, 12))

    def read_vec3d(self, addr):
        """Read FVector as 3 doubles (UE5 Large World Coordinates)"""
        return struct.unpack('<ddd', self.read(addr, 24))

    def read_fstring(self, addr, max_len=64):
        data_ptr = self.read_u64(addr)
        num = self.read_i32(addr + 8)
        if num <= 0 or num > max_len or data_ptr == 0:
            return ''
        raw = self.read(data_ptr, num * 2)
        try:
            return raw.decode('utf-16-le').rstrip('\x00')
        except:
            return ''


# === OFFSETS — discovered by probe for THIS build ===
# Probe overrides these dynamically.
# Reference: ArcRaiders-DMA-Dumper (April 2025 Playtest 2) offsets
# Our build has GWorld=0xD856998 (theirs was 0x80E9950) — game was updated
# Theia obfuscator encrypts memory pages — may affect readings
OFFSETS = {
    'GWorld': 0xD856998,           # Found by PE scan (our build)
    # --- UWorld --- (UC thread + SDK dump)
    'PersistentLevel': 0x38,      # DMA dumper reference
    'OwningGameInstance': 0x1A0,  # DMA dumper reference (probe overrides)
    # --- UGameInstance --- (UC thread page 74: LocalPlayers = 0xF0)
    'LocalPlayers': 0xF0,         # UC SDK dump: GameInstance::LocalPlayers
    # --- UPlayer ---
    'PlayerController': 0x30,     # Standard UE5 (probe will override)
    # --- ULevel --- (DMA dumper: AActors=0xA0)
    'AActors': 0xA0,             # DMA dumper reference
    'ActorCount': 0xA8,
    # --- AActor --- (DMA dumper: RootComponent=0x1A0)
    'RootComponent': 0x1A0,       # DMA dumper reference
    # --- APawn --- (DMA dumper: PlayerState=0x2B0)
    'PlayerState': 0x2B0,        # DMA dumper reference
    # --- AController --- (DMA dumper: Pawn=0x310)
    'ControllerPawn': 0x310,      # DMA dumper reference
    # --- USceneComponent --- (DMA dumper: RelativeLocation=0x128)
    'RelativeLocation': 0x128,    # DMA dumper reference
    'ComponentToWorld': 0x1C0,    # Estimate
    'ComponentVelocity': 0x168,   # DMA dumper reference
    # --- APlayerState --- (DMA dumper: PlayerName=0x340)
    'PlayerName': 0x340,          # DMA dumper reference
    # --- APlayerController --- (DMA dumper: CameraManager=0x348)
    'PlayerCameraManager': 0x348, # DMA dumper reference
    'ControlRotation': 0xA78,     # Found by scan (PC+0xA78)
    # --- APlayerCameraManager --- (DMA dumper: CameraCache=0x2270)
    'CameraCachePrivate': 0x2270, # DMA dumper reference
    'ViewTarget': 0x430,          # Dumpspace
    'use_doubles': 0,              # 1 = UE5 Large World Coordinates (FVector = 3 doubles)
    'DefaultFOV': 0x418,          # Dumpspace
}

def get_pe_info(comm, base):
    """Lit les headers PE pour obtenir la taille de l'image et les sections"""
    dos_header = comm.read(base, 64)
    if dos_header[:2] != b'MZ':
        return None, []

    e_lfanew = struct.unpack_from('<I', dos_header, 0x3C)[0]
    pe_header = comm.read(base + e_lfanew, 0x108)  # PE sig + COFF + optional header
    if pe_header[:4] != b'PE\x00\x00':
        return None, []

    num_sections = struct.unpack_from('<H', pe_header, 6)[0]
    size_of_image = struct.unpack_from('<I', pe_header, 0x50)[0]

    # Read section headers (40 bytes each)
    section_offset = e_lfanew + 0x18 + struct.unpack_from('<H', pe_header, 0x14)[0]
    section_data = comm.read(base + section_offset, num_sections * 40)

    sections = []
    for i in range(num_sections):
        s = section_data[i*40:(i+1)*40]
        name = s[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
        vsize = struct.unpack_from('<I', s, 8)[0]
        va = struct.unpack_from('<I', s, 12)[0]
        sections.append({'name': name, 'va': va, 'vsize': vsize})

    return size_of_image, sections


def scan_for_gworld(comm, base, sections):
    """Scanne la section .data pour trouver un pointeur UWorld valide.
    UWorld est un global pointer dans .data qui pointe vers un objet heap.
    On cherche un pointeur qui, quand déréférencé, contient une vtable valide
    et un PersistentLevel valide à offset 0x30."""

    # Trouver la section .data
    data_section = None
    for s in sections:
        if s['name'] == '.data':
            data_section = s
            break

    if not data_section:
        print("    [SCAN] Section .data non trouvée")
        return None

    data_va = data_section['va']
    data_size = data_section['vsize']
    print(f"    [SCAN] Section .data: RVA=0x{data_va:x} Size=0x{data_size:x}")

    # Lire par blocs de 64KB et chercher des pointeurs heap
    BLOCK = DATA_BUF_SIZE
    candidates = []

    # Limiter le scan aux premiers 32MB de .data (perf)
    scan_size = min(data_size, 0x2000000)
    total_blocks = (scan_size + BLOCK - 1) // BLOCK

    print(f"    [SCAN] Scanning {scan_size // (1024*1024)}MB ({total_blocks} blocks)...")

    for block_idx in range(total_blocks):
        offset = block_idx * BLOCK
        addr = base + data_va + offset
        chunk_size = min(BLOCK, scan_size - offset)
        raw = comm.read(addr, chunk_size)

        if raw == b'\x00' * chunk_size:
            continue  # Page non mappée

        # Scanner chaque pointeur 8 bytes aligné
        for i in range(0, chunk_size - 8, 8):
            ptr = struct.unpack_from('<Q', raw, i)[0]

            # Filtre: doit ressembler à un pointeur heap user-mode
            if ptr < 0x10000 or ptr > 0x7FFFFFFFFFFF:
                continue
            # Éviter les pointeurs dans le module lui-même
            if base <= ptr < base + 0x10000000:
                continue

            # Vérifier si c'est un UWorld: lire PersistentLevel (try multiple offsets)
            level_ptr = None
            for pl_off in [0x108, 0xD0, 0x3D0, 0x30, 0xC0, 0xC8]:
                lp = comm.read_u64(ptr + pl_off)
                if 0x10000 < lp < 0x7FFFFFFFFFFF:
                    level_ptr = lp
                    break
            if not level_ptr:
                continue

            # Vérifier PersistentLevel a un ActorArray valide (try multiple offsets)
            actors_ptr = None
            actor_count = 0
            for aa_off in [0x118, 0x108, 0xD0, 0xA0, 0xB0, 0xC0, 0xE0]:
                ap = comm.read_u64(level_ptr + aa_off)
                if ap < 0x10000 or ap > 0x7FFFFFFFFFFF:
                    continue
                ac = struct.unpack('<i', comm.read(level_ptr + aa_off + 8, 4))[0]
                if 10 < ac < 200000:
                    actors_ptr = ap
                    actor_count = ac
                    break
            if not actors_ptr:
                continue

            rva = data_va + offset + i
            print(f"    [SCAN] Candidat GWorld @ RVA 0x{rva:x} -> 0x{ptr:x}")
            print(f"           PersistentLevel=0x{level_ptr:x} ActorCount={actor_count}")
            candidates.append((rva, ptr, actor_count))

            # Early exit: >10000 actors is definitely the main world
            if actor_count > 10000:
                print(f"[+] GWorld trouvé par scan: offset=0x{rva:x} ptr=0x{ptr:x} ({actor_count} acteurs)")
                return rva

        # Progress
        if block_idx > 0 and block_idx % 100 == 0:
            pct = block_idx * 100 // total_blocks
            print(f"    [SCAN] {pct}%...")

    if candidates:
        # Prendre celui avec le plus d'acteurs (probablement le vrai UWorld)
        best = max(candidates, key=lambda c: c[2])
        print(f"[+] GWorld trouvé par scan: offset=0x{best[0]:x} ptr=0x{best[1]:x} ({best[2]} acteurs)")
        if best[2] < 100:
            print("    [!] Peu d'acteurs — tu es peut-être dans le menu. Relance en match.")
        return best[0]  # Retourne le RVA (offset depuis base)

    print("    [SCAN] Aucun GWorld trouvé")
    return None


def _is_heap(addr, base, img_end):
    """Check if address is a valid heap pointer (not in module range).
    On Win64, heap allocs are typically >= 0x10000000000 (64GB+).
    This rejects packed integers like 0xffffffff, 0x3ffffffff, etc."""
    if addr < 0x10000000000 or addr > 0x7FFFFFFFFFFF:
        return False
    if base and base <= addr < img_end:
        return False
    return True


def _is_ptr(addr, base, img_end):
    """Looser check: any non-zero pointer (heap or module)"""
    if addr < 0x10000 or addr > 0x7FFFFFFFFFFF:
        return False
    return True


def probe_uworld_offsets(comm, gworld_ptr):
    """Probe UWorld to find offsets. Tests known offsets first, then brute-force."""
    print("\n=== PROBE UWorld ===")
    print(f"  UWorld @ 0x{gworld_ptr:x}")

    base = comm.base
    img_end = base + 0x10000000 if base else 0
    print(f"  Module range: 0x{base:x} - 0x{img_end:x}")

    # Validate GWorld is a real UObject (vtable in module)
    vt = comm.read_u64(gworld_ptr)
    if base and base <= vt < img_end:
        print(f"  UWorld vtable: 0x{vt:x} [MODULE] ✓")
    else:
        print(f"  [!] UWorld vtable: 0x{vt:x} [NOT MODULE] — may not be a real UObject")
        print(f"      This could mean GWorld is encrypted/obfuscated or points to a wrapper")

    # Read UWorld (0x800 bytes)
    raw = comm.read(gworld_ptr, 0x800)
    if len(raw) < 0x800:
        print("  [!] Impossible de lire UWorld")
        return

    # === Dump UWorld structure ===
    print("\n  --- UWorld raw dump (all 0x800 bytes) ---")
    heap_count = 0
    module_count = 0
    for off in range(0, 0x800, 8):
        ptr = struct.unpack_from('<Q', raw, off)[0]
        if base and base <= ptr < img_end:
            module_count += 1
            print(f"    +0x{off:03X}: 0x{ptr:x} [MODULE]")
        elif _is_heap(ptr, base, img_end):
            heap_count += 1
            print(f"    +0x{off:03X}: 0x{ptr:x} [HEAP]")
        elif base and base <= ptr < img_end:
            print(f"    +0x{off:03X}: 0x{ptr:x} [MODULE]")
    print(f"  ({heap_count} heap + {module_count} module pointers in 0x800 bytes)")

    # === Test PersistentLevel offsets ===
    # Theia may obfuscate vtables, so we DON'T require MODULE vtable.
    # Instead we validate by structure: Level -> TArray<AActor*> with valid heap entries.
    print("\n  Testing PersistentLevel offsets (no vtable requirement)...")
    known_pl_offsets = [0x38, 0x30, 0x40, 0xC0, 0xD0, 0x108, 0x390, 0x3D0, 0xC8, 0x1E0]
    known_aa_offsets = [0xA0, 0xA8, 0x98, 0x2D0, 0x118, 0x108, 0xD0, 0xB0, 0xC0, 0xE0,
                        0x248, 0x140, 0x270, 0x1D0, 0x230, 0x1D8, 0x150, 0x160]

    best_level = None  # (uworld_off, actor_off, level_ptr, actors_ptr, count, heap_valid, score)

    def _check_actor_array(actors_ptr, actor_count):
        """Check if an actor array has valid heap entries. Returns (heap_valid, module_vt)."""
        sample = comm.read(actors_ptr, min(actor_count, 20) * 8)
        heap_valid = 0
        module_vt = 0
        for j in range(min(actor_count, 20)):
            elem = struct.unpack_from('<Q', sample, j * 8)[0]
            if _is_heap(elem, base, img_end):
                heap_valid += 1
                vt = comm.read_u64(elem)
                if base and base <= vt < img_end:
                    module_vt += 1
            if heap_valid >= 10:
                break
        return heap_valid, module_vt

    # Step 1: known offsets
    for pl_off in known_pl_offsets:
        if pl_off >= len(raw):
            continue
        level_ptr = struct.unpack_from('<Q', raw, pl_off)[0]
        if not _is_heap(level_ptr, base, img_end):
            continue

        for aa_off in known_aa_offsets:
            data = comm.read(level_ptr + aa_off, 16)
            actors_ptr = struct.unpack_from('<Q', data, 0)[0]
            actor_count = struct.unpack_from('<i', data, 8)[0]

            if not _is_heap(actors_ptr, base, img_end):
                continue
            if actor_count < 1 or actor_count > 200000:
                continue

            heap_valid, module_vt = _check_actor_array(actors_ptr, actor_count)

            if heap_valid >= 3:
                # Score: prefer MODULE vtables > heap count > actor count
                score = module_vt * 10000 + heap_valid * 1000 + min(actor_count, 999)
                tag = f"vt={module_vt}" if module_vt > 0 else f"heap={heap_valid}"
                print(f"    UWorld+0x{pl_off:03X} -> Level+0x{aa_off:03X}: {actor_count} actors, {tag}")
                if best_level is None or score > best_level[6]:
                    best_level = (pl_off, aa_off, level_ptr, actors_ptr, actor_count, heap_valid, score)

    # Read extended UWorld now (used by brute-force, GI search, streaming scan)
    raw_ext = comm.read(gworld_ptr + 0x800, 0x800)
    raw_full = raw + raw_ext

    # Step 2: brute-force ALL UWorld offsets (0x0 to 0x1000)
    # GI was found at 0xDF8, so PersistentLevel could also be beyond 0x800
    if best_level is None or best_level[6] < 5000:
        print("\n  Brute-force scanning all UWorld offsets 0x0-0x1000 (no vtable requirement)...")

        for off in range(0, len(raw_full), 8):
            ptr = struct.unpack_from('<Q', raw_full, off)[0]
            if not _is_heap(ptr, base, img_end):
                continue

            # Read a larger chunk of the candidate Level (up to 0x500)
            lvl_data = comm.read(ptr, 0x500)
            if len(lvl_data) < 0x500:
                continue

            for aa_off in range(0x20, 0x4F0, 8):
                actors_ptr = struct.unpack_from('<Q', lvl_data, aa_off)[0]
                if not _is_heap(actors_ptr, base, img_end):
                    continue
                actor_count = struct.unpack_from('<i', lvl_data, aa_off + 8)[0]
                if actor_count < 5 or actor_count > 200000:
                    continue

                heap_valid, module_vt = _check_actor_array(actors_ptr, actor_count)

                if heap_valid >= 3:
                    score = module_vt * 10000 + heap_valid * 1000 + min(actor_count, 999)
                    if best_level is None or score > best_level[6]:
                        best_level = (off, aa_off, ptr, actors_ptr, actor_count, heap_valid, score)
                        tag = f"vt={module_vt}" if module_vt > 0 else f"heap={heap_valid}"
                        print(f"    Found: UWorld+0x{off:x} -> Level+0x{aa_off:x}: {actor_count} actors, {tag}")

    if best_level:
        pl_off, aa_off = best_level[0], best_level[1]
        print(f"\n  [+] PersistentLevel = UWorld+0x{pl_off:x} (Level @ 0x{best_level[2]:x})")
        print(f"       ActorArray = Level+0x{aa_off:x} ({best_level[4]} actors, score={best_level[6]})")
        OFFSETS['PersistentLevel'] = pl_off
        OFFSETS['AActors'] = aa_off
        OFFSETS['ActorCount'] = aa_off + 8
    else:
        print("\n  [!] PersistentLevel non trouvé")
        print("  [!] Es-tu en match ? En menu il y a trop peu d'acteurs pour valider.")

    # === Find OwningGameInstance ===
    print("\n  Searching GameInstance...")

    # raw_full already contains 0x1000 bytes of UWorld (read earlier)

    # --- Step 1: Try known GI offsets directly ---
    # DMA dumper: GI=0x1A0
    known_gi_offsets = [0x1A0, 0x1A8, 0x198, 0xCB8, 0x2C0, 0x40, 0x180, 0x1C0, 0x200, 0x280, 0x300, 0x20]
    gi_candidates = []

    def _is_valid_uobj(ptr):
        """Check if ptr looks like a UObject — vtable is either MODULE or HEAP (Theia)"""
        vt = comm.read_u64(ptr)
        return (base and base <= vt < img_end) or _is_heap(vt, base, img_end)

    for gi_off in known_gi_offsets:
        if gi_off + 8 > len(raw_full):
            continue
        gi_ptr = struct.unpack_from('<Q', raw_full, gi_off)[0]
        if not _is_heap(gi_ptr, base, img_end):
            continue
        # Check vtable — accept HEAP vtable too (Theia obfuscation)
        if not _is_valid_uobj(gi_ptr):
            continue
        # Check for TArray(count=1) at known LP offsets
        for lp_off in [0xF0, 0x38, 0x40, 0x48, 0x1D0, 0x1E0, 0x1A8, 0x210, 0x240, 0x250, 0x268]:
            lp_data = comm.read(gi_ptr + lp_off, 16)
            lp_ptr = struct.unpack_from('<Q', lp_data, 0)[0]
            lp_count = struct.unpack_from('<i', lp_data, 8)[0]
            if not _is_heap(lp_ptr, base, img_end) or lp_count != 1:
                continue
            lp0 = comm.read_u64(lp_ptr)
            if not _is_heap(lp0, base, img_end):
                continue
            # Accept HEAP vtable too (Theia)
            if not _is_valid_uobj(lp0):
                continue
            # Find PC in LP[0]
            lp0_data = comm.read(lp0, 0x200)
            for pc_off in [0x30, 0x38, 0x48, 0x50, 0x58, 0x60, 0x78, 0xA8, 0x178]:
                pc = struct.unpack_from('<Q', lp0_data, pc_off)[0]
                if not _is_heap(pc, base, img_end) or pc == gi_ptr or pc == lp0:
                    continue
                # Accept HEAP vtable too (Theia)
                if not _is_valid_uobj(pc):
                    continue
                # Check pawn
                found_pawn = False
                for pawn_off in [0x220, 0x310, 0x318, 0x308, 0x320, 0x328, 0x338, 0x3E0, 0x3E8, 0x378, 0x388, 0x240, 0x260, 0x280, 0x2A0]:
                    pawn = comm.read_u64(pc + pawn_off)
                    if _is_heap(pawn, base, img_end) and pawn != pc and pawn != lp0:
                        root = comm.read_u64(pawn + OFFSETS['RootComponent'])
                        if _is_heap(root, base, img_end):
                            gi_candidates.append({
                                'uw_off': gi_off, 'lp_off': lp_off, 'pc_off': pc_off,
                                'pawn_off': pawn_off, 'gi': gi_ptr, 'lp0': lp0,
                                'pc': pc, 'pawn': pawn, 'has_pawn': True
                            })
                            found_pawn = True
                            break
                if not found_pawn:
                    gi_candidates.append({
                        'uw_off': gi_off, 'lp_off': lp_off, 'pc_off': pc_off,
                        'pawn_off': 0, 'gi': gi_ptr, 'lp0': lp0,
                        'pc': pc, 'pawn': 0, 'has_pawn': False
                    })
                print(f"    Known: UWorld+0x{gi_off:X} GI=0x{gi_ptr:x} LP@+0x{lp_off:x} PC@+0x{pc_off:x} pawn={'YES' if found_pawn else 'no'}")
                break
            if gi_candidates and gi_candidates[-1].get('has_pawn'):
                break
        if gi_candidates and gi_candidates[-1].get('has_pawn'):
            break

    # --- Step 2: Aggressive search only if known offsets failed ---
    if not gi_candidates:
        print("  Known GI offsets failed, trying aggressive scan...")
        for off in range(0, len(raw_full), 8):
            ptr = struct.unpack_from('<Q', raw_full, off)[0]
            if not _is_heap(ptr, base, img_end):
                continue
            # GI must look like a UObject (vtable in module OR heap — Theia)
            if not _is_valid_uobj(ptr):
                continue

            # Read 0x300 bytes of this candidate GameInstance
            gi_data = comm.read(ptr, 0x300)
            if len(gi_data) < 0x300:
                continue

            # Look for a TArray with count=1 (LocalPlayers)
            for lp_off in range(0x30, 0x280, 8):
                lp_ptr = struct.unpack_from('<Q', gi_data, lp_off)[0]
                if not _is_heap(lp_ptr, base, img_end):
                    continue
                if lp_off + 12 > len(gi_data):
                    continue
                lp_count = struct.unpack_from('<i', gi_data, lp_off + 8)[0]
                if lp_count != 1:
                    continue

                # Read LP[0]
                lp0 = comm.read_u64(lp_ptr)
                if not _is_heap(lp0, base, img_end):
                    continue
                if lp0 == ptr:
                    continue

                # LP[0] must look like a UObject (Theia: vtable can be HEAP)
                if not _is_valid_uobj(lp0):
                    continue

                # Try to find PlayerController in LP[0]
                lp0_data = comm.read(lp0, 0x200)
                for pc_off in range(0x28, 0x200, 8):
                    pc = struct.unpack_from('<Q', lp0_data, pc_off)[0]
                    if not _is_heap(pc, base, img_end):
                        continue
                    if pc == ptr or pc == lp0:
                        continue
                    # Accept HEAP vtable (Theia)
                    if not _is_valid_uobj(pc):
                        continue

                    # PC is a UObject! Check for Pawn
                    found_pawn = False
                    for pawn_off in [0x310, 0x318, 0x308, 0x320, 0x328, 0x338, 0x3E0, 0x3E8, 0x378, 0x388]:
                        pawn = comm.read_u64(pc + pawn_off)
                        if _is_heap(pawn, base, img_end) and pawn != pc and pawn != lp0:
                            root = comm.read_u64(pawn + OFFSETS['RootComponent'])
                            if _is_heap(root, base, img_end):
                                gi_candidates.append({
                                    'uw_off': off, 'lp_off': lp_off, 'pc_off': pc_off,
                                    'pawn_off': pawn_off, 'gi': ptr, 'lp0': lp0,
                                    'pc': pc, 'pawn': pawn, 'has_pawn': True
                                })
                                found_pawn = True
                                break

                    if not found_pawn:
                        gi_candidates.append({
                            'uw_off': off, 'lp_off': lp_off, 'pc_off': pc_off,
                            'pawn_off': 0, 'gi': ptr, 'lp0': lp0,
                            'pc': pc, 'pawn': 0, 'has_pawn': False
                        })
                    break  # First valid PC is enough
                if gi_candidates and gi_candidates[-1].get('has_pawn'):
                    break  # Found a full chain, stop
            if gi_candidates and gi_candidates[-1].get('has_pawn'):
                break

    if gi_candidates:
        # Prefer candidates with pawn
        gi_candidates.sort(key=lambda c: (not c['has_pawn'], c['uw_off']))
        best = gi_candidates[0]
        print(f"  [{len(gi_candidates)} candidates]")
        for c in gi_candidates[:5]:
            pawn_str = f"Pawn=0x{c['pawn']:x}" if c['has_pawn'] else "no pawn"
            print(f"    UWorld+0x{c['uw_off']:x} GI+0x{c['lp_off']:x} LP+0x{c['pc_off']:x} ({pawn_str})")

        print(f"\n  [+] GameInstance = UWorld+0x{best['uw_off']:x} -> 0x{best['gi']:x}")
        print(f"       LocalPlayers = GI+0x{best['lp_off']:x}, LP[0]=0x{best['lp0']:x}")
        print(f"       PlayerController = LP+0x{best['pc_off']:x} -> 0x{best['pc']:x}")
        OFFSETS['OwningGameInstance'] = best['uw_off']
        OFFSETS['LocalPlayers'] = best['lp_off']
        OFFSETS['PlayerController'] = best['pc_off']

        if best['has_pawn']:
            print(f"       Pawn = PC+0x{best['pawn_off']:x} -> 0x{best['pawn']:x}")
            OFFSETS['ControllerPawn'] = best['pawn_off']
            root = comm.read_u64(best['pawn'] + 0x228)
            if root > 0x10000:
                for loc_off in [0x1F8, 0x258, 0x1D0, 0x158, 0x120, 0x340]:
                    loc = comm.read_vec3(root + loc_off)
                    if abs(loc[0]) > 50 and abs(loc[0]) < 5e6 and abs(loc[2]) > 1:
                        print(f"       Location @ Root+0x{loc_off:x} = ({loc[0]:.0f}, {loc[1]:.0f}, {loc[2]:.0f})")
                        OFFSETS['RelativeLocation'] = loc_off
                        break
        else:
            print(f"       (No Pawn at known offsets)")
            pc = best['pc']

            # === DEEP PAWN DISCOVERY ===
            # Don't assume RootComponent at 0x228 — scan all heap sub-objects
            print(f"\n  --- Deep Pawn Discovery from PC (0x{pc:x}) ---")
            pc_data = comm.read(pc, 0xE00)
            pawn_candidates = []

            # Known RootComponent offsets to try on each candidate
            # DMA dumper: RootComponent=0x1A0
            rc_offsets = [0x1A0, 0x1A8, 0x198, 0x1B0, 0x1B8, 0x1C0, 0x1C8,
                          0x1D0, 0x1D8, 0x1E0, 0x1E8, 0x1F0, 0x1F8, 0x200,
                          0x208, 0x210, 0x218, 0x220, 0x228, 0x230, 0x238,
                          0x240, 0x248, 0x250, 0x258, 0x260, 0x268, 0x270, 0x278, 0x280]
            # DMA dumper: RelativeLocation=0x128
            loc_offsets = [0x128, 0x130, 0x120, 0x138, 0x140, 0x148, 0x150,
                           0x158, 0x160, 0x168, 0x170, 0x178, 0x1D0, 0x1F8,
                           0x200, 0x210, 0x220, 0x230, 0x240, 0x258, 0x2E0,
                           0x300, 0x310, 0x320, 0x330, 0x350, 0x360]

            # Pawn is typically at offset >= 0x280 in APlayerController
            # (AController::Pawn is after all UObject/AActor/APawn fields)
            for poff in range(0x200, len(pc_data), 8):
                val = struct.unpack_from('<Q', pc_data, poff)[0]
                if not _is_heap(val, base, img_end):
                    continue
                if val == pc or val == best['gi'] or val == best['lp0']:
                    continue
                # Reject page-aligned pointers (likely not real heap allocs)
                if (val & 0xFFFFFF) == 0:
                    continue
                # Try each RootComponent offset
                for rc_off in rc_offsets:
                    rc = comm.read_u64(val + rc_off)
                    if not _is_heap(rc, base, img_end) or rc == val:
                        continue
                    # Reject page-aligned RootComponent (likely not real alloc)
                    if (rc & 0xFFFF) == 0:
                        continue
                    # Try each location offset — doubles first (UE5 LWC), then floats
                    # Require at least 2 non-zero axes for a real 3D position
                    found_this = False
                    for loc_off in loc_offsets:
                        # Try doubles (24 bytes)
                        try:
                            locd = struct.unpack('<ddd', comm.read(rc + loc_off, 24))
                            mc = max(abs(locd[0]), abs(locd[1]), abs(locd[2]))
                            nz = sum(1 for v in locd if abs(v) > 1.0)
                            if (mc > 100 and mc < 5e6 and nz >= 2 and
                                not math.isinf(locd[0]) and not math.isnan(locd[0])):
                                pawn_candidates.append((poff, val, rc_off, rc, loc_off, locd))
                                found_this = True
                                break
                        except:
                            pass
                    if not found_this:
                        for loc_off in loc_offsets:
                            loc = comm.read_vec3(rc + loc_off)
                            mc = max(abs(loc[0]), abs(loc[1]), abs(loc[2]))
                            nz = sum(1 for v in loc if abs(v) > 1.0)
                            if (mc > 100 and mc < 5e6 and nz >= 2 and
                                not math.isinf(loc[0]) and not math.isnan(loc[0])):
                                pawn_candidates.append((poff, val, rc_off, rc, loc_off, loc))
                                break
                    if pawn_candidates and pawn_candidates[-1][1] == val:
                        break  # Found valid location for this candidate

                # Limit output
                if len(pawn_candidates) >= 10:
                    break

            if pawn_candidates:
                for c in pawn_candidates[:5]:
                    print(f"    PC+0x{c[0]:03X}: 0x{c[1]:x} Root@+0x{c[2]:x}=0x{c[3]:x} Loc@+0x{c[4]:x}=({c[5][0]:.0f},{c[5][1]:.0f},{c[5][2]:.0f})")
                best_pawn = pawn_candidates[0]
                print(f"\n  [+] PAWN FOUND: PC+0x{best_pawn[0]:X} -> 0x{best_pawn[1]:x}")
                print(f"       RootComponent @ +0x{best_pawn[2]:x} = 0x{best_pawn[3]:x}")
                print(f"       Location @ Root+0x{best_pawn[4]:x} = ({best_pawn[5][0]:.0f},{best_pawn[5][1]:.0f},{best_pawn[5][2]:.0f})")
                OFFSETS['ControllerPawn'] = best_pawn[0]
                # Store pawn-specific offsets (may differ from generic actors)
                OFFSETS['PawnRootComponent'] = best_pawn[2]
                OFFSETS['PawnRelativeLocation'] = best_pawn[4]
                # Also set generic offsets as initial values
                OFFSETS['RootComponent'] = best_pawn[2]
                OFFSETS['RelativeLocation'] = best_pawn[4]
            else:
                # Fallback: just list all UObject heap pointers in PC for debugging
                print("    No candidates with valid 3D coordinates found")
                print("    UObject heap pointers in PC:")
                count = 0
                for poff in range(0, len(pc_data), 8):
                    val = struct.unpack_from('<Q', pc_data, poff)[0]
                    if not _is_heap(val, base, img_end) or val == pc:
                        continue
                    vt = comm.read_u64(val)
                    if base and base <= vt < img_end:
                        print(f"      PC+0x{poff:03X}: 0x{val:x}")
                        count += 1
                        if count >= 20:
                            break

            # Scan for ControlRotation (try both floats and doubles)
            print(f"\n  Scanning for ControlRotation...")
            # Try as 3 floats (12 bytes)
            for poff in range(0x300, 0xD00, 4):
                if poff + 12 > len(pc_data):
                    break
                p, y, r = struct.unpack_from('<fff', pc_data, poff)
                if (abs(p) < 90 and abs(y) < 360 and abs(r) < 90 and
                    (abs(p) > 0.1 or abs(y) > 0.1) and
                    not math.isinf(p) and not math.isnan(p)):
                    print(f"    PC+0x{poff:03X}: P={p:.2f} Y={y:.2f} R={r:.2f} (floats)")
            # Try as 3 doubles (24 bytes)
            for poff in range(0x300, 0xD00, 8):
                if poff + 24 > len(pc_data):
                    break
                p, y, r = struct.unpack_from('<ddd', pc_data, poff)
                if (abs(p) < 90 and abs(y) < 360 and abs(r) < 90 and
                    (abs(p) > 0.1 or abs(y) > 0.1) and
                    not math.isinf(p) and not math.isnan(p)):
                    print(f"    PC+0x{poff:03X}: P={p:.2f} Y={y:.2f} R={r:.2f} (doubles)")

    else:
        print("  [!] GameInstance non trouvé dans 0x1000 bytes de UWorld")

    # === ALWAYS scan streaming levels (no vtable requirement) ===
    print(f"\n  --- Scanning ALL levels in UWorld (extended) ---")
    best_streaming = None  # (lvl_off, aa_off, lvl_ptr, ap, ac, score)
    # Skip this scan if brute-force already found a good result
    if best_level and best_level[6] >= 5000:
        print("  (Skipping — brute-force already found a good level)")
    else:
        for lvl_off in range(0x0, len(raw_full), 8):
            lvl_ptr = struct.unpack_from('<Q', raw_full, lvl_off)[0]
            if not _is_heap(lvl_ptr, base, img_end):
                continue

            # Read larger chunk of each candidate and scan wider range
            lvl_chunk = comm.read(lvl_ptr, 0x500)
            if len(lvl_chunk) < 0x500:
                continue

            for aa_off in range(0x20, 0x4F0, 8):
                ap = struct.unpack_from('<Q', lvl_chunk, aa_off)[0]
                ac = struct.unpack_from('<i', lvl_chunk, aa_off + 8)[0]
                if not _is_heap(ap, base, img_end) or ac < 5 or ac > 200000:
                    continue
                # Check entries are valid heap pointers
                heap_ok, vt_ok = _check_actor_array(ap, ac)
                if heap_ok >= 3:
                    tag = " <<<" if ac > 100 else ""
                    vtag = f"vt={vt_ok}" if vt_ok > 0 else f"heap={heap_ok}"
                    print(f"    UWorld+0x{lvl_off:03X} -> Level+0x{aa_off:03X}: {ac} actors, {vtag}{tag}")
                    score = vt_ok * 10000 + heap_ok * 1000 + min(ac, 5000)
                    if best_streaming is None or score > best_streaming[5]:
                        best_streaming = (lvl_off, aa_off, lvl_ptr, ap, ac, score)

    if best_streaming:
        print(f"\n  [+] Best level: UWorld+0x{best_streaming[0]:x} -> Level+0x{best_streaming[1]:x} ({best_streaming[4]} actors, score={best_streaming[5]})")
        # Override if streaming has significantly more actors
        if best_streaming[4] > 50:
            if not best_level or best_streaming[4] > best_level[4] * 2:
                if best_level:
                    print(f"       Overriding PersistentLevel (was {best_level[4]} actors)")
                OFFSETS['PersistentLevel'] = best_streaming[0]
                OFFSETS['AActors'] = best_streaming[1]
                OFFSETS['ActorCount'] = best_streaming[1] + 8
            else:
                print(f"       (Not overriding — not clearly better than {best_level[4]} actors)")
        else:
            print(f"       (Not overriding — only {best_streaming[4]} actors)")
    else:
        print("  [!] No valid levels found in streaming scan")

    print("=== END PROBE ===\n")


def find_all_levels(comm, gworld_ptr, base):
    """Search UWorld for TArray<ULevel*> — finds ALL loaded levels including match levels.
    In UE5, UWorld::Levels contains persistent + streaming levels."""
    img_end = base + 0x10000000 if base else 0

    # Read 0x1000 bytes of UWorld
    raw = comm.read(gworld_ptr, 0x1000)
    if len(raw) < 0x1000:
        print("  [!] Impossible de lire UWorld")
        return

    best_level = None  # (uw_off, aa_off, lvl_ptr, actors_ptr, actor_count, vt_ok)
    aa_offsets = [0xA0, 0xA8, 0x98, 0xB0, 0xB8, 0xC0, 0xD0, 0xE0, 0x108, 0x118,
                  0x140, 0x1D0, 0x1D8, 0x230, 0x248, 0x270, 0x2D0]

    # Look for TArray<ULevel*> patterns: (ptr, count, max) where count >= 2
    for off in range(0x0, 0x1000, 8):
        arr_ptr = struct.unpack_from('<Q', raw, off)[0]
        if not _is_heap(arr_ptr, base, img_end):
            continue
        # Read count (int32 at +8)
        if off + 12 > len(raw):
            continue
        count = struct.unpack_from('<i', raw, off + 8)[0]
        if count < 2 or count > 100:
            continue
        # Read max (int32 at +12) — should be >= count
        max_count = struct.unpack_from('<i', raw, off + 12)[0]
        if max_count < count:
            continue

        # Read the array entries
        arr_data = comm.read(arr_ptr, count * 8)
        if len(arr_data) < count * 8:
            continue

        # Check each entry: should be heap pointers (ULevel objects)
        levels_ok = 0
        for i in range(count):
            lvl = struct.unpack_from('<Q', arr_data, i * 8)[0]
            if _is_heap(lvl, base, img_end):
                levels_ok += 1

        if levels_ok < 2:
            continue

        print(f"  UWorld+0x{off:03X}: TArray<ULevel*>? count={count}/{max_count}, valid={levels_ok}")

        # For each ULevel in this array, find the actor array
        for i in range(count):
            lvl = struct.unpack_from('<Q', arr_data, i * 8)[0]
            if not _is_heap(lvl, base, img_end):
                continue

            for aa_off in aa_offsets:
                d = comm.read(lvl + aa_off, 16)
                ap = struct.unpack_from('<Q', d, 0)[0]
                ac = struct.unpack_from('<i', d, 8)[0]
                if not _is_heap(ap, base, img_end) or ac < 5 or ac > 200000:
                    continue
                # Check entries are valid heap pointers
                sample = comm.read(ap, min(ac, 16) * 8)
                heap_ok = 0
                for j in range(min(ac, 16)):
                    elem = struct.unpack_from('<Q', sample, j * 8)[0]
                    if _is_heap(elem, base, img_end):
                        heap_ok += 1
                if heap_ok >= 3:
                    tag = " <<<" if ac > 100 else ""
                    print(f"    Level[{i}] @ 0x{lvl:x} -> +0x{aa_off:x}: {ac} actors, heap={heap_ok}{tag}")
                    if best_level is None or ac > best_level[4]:
                        best_level = (off, aa_off, lvl, ap, ac, heap_ok)

    if best_level:
        print(f"\n  [+] BEST LEVEL: {best_level[4]} actors (UWorld+0x{best_level[0]:x} Level+0x{best_level[1]:x})")
        if best_level[4] > 50:
            OFFSETS['PersistentLevel'] = best_level[0]
            OFFSETS['AActors'] = best_level[1]
            OFFSETS['ActorCount'] = best_level[1] + 8
            print(f"       Offsets mis à jour: PersistentLevel=0x{best_level[0]:x}, AActors=0x{best_level[1]:x}")
        else:
            print(f"       (Pas assez d'acteurs pour être le level de match)")
    else:
        print("  [!] Aucun TArray<ULevel*> trouvé")

    print("=== END LEVEL SEARCH ===\n")


def dump_level_and_actors(comm, radar):
    """Dump Level object to find real actor array and discover struct offsets"""
    if not radar.gworld:
        return

    level = comm.read_u64(radar.gworld + OFFSETS['PersistentLevel'])
    if level < 0x10000:
        return
    base = comm.base
    img_end = base + 0x10000000 if base else 0

    print("\n=== DEEP ACTOR SCAN ===")
    print(f"  Level @ 0x{level:x}")
    print(f"  Module range: 0x{base:x} - 0x{img_end:x}")

    # Use the actor array we already found
    actors_ptr = comm.read_u64(level + OFFSETS['AActors'])
    actor_count = comm.read_i32(level + OFFSETS['ActorCount'])
    print(f"  ActorArray @ Level+0x{OFFSETS['AActors']:x} = 0x{actors_ptr:x} ({actor_count} entries)")

    if actors_ptr < 0x10000 or actor_count <= 0:
        print("  [!] Invalid actor array")
        print("=== END DEEP SCAN ===\n")
        return

    # Step 1: Sample actors from across the array (not just first 10)
    # Read a spread of entries: first 20, middle 20, random spots
    sample_indices = list(range(0, min(20, actor_count)))
    mid = actor_count // 2
    sample_indices += list(range(mid, min(mid + 20, actor_count)))
    sample_indices += list(range(max(0, actor_count - 20), actor_count))
    # Add some quarter-marks
    q1, q3 = actor_count // 4, actor_count * 3 // 4
    sample_indices += list(range(q1, min(q1 + 10, actor_count)))
    sample_indices += list(range(q3, min(q3 + 10, actor_count)))
    sample_indices = sorted(set(sample_indices))

    # Read all sampled pointers (batch reads in chunks)
    print(f"  Sampling {len(sample_indices)} indices across array...")

    non_null_actors = []
    vtable_in_module = 0
    vtable_in_heap = 0

    for idx in sample_indices:
        ptr = comm.read_u64(actors_ptr + idx * 8)
        if ptr < 0x10000 or ptr > 0x7FFFFFFFFFFF:
            continue
        if ptr == actors_ptr:  # Skip self-reference
            continue
        non_null_actors.append((idx, ptr))

    print(f"  Non-null actors: {len(non_null_actors)}")

    # Step 2: Check vtables to confirm these are real UObjects
    for idx, actor in non_null_actors[:30]:
        vtable = comm.read_u64(actor)
        if base and base <= vtable < img_end:
            vtable_in_module += 1
        elif vtable > 0x10000 and vtable < 0x7FFFFFFFFFFF:
            vtable_in_heap += 1

    print(f"  Vtables: {vtable_in_module} in module, {vtable_in_heap} in heap (of {min(30, len(non_null_actors))} tested)")

    if vtable_in_module < 5 and vtable_in_heap < 5:
        print("  [!] Very few valid vtables — this may not be a real actor array")
        print("=== END DEEP SCAN ===\n")
        return

    # Step 3: Brute-force scan for RootComponent + RelativeLocation
    # For ~10 confirmed actors, read 0x500 bytes and test ALL pointer offsets
    print("\n  Brute-force scanning for RootComponent + Location...")

    # Collect offset->hit_count for RootComponent candidates
    rc_hits = {}  # (actor_offset, loc_offset) -> count
    actor_locations = {}  # actor_addr -> (x, y, z)

    test_actors = []
    for idx, actor in non_null_actors:
        vtable = comm.read_u64(actor)
        is_uobject = (base and base <= vtable < img_end) or (vtable > 0x10000 and vtable < 0x7FFFFFFFFFFF)
        if is_uobject:
            test_actors.append((idx, actor))
        if len(test_actors) >= 15:
            break

    for idx, actor in test_actors:
        actor_data = comm.read(actor, 0x500)
        if len(actor_data) < 0x500:
            continue

        # Try every 8-byte aligned offset as potential RootComponent
        for rc_off in range(0x100, 0x500, 8):
            rc = struct.unpack_from('<Q', actor_data, rc_off)[0]
            if rc < 0x10000 or rc > 0x7FFFFFFFFFFF:
                continue
            if base and base <= rc < img_end:
                continue
            if rc == actor:  # Self-pointer
                continue

            # Read candidate SceneComponent and try Location offsets
            sc_data = comm.read(rc, 0x400)
            if len(sc_data) < 0x400:
                continue

            found_loc = False
            # Try DOUBLES first (UE5 Large World Coordinates — 3 x double = 24 bytes)
            for loc_off in range(0x100, 0x3E8, 8):
                if loc_off + 24 > len(sc_data):
                    break
                x, y, z = struct.unpack_from('<ddd', sc_data, loc_off)
                max_coord = max(abs(x), abs(y), abs(z))
                nz = sum(1 for v in (x, y, z) if abs(v) > 1.0)
                if (max_coord > 100 and max_coord < 5e6 and nz >= 2 and
                    not math.isinf(x) and not math.isnan(x) and
                    not math.isinf(y) and not math.isnan(y)):
                    key = (rc_off, loc_off)
                    rc_hits[key] = rc_hits.get(key, 0) + 1
                    if rc_hits[key] == 1:
                        actor_locations[actor] = (x, y, z)
                    found_loc = True
                    break
            if found_loc:
                continue
            # Fallback: try FLOATS (3 x float = 12 bytes)
            for loc_off in range(0x100, 0x400, 4):
                if loc_off + 12 > len(sc_data):
                    break
                x, y, z = struct.unpack_from('<fff', sc_data, loc_off)
                max_coord = max(abs(x), abs(y), abs(z))
                nz = sum(1 for v in (x, y, z) if abs(v) > 1.0)
                if (max_coord > 100 and max_coord < 5e6 and nz >= 2 and
                    not math.isinf(x) and not math.isnan(x) and
                    not math.isinf(y) and not math.isnan(y)):
                    key = (rc_off, loc_off)
                    rc_hits[key] = rc_hits.get(key, 0) + 1
                    if rc_hits[key] == 1:
                        actor_locations[actor] = (x, y, z)
                    break

    if rc_hits:
        # Sort by hit count
        sorted_hits = sorted(rc_hits.items(), key=lambda x: -x[1])
        print(f"\n  Top RootComponent+Location offset combos (from {len(test_actors)} actors):")
        for (rc_off, loc_off), count in sorted_hits[:10]:
            marker = " <<<" if count >= 5 else ""
            print(f"    Actor+0x{rc_off:03X} -> SceneComp+0x{loc_off:03X}: {count} hits{marker}")

        # Use the best combo
        best_rc, best_loc = sorted_hits[0][0]
        best_count = sorted_hits[0][1]
        if best_count >= 3:
            # Detect if doubles or floats based on which pass found the hit
            # Test: re-read one actor with doubles and see if it gives valid coords
            is_doubles = False
            multi_axis = 0  # count actors with 2+ non-zero axes
            for idx, actor in test_actors[:5]:
                rc = comm.read_u64(actor + best_rc)
                if rc < 0x10000 or rc > 0x7FFFFFFFFFFF:
                    continue
                if base and base <= rc < img_end:
                    continue
                # Try doubles
                dbl = comm.read_vec3d(rc + best_loc)
                mc_d = max(abs(dbl[0]), abs(dbl[1]), abs(dbl[2]))
                nz_d = sum(1 for v in dbl if abs(v) > 1.0)
                if mc_d > 100 and mc_d < 5e6 and nz_d >= 2 and not math.isinf(dbl[0]) and not math.isnan(dbl[0]):
                    is_doubles = True
                    multi_axis += 1
                else:
                    # Try floats
                    flt = comm.read_vec3(rc + best_loc)
                    nz_f = sum(1 for v in flt if abs(v) > 1.0)
                    if nz_f >= 2:
                        multi_axis += 1
                break

            fmt_str = "DOUBLES (UE5 LWC)" if is_doubles else "FLOATS"
            print(f"\n  [+] FOUND: RootComponent=Actor+0x{best_rc:X}, Location=Root+0x{best_loc:X} [{fmt_str}]")
            # Only override Pawn offsets if we have solid evidence (5+ verified with 2+ axes)
            OFFSETS['RootComponent'] = best_rc
            OFFSETS['RelativeLocation'] = best_loc
            OFFSETS['use_doubles'] = 1 if is_doubles else 0

            # Now verify with a few actors and print their locations
            print("\n  Verifying with sample actors:")
            verified = 0
            for idx, actor in non_null_actors[:200]:
                rc = comm.read_u64(actor + best_rc)
                if rc < 0x10000 or rc > 0x7FFFFFFFFFFF:
                    continue
                if base and base <= rc < img_end:
                    continue
                if is_doubles:
                    loc = comm.read_vec3d(rc + best_loc)
                else:
                    loc = comm.read_vec3(rc + best_loc)
                mc = max(abs(loc[0]), abs(loc[1]), abs(loc[2]))
                if mc > 50 and mc < 5e6:
                    verified += 1
                    if verified <= 8:
                        print(f"    Actor[{idx}] 0x{actor:x}: ({loc[0]:.0f}, {loc[1]:.0f}, {loc[2]:.0f})")
            print(f"  Total verified: {verified}/{min(200, len(non_null_actors))}")

            # Step 4: Find PlayerState offset
            print("\n  Scanning for PlayerState + PlayerName...")
            ps_hits = {}
            name_hits = {}
            for idx, actor in non_null_actors[:100]:
                actor_data = comm.read(actor, 0x500)
                if len(actor_data) < 0x500:
                    continue
                for ps_off in range(0x200, 0x500, 8):
                    ps = struct.unpack_from('<Q', actor_data, ps_off)[0]
                    if ps < 0x10000 or ps > 0x7FFFFFFFFFFF:
                        continue
                    if base and base <= ps < img_end:
                        continue
                    if ps == actor:
                        continue
                    # Try reading PlayerName at various offsets in this "PlayerState"
                    for name_off in [0x440, 0x370, 0x3A0, 0x3B0, 0x3C0, 0x450, 0x460, 0x330, 0x340, 0x350]:
                        name = comm.read_fstring(ps + name_off)
                        if name and len(name) >= 3 and len(name) <= 32 and all(c.isalnum() or c in '_ -.' for c in name):
                            key = (ps_off, name_off)
                            name_hits[key] = name_hits.get(key, 0) + 1
                            if name_hits[key] <= 2:
                                print(f"    Actor[{idx}] PS@+0x{ps_off:X} Name@+0x{name_off:X} = '{name}'")
                            break

            if name_hits:
                sorted_names = sorted(name_hits.items(), key=lambda x: -x[1])
                best_ps, best_name = sorted_names[0][0]
                best_name_count = sorted_names[0][1]
                print(f"\n  Top PlayerState+Name combos:")
                for (ps_off, name_off), count in sorted_names[:5]:
                    print(f"    Actor+0x{ps_off:X} -> PS+0x{name_off:X}: {count} hits")
                if best_name_count >= 2:
                    print(f"\n  [+] FOUND: PlayerState=Actor+0x{best_ps:X}, PlayerName=PS+0x{best_name:X}")
                    OFFSETS['PlayerState'] = best_ps
                    OFFSETS['PlayerName'] = best_name
            else:
                print("  [!] No PlayerName patterns found")
    else:
        print("  [!] No valid RootComponent+Location found anywhere!")
        print("  Dumping raw actor data for manual inspection...")
        for idx, actor in test_actors[:3]:
            actor_data = comm.read(actor, 0x300)
            print(f"\n  Actor[{idx}] @ 0x{actor:x}:")
            for off in range(0, 0x300, 8):
                val = struct.unpack_from('<Q', actor_data, off)[0]
                if val > 0x10000 and val < 0x7FFFFFFFFFFF:
                    in_mod = " [MODULE]" if (base and base <= val < img_end) else " [HEAP]"
                    print(f"    +0x{off:03X}: 0x{val:016X}{in_mod}")

    print("=== END DEEP SCAN ===\n")


def dump_actor_layout(comm, radar):
    """Dump a few heap actors to discover actual struct offsets"""
    if not radar.gworld:
        return

    level = comm.read_u64(radar.gworld + OFFSETS['PersistentLevel'])
    if level < 0x10000:
        return

    actors_ptr = comm.read_u64(level + OFFSETS['AActors'])
    actor_count = comm.read_i32(level + OFFSETS['ActorCount'])
    if actors_ptr < 0x10000 or actor_count <= 0:
        return

    base = comm.base
    max_scan = min(actor_count, 2000)
    raw = comm.read(actors_ptr, max_scan * 8)

    print("=== DUMP ACTOR LAYOUT ===")

    dumped = 0
    for i in range(max_scan):
        actor = struct.unpack_from('<Q', raw, i * 8)[0]
        if actor < 0x10000 or actor == actors_ptr:
            continue
        if base and base <= actor < base + 0x10000000:
            continue

        # Read first 0x500 bytes of this actor
        actor_data = comm.read(actor, 0x500)
        if len(actor_data) < 0x500:
            continue

        # Find all valid heap pointers in this actor
        ptrs = []
        for off in range(0, 0x500, 8):
            val = struct.unpack_from('<Q', actor_data, off)[0]
            if 0x10000 < val < 0x7FFFFFFFFFFF:
                ptrs.append((off, val))

        if len(ptrs) < 5:
            continue  # Not a real actor object

        print(f"\n  Actor[{i}] @ 0x{actor:x} ({len(ptrs)} pointers)")

        # Check if any pointer at common RootComponent offsets has a SceneComponent
        for root_off in [0x190, 0x1F0, 0x228, 0x230, 0x238, 0x240, 0x250, 0x258]:
            root_val = struct.unpack_from('<Q', actor_data, root_off)[0]
            if root_val < 0x10000 or root_val > 0x7FFFFFFFFFFF:
                continue
            if base and base <= root_val < base + 0x10000000:
                continue
            # Check if this has a RelativeLocation with reasonable coords
            for loc_off in [0x158, 0x1F8, 0x1E0, 0x210, 0x120, 0x130, 0x140]:
                loc_data = comm.read(root_val + loc_off, 12)
                x, y, z = struct.unpack('<fff', loc_data)
                if abs(x) > 1 and abs(x) < 1e7 and abs(y) > 1 and abs(y) < 1e7 and abs(z) < 1e7:
                    print(f"    RootComponent @ Actor+0x{root_off:x} = 0x{root_val:x}")
                    print(f"      RelativeLocation @ Root+0x{loc_off:x} = ({x:.0f}, {y:.0f}, {z:.0f})")
                    break

        # Check for PlayerState at various offsets
        for ps_off in [0x298, 0x3C8, 0x340, 0x358, 0x368, 0x3B0, 0x2A0, 0x2A8]:
            ps_val = struct.unpack_from('<Q', actor_data, ps_off)[0]
            if ps_val < 0x10000 or ps_val > 0x7FFFFFFFFFFF:
                continue
            if base and base <= ps_val < base + 0x10000000:
                continue
            # Check if PlayerState has a PlayerName at 0x440
            name = comm.read_fstring(ps_val + 0x440)
            if name and len(name) > 1 and all(c.isalnum() or c in '_ -' for c in name):
                print(f"    PlayerState @ Actor+0x{ps_off:x} = 0x{ps_val:x}")
                print(f"      PlayerName @ PS+0x440 = '{name}'")
                break

        dumped += 1
        if dumped >= 5:
            break

    print("=== END DUMP ===\n")


class Radar:
    """Radar principal — lit les positions via le driver"""

    def __init__(self, comm, base_addr):
        self.comm = comm
        self.base = base_addr
        self.gworld = None
        self.local_pos = (0, 0, 0)
        self.local_yaw = 0
        self.players = []
        self._gworld_logged = False

    @staticmethod
    def _decrypt_gworld(encrypted):
        """Try to decrypt GWorld pointer using known Theia obfuscation methods.
        Arc Raiders uses ROL4 + XOR on GWorld pointer."""
        def rol32(val, n):
            """Rotate left 32-bit"""
            val &= 0xFFFFFFFF
            return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

        def ror32(val, n):
            """Rotate right 32-bit (inverse of ROL)"""
            val &= 0xFFFFFFFF
            return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF

        # Known XOR keys from UC reversal notes
        xor_keys = [
            0x1B7112D299F8028D,
            0xD8AABB54B36CB2F,
            0x0,  # No encryption
        ]

        candidates = []
        for key in xor_keys:
            # Method 1: Simple XOR
            dec = encrypted ^ key
            if 0x10000000000 < dec < 0x7FFFFFFFFFFF:
                candidates.append(('XOR', key, dec))

            # Method 2: XOR then ROR4 on each 32-bit half
            xored = encrypted ^ key
            lo = ror32(xored & 0xFFFFFFFF, 4)
            hi = ror32((xored >> 32) & 0xFFFFFFFF, 4)
            dec = (hi << 32) | lo
            if 0x10000000000 < dec < 0x7FFFFFFFFFFF:
                candidates.append(('XOR+ROR4', key, dec))

            # Method 3: ROL4 on each 32-bit half then XOR
            lo = rol32(encrypted & 0xFFFFFFFF, 4)
            hi = rol32((encrypted >> 32) & 0xFFFFFFFF, 4)
            rolled = (hi << 32) | lo
            dec = rolled ^ key
            if 0x10000000000 < dec < 0x7FFFFFFFFFFF:
                candidates.append(('ROL4+XOR', key, dec))

        return candidates

    def update_gworld(self):
        gworld_addr = self.base + OFFSETS['GWorld']

        # Lecture directe (pointeur simple)
        direct = self.comm.read_u64(gworld_addr)

        if not self._gworld_logged:
            print(f"    [DBG] GWorld raw @ 0x{gworld_addr:x} = 0x{direct:x}")

            # Check if direct pointer has valid UWorld vtable (MODULE range)
            if 0x10000000000 < direct < 0x7FFFFFFFFFFF:
                vt = self.comm.read_u64(direct)
                if self.base and self.base <= vt < self.base + 0x10000000:
                    print(f"    [DBG] GWorld vtable: 0x{vt:x} [MODULE] ✓ — no decryption needed")
                    self.gworld = direct
                    self._gworld_logged = True
                    return True
                else:
                    print(f"    [DBG] GWorld vtable: 0x{vt:x} [NOT MODULE] — trying decryption...")

            # Try decryption
            candidates = self._decrypt_gworld(direct)
            for method, key, dec in candidates:
                vt = self.comm.read_u64(dec)
                is_module = self.base and self.base <= vt < self.base + 0x10000000
                tag = "[MODULE] ✓" if is_module else "[HEAP]"
                print(f"    [DBG] Decrypt {method} key=0x{key:x}: 0x{dec:x} vt=0x{vt:x} {tag}")
                if is_module:
                    print(f"    [DBG] *** DECRYPTED GWorld: 0x{dec:x} ***")
                    self.gworld = dec
                    self._gworld_logged = True
                    return True

            # Fallback: use direct even without MODULE vtable
            if 0x10000 < direct < 0x7FFFFFFFFFFF:
                print(f"    [DBG] Using raw GWorld (no decryption worked): 0x{direct:x}")
                self.gworld = direct
                self._gworld_logged = True
                return True

            self._gworld_logged = True

        elif self.gworld:
            # Fast path for subsequent calls
            new = self.comm.read_u64(gworld_addr)
            if 0x10000 < new < 0x7FFFFFFFFFFF:
                # Quick check: if same as before, reuse
                if new == self.gworld:
                    return True
                # Try to decrypt if needed
                vt = self.comm.read_u64(new)
                if self.base and self.base <= vt < self.base + 0x10000000:
                    self.gworld = new
                    return True
                # Try decryption on new value
                candidates = self._decrypt_gworld(new)
                for method, key, dec in candidates:
                    vt2 = self.comm.read_u64(dec)
                    if self.base and self.base <= vt2 < self.base + 0x10000000:
                        self.gworld = dec
                        return True
                # Fallback
                self.gworld = new
                return True
            return True  # Keep old gworld

        self.gworld = None
        return False

    def get_persistent_level(self):
        if not self.gworld:
            return None
        return self.comm.read_u64(self.gworld + OFFSETS['PersistentLevel'])

    def get_actors(self):
        level = self.get_persistent_level()
        if not level or level < 0x10000:
            return [], 0

        actors_ptr = self.comm.read_u64(level + OFFSETS['AActors'])
        actor_count = self.comm.read_i32(level + OFFSETS['ActorCount'])

        if actors_ptr < 0x10000 or actor_count <= 0 or actor_count > 100000:
            return [], 0

        # Limit read to 64KB max (8192 actors), read in chunks if more
        max_per_read = DATA_BUF_SIZE // 8
        read_count = min(actor_count, max_per_read)
        raw = self.comm.read(actors_ptr, read_count * 8)
        actors = []
        for i in range(read_count):
            ptr = struct.unpack_from('<Q', raw, i * 8)[0]
            if ptr > 0x10000:
                actors.append(ptr)

        return actors, actor_count

    def get_actor_location(self, actor):
        root = self.comm.read_u64(actor + OFFSETS['RootComponent'])
        if root < 0x10000:
            return None
        if OFFSETS.get('use_doubles'):
            return self.comm.read_vec3d(root + OFFSETS['RelativeLocation'])
        return self.comm.read_vec3(root + OFFSETS['RelativeLocation'])

    def _find_camera_manager_offset(self, player_controller):
        """Probe PlayerController to find PlayerCameraManager offset.
        Scans for a pointer that looks like a valid PCM (has reasonable FOV)."""
        if hasattr(self, '_pcm_offset') and self._pcm_offset:
            return self._pcm_offset

        # Read a big chunk of the PlayerController object
        raw = self.comm.read(player_controller + 0x440, 0x300)
        if len(raw) < 0x300:
            return None

        for i in range(0, 0x300, 8):
            ptr = struct.unpack_from('<Q', raw, i)[0]
            if ptr < 0x10000 or ptr > 0x7FFFFFFFFFFF:
                continue

            # Check if ptr+ViewTarget+POV+FOV gives a reasonable FOV value
            fov = self.comm.read_float(ptr + OFFSETS['ViewTarget'] + 0x10 + 0x58)
            if 20.0 < fov < 170.0:
                offset = 0x440 + i
                print(f"    [PROBE] PlayerCameraManager trouvé à PC+0x{offset:X} (FOV={fov:.1f})")
                self._pcm_offset = offset
                return offset

        return None

    def get_local_camera(self):
        if not self.gworld:
            return None, None, None

        game_instance = self.comm.read_u64(self.gworld + OFFSETS['OwningGameInstance'])
        if game_instance < 0x10000:
            return None, None, None

        local_players_ptr = self.comm.read_u64(game_instance + OFFSETS['LocalPlayers'])
        if local_players_ptr < 0x10000:
            return None, None, None

        local_player = self.comm.read_u64(local_players_ptr)
        if local_player < 0x10000:
            return None, None, None

        player_controller = self.comm.read_u64(local_player + OFFSETS['PlayerController'])
        if player_controller < 0x10000:
            return None, None, None

        # Get local pawn position via ControllerPawn
        pawn = self.comm.read_u64(player_controller + OFFSETS['ControllerPawn'])
        location = None
        if pawn > 0x10000:
            pawn_rc = OFFSETS.get('PawnRootComponent', OFFSETS['RootComponent'])
            pawn_loc = OFFSETS.get('PawnRelativeLocation', OFFSETS['RelativeLocation'])
            root = self.comm.read_u64(pawn + pawn_rc)
            if root > 0x10000:
                if OFFSETS.get('use_doubles'):
                    location = self.comm.read_vec3d(root + pawn_loc)
                else:
                    location = self.comm.read_vec3(root + pawn_loc)

        # Get rotation from PlayerController ControlRotation
        cr = OFFSETS.get('ControlRotation', 0xA78)
        rotation = self.comm.read_vec3(player_controller + cr)

        # Try PlayerCameraManager for location/rotation/FOV
        fov = 90.0
        pcm = self.comm.read_u64(player_controller + OFFSETS['PlayerCameraManager'])
        if pcm > 0x10000:
            # CameraCachePrivate (0x408) contains POV: Location(+0x10), Rotation(+0x28), FOV(+0x40)
            cc = OFFSETS.get('CameraCachePrivate', 0x408)
            cam_loc = self.comm.read_vec3(pcm + cc + 0x10)
            cam_rot = self.comm.read_vec3(pcm + cc + 0x28)
            cam_fov = self.comm.read_float(pcm + cc + 0x40)
            if abs(cam_loc[0]) > 1 and abs(cam_loc[0]) < 5e6:
                location = cam_loc
            if abs(cam_rot[1]) <= 360:
                rotation = cam_rot
            if 20.0 < cam_fov < 170.0:
                fov = cam_fov

        return location, rotation, fov

    def is_player_actor(self, actor):
        # Skip static/CDO objects (within module address range)
        if self.base and self.base <= actor < self.base + 0x10000000:
            return False
        player_state = self.comm.read_u64(actor + OFFSETS['PlayerState'])
        if player_state < 0x10000 or player_state > 0x7FFFFFFFFFFF:
            return False
        # PlayerState should also be a heap object
        if self.base and self.base <= player_state < self.base + 0x10000000:
            return False
        return True

    def get_player_name(self, actor):
        player_state = self.comm.read_u64(actor + OFFSETS['PlayerState'])
        if player_state < 0x10000:
            return '?'
        return self.comm.read_fstring(player_state + OFFSETS['PlayerName'])

    def debug_chain(self):
        """Debug: scan actors for real players and test offset chain"""
        print("\n=== DEBUG CHAIN ===")
        if not self.gworld:
            print("  GWorld: None")
            return

        print(f"  GWorld: 0x{self.gworld:x}")
        level = self.comm.read_u64(self.gworld + OFFSETS['PersistentLevel'])
        print(f"  PersistentLevel (GWorld+0x{OFFSETS['PersistentLevel']:x}): 0x{level:x}")

        if level < 0x10000:
            print("  [!] PersistentLevel invalide")
            return

        actors_ptr = self.comm.read_u64(level + OFFSETS['AActors'])
        actor_count = self.comm.read_i32(level + OFFSETS['ActorCount'])
        print(f"  ActorArray (Level+0x{OFFSETS['AActors']:x}): 0x{actors_ptr:x}")
        print(f"  ActorCount: {actor_count}")

        if actors_ptr < 0x10000 or actor_count <= 0:
            return

        # Scan actors in batches, skip module-range objects
        print(f"\n  Scan acteurs (skip module range 0x{self.base:x})...")
        heap_actors = 0
        players_found = 0
        max_scan = min(actor_count, 8192)
        raw = self.comm.read(actors_ptr, max_scan * 8)

        for i in range(max_scan):
            actor = struct.unpack_from('<Q', raw, i * 8)[0]
            if actor < 0x10000:
                continue
            # Skip module-range CDOs
            if self.base and self.base <= actor < self.base + 0x10000000:
                continue
            heap_actors += 1

            # Try PlayerState at current offset
            ps = self.comm.read_u64(actor + OFFSETS['PlayerState'])
            if ps < 0x10000 or ps > 0x7FFFFFFFFFFF:
                continue
            if self.base and self.base <= ps < self.base + 0x10000000:
                continue

            players_found += 1
            # Read location via RootComponent → RelativeLocation
            root = self.comm.read_u64(actor + OFFSETS['RootComponent'])
            loc_str = "N/A"
            if root > 0x10000 and (not self.base or not (self.base <= root < self.base + 0x10000000)):
                loc = self.comm.read_vec3(root + OFFSETS['RelativeLocation'])
                loc_str = f"({loc[0]:.0f}, {loc[1]:.0f}, {loc[2]:.0f})"

            # Read player name
            name = self.comm.read_fstring(ps + OFFSETS['PlayerName'])

            if players_found <= 5:
                print(f"  Player[{players_found}] Actor=0x{actor:x} PS=0x{ps:x}")
                print(f"    Name: '{name}' Loc: {loc_str}")

        print(f"\n  Total: {heap_actors} heap actors, {players_found} avec PlayerState")

        # Debug camera chain
        print("\n  --- Camera Chain ---")
        gi = self.comm.read_u64(self.gworld + OFFSETS['OwningGameInstance'])
        print(f"  GameInstance (UWorld+0x{OFFSETS['OwningGameInstance']:x}): 0x{gi:x}")
        if gi > 0x10000:
            lp_ptr = self.comm.read_u64(gi + OFFSETS['LocalPlayers'])
            lp_count = self.comm.read_i32(gi + OFFSETS['LocalPlayers'] + 8)
            print(f"  LocalPlayers (GI+0x{OFFSETS['LocalPlayers']:x}): ptr=0x{lp_ptr:x} count={lp_count}")
            if lp_ptr > 0x10000 and lp_count > 0:
                lp0 = self.comm.read_u64(lp_ptr)
                print(f"  LocalPlayer[0]: 0x{lp0:x}")
                if lp0 > 0x10000:
                    pc = self.comm.read_u64(lp0 + OFFSETS['PlayerController'])
                    print(f"  PlayerController (LP+0x{OFFSETS['PlayerController']:x}): 0x{pc:x}")
                    if pc > 0x10000:
                        pawn = self.comm.read_u64(pc + OFFSETS['ControllerPawn'])
                        print(f"  Pawn (PC+0x{OFFSETS['ControllerPawn']:x}): 0x{pawn:x}")
                        pcm = self.comm.read_u64(pc + OFFSETS['PlayerCameraManager'])
                        print(f"  CameraManager (PC+0x{OFFSETS['PlayerCameraManager']:x}): 0x{pcm:x}")
                        cr = self.comm.read_vec3(pc + OFFSETS['ControlRotation'])
                        print(f"  ControlRotation: Pitch={cr[0]:.1f} Yaw={cr[1]:.1f} Roll={cr[2]:.1f}")
                        if pawn > 0x10000:
                            # Use Pawn-specific offsets if available
                            pawn_rc_off = OFFSETS.get('PawnRootComponent', OFFSETS['RootComponent'])
                            pawn_loc_off = OFFSETS.get('PawnRelativeLocation', OFFSETS['RelativeLocation'])
                            root = self.comm.read_u64(pawn + pawn_rc_off)
                            loc = (0.0, 0.0, 0.0)
                            if root > 0x10000:
                                if OFFSETS.get('use_doubles'):
                                    loc = self.comm.read_vec3d(root + pawn_loc_off)
                                else:
                                    loc = self.comm.read_vec3(root + pawn_loc_off)
                                print(f"  Local Pawn Pos (RC=+0x{pawn_rc_off:X} Loc=+0x{pawn_loc_off:X}): ({loc[0]:.0f}, {loc[1]:.0f}, {loc[2]:.0f})")

                            # If position is (0,0,0), brute-force scan the Pawn for real RootComponent
                            if not root or root < 0x10000 or (abs(loc[0]) < 1 and abs(loc[1]) < 1):
                                print(f"\n  --- Pawn RootComponent scan (0x{pawn:x}) ---")
                                pawn_data = self.comm.read(pawn, 0x600)
                                found_pawn_loc = False
                                for rc_off in range(0x100, 0x600, 8):
                                    rc_val = struct.unpack_from('<Q', pawn_data, rc_off)[0]
                                    if rc_val < 0x10000 or rc_val > 0x7FFFFFFFFFFF:
                                        continue
                                    if self.base and self.base <= rc_val < self.base + 0x10000000:
                                        continue
                                    if rc_val == pawn or rc_val == pc:
                                        continue
                                    sc_data = self.comm.read(rc_val, 0x400)
                                    if len(sc_data) < 0x400:
                                        continue
                                    # Try DOUBLES first (UE5 LWC)
                                    for loc_off in range(0x100, 0x3E8, 8):
                                        if loc_off + 24 > len(sc_data):
                                            break
                                        x, y, z = struct.unpack_from('<ddd', sc_data, loc_off)
                                        mc = max(abs(x), abs(y), abs(z))
                                        if (mc > 100 and mc < 5e6 and
                                            not math.isinf(x) and not math.isnan(x)):
                                            print(f"    Pawn+0x{rc_off:X} -> Root+0x{loc_off:X}: ({x:.0f}, {y:.0f}, {z:.0f}) [DOUBLE]")
                                            if not found_pawn_loc:
                                                OFFSETS['RootComponent'] = rc_off
                                                OFFSETS['RelativeLocation'] = loc_off
                                                OFFSETS['use_doubles'] = 1
                                                found_pawn_loc = True
                                            break
                                    if found_pawn_loc:
                                        break
                                    # Try FLOATS
                                    for loc_off in range(0x100, 0x400, 4):
                                        if loc_off + 12 > len(sc_data):
                                            break
                                        x, y, z = struct.unpack_from('<fff', sc_data, loc_off)
                                        mc = max(abs(x), abs(y), abs(z))
                                        if (mc > 100 and mc < 5e6 and
                                            not math.isinf(x) and not math.isnan(x)):
                                            print(f"    Pawn+0x{rc_off:X} -> Root+0x{loc_off:X}: ({x:.0f}, {y:.0f}, {z:.0f}) [FLOAT]")
                                            if not found_pawn_loc:
                                                OFFSETS['RootComponent'] = rc_off
                                                OFFSETS['RelativeLocation'] = loc_off
                                                found_pawn_loc = True
                                            break
                                    if found_pawn_loc:
                                        break
                                if not found_pawn_loc:
                                    print("    No valid Pawn location found")

                        # Scan for ControlRotation in PC
                        print(f"\n  --- ControlRotation scan (PC 0x{pc:x}) ---")
                        pc_data = self.comm.read(pc, 0xE00)
                        cr_found = False
                        for poff in range(0x300, min(0xD00, len(pc_data) - 12), 4):
                            p, y_rot, r = struct.unpack_from('<fff', pc_data, poff)
                            if (abs(p) < 90 and abs(y_rot) < 360 and abs(r) < 90 and
                                (abs(p) > 0.5 or abs(y_rot) > 0.5) and
                                not math.isinf(p) and not math.isnan(p)):
                                print(f"    PC+0x{poff:03X}: P={p:.2f} Y={y_rot:.2f} R={r:.2f}")
                                if not cr_found:
                                    OFFSETS['ControlRotation'] = poff
                                    cr_found = True

                        # Scan for CameraManager (look for a pointer to object with valid FOV)
                        print(f"\n  --- CameraManager scan (PC 0x{pc:x}) ---")
                        for pcm_off in range(0x300, min(0x800, len(pc_data) - 8), 8):
                            pcm_val = struct.unpack_from('<Q', pc_data, pcm_off)[0]
                            if pcm_val < 0x10000 or pcm_val > 0x7FFFFFFFFFFF:
                                continue
                            if self.base and self.base <= pcm_val < self.base + 0x10000000:
                                continue
                            if pcm_val == pc or pcm_val == pawn:
                                continue
                            # Check FOV at known ViewTarget offsets
                            for vt_off in [0x2EC, 0x2FC, 0x30C, 0x31C, 0x32C, 0x33C, 0x2BC]:
                                fov_data = self.comm.read(pcm_val + vt_off, 4)
                                fov = struct.unpack_from('<f', fov_data, 0)[0]
                                if 20.0 < fov < 170.0:
                                    print(f"    PC+0x{pcm_off:X} -> PCM+0x{vt_off:X} FOV={fov:.1f}")
                                    OFFSETS['PlayerCameraManager'] = pcm_off
                                    break

        print("=== END DEBUG ===\n")

    def update(self):
        if not self.update_gworld():
            return False

        cam_loc, cam_rot, cam_fov = self.get_local_camera()
        if cam_loc:
            self.local_pos = cam_loc
        if cam_rot:
            self.local_yaw = cam_rot[1]

        actors, count = self.get_actors()
        self.players = []

        for actor in actors:
            if not self.is_player_actor(actor):
                continue

            loc = self.get_actor_location(actor)
            if loc is None:
                continue

            name = self.get_player_name(actor)
            dx = loc[0] - self.local_pos[0]
            dy = loc[1] - self.local_pos[1]
            dz = loc[2] - self.local_pos[2]
            dist = math.sqrt(dx*dx + dy*dy + dz*dz) / 100

            self.players.append({
                'name': name,
                'pos': loc,
                'dist': dist,
                'dx': dx,
                'dy': dy,
                'dz': dz,
            })

        return True


# === WEB RADAR ===

RADAR_HTML = '''<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Arc Raiders Radar</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a0a; color: #0f0; font-family: 'Consolas', monospace; overflow: hidden; }
canvas { display: block; margin: 20px auto; }
#hud { text-align: center; padding: 10px; font-size: 14px; }
#players { position: fixed; right: 10px; top: 10px; width: 280px; background: rgba(0,20,0,0.8);
  border: 1px solid #0f0; padding: 10px; font-size: 12px; max-height: 90vh; overflow-y: auto; }
.player-entry { padding: 3px 0; border-bottom: 1px solid #030; }
.dist { color: #ff0; float: right; }
#status { position: fixed; left: 10px; top: 10px; font-size: 12px; color: #0a0; }
</style></head><body>
<div id="status">Connecting...</div>
<div id="hud">ARC RAIDERS RADAR</div>
<canvas id="radar" width="600" height="600"></canvas>
<div id="players"></div>
<script>
const canvas = document.getElementById('radar');
const ctx = canvas.getContext('2d');
const W = canvas.width, H = canvas.height;
const CX = W/2, CY = H/2;
let radarRadius = 150;
let data = { players: [], local_pos: [0,0,0], local_yaw: 0 };

function drawRadar() {
  ctx.fillStyle = '#0a0a0a';
  ctx.fillRect(0, 0, W, H);
  ctx.strokeStyle = '#0a2a0a'; ctx.lineWidth = 1;
  for (let r = 1; r <= 4; r++) {
    ctx.beginPath();
    ctx.arc(CX, CY, (r/4) * (W/2 - 20), 0, Math.PI * 2);
    ctx.stroke();
    ctx.fillStyle = '#0a3a0a'; ctx.font = '10px Consolas';
    ctx.fillText(Math.round(radarRadius * r / 4) + 'm', CX + 4, CY - (r/4) * (W/2 - 20) + 12);
  }
  ctx.strokeStyle = '#0a2a0a'; ctx.beginPath();
  ctx.moveTo(CX, 20); ctx.lineTo(CX, H-20);
  ctx.moveTo(20, CY); ctx.lineTo(W-20, CY); ctx.stroke();

  ctx.fillStyle = '#0f0'; ctx.beginPath();
  ctx.arc(CX, CY, 5, 0, Math.PI * 2); ctx.fill();
  ctx.beginPath(); ctx.moveTo(CX, CY - 12);
  ctx.lineTo(CX - 5, CY - 2); ctx.lineTo(CX + 5, CY - 2);
  ctx.closePath(); ctx.fill();

  let yawRad = -data.local_yaw * Math.PI / 180;
  let scale = (W/2 - 20) / (radarRadius * 100);
  let cos_y = Math.cos(yawRad), sin_y = Math.sin(yawRad);
  let playerList = '';

  data.players.forEach((p, i) => {
    if (p.dist < 1) return;
    let rx = p.dx * cos_y - p.dy * sin_y;
    let ry = p.dx * sin_y + p.dy * cos_y;
    let px = CX + rx * scale, py = CY - ry * scale;
    let fromCenter = Math.sqrt((px-CX)**2 + (py-CY)**2);
    let maxR = W/2 - 25, onEdge = false;
    if (fromCenter > maxR) {
      px = CX + (px-CX) * maxR / fromCenter;
      py = CY + (py-CY) * maxR / fromCenter;
      onEdge = true;
    }
    let color = p.dist < 30 ? '#f00' : p.dist < 80 ? '#ff0' : '#0f0';
    if (onEdge) color = '#666';
    ctx.fillStyle = color; ctx.beginPath();
    ctx.arc(px, py, onEdge ? 3 : 5, 0, Math.PI * 2); ctx.fill();
    ctx.font = '10px Consolas'; ctx.textAlign = 'center';
    let label = p.name || ('P' + i);
    if (label.length > 12) label = label.substring(0, 12);
    ctx.fillText(label, px, py - 8);
    let dz = p.dz / 100;
    if (Math.abs(dz) > 2) ctx.fillText(dz > 0 ? '▲' : '▼', px + 15, py + 4);
    playerList += '<div class="player-entry">' + (p.name||'?') +
      '<span class="dist">' + Math.round(p.dist) + 'm</span></div>';
  });

  document.getElementById('players').innerHTML =
    '<b>Players (' + data.players.filter(p => p.dist >= 1).length + ')</b><br>' + playerList;
  ctx.textAlign = 'left';
  document.getElementById('hud').textContent =
    'ARC RAIDERS RADAR | Radius: ' + radarRadius + 'm | ' +
    'Pos: (' + data.local_pos.map(v => Math.round(v)).join(', ') + ')';
}

function connect() {
  const es = new EventSource('/stream');
  es.onmessage = function(e) {
    data = JSON.parse(e.data);
    drawRadar();
    document.getElementById('status').textContent = 'Connected | ' + new Date().toLocaleTimeString();
  };
  es.onerror = function() {
    document.getElementById('status').textContent = 'Disconnected - reconnecting...';
    es.close(); setTimeout(connect, 2000);
  };
}
canvas.addEventListener('wheel', function(e) {
  e.preventDefault();
  radarRadius = Math.max(20, Math.min(500, radarRadius + (e.deltaY > 0 ? 10 : -10)));
});
connect(); drawRadar();
</script></body></html>'''


class RadarHTTPHandler(SimpleHTTPRequestHandler):
    radar_data = {'players': [], 'local_pos': [0, 0, 0], 'local_yaw': 0}
    clients = []

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(RADAR_HTML.encode())
        elif self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            RadarHTTPHandler.clients.append(self.wfile)
            try:
                while True:
                    time.sleep(60)
            except:
                pass
            finally:
                if self.wfile in RadarHTTPHandler.clients:
                    RadarHTTPHandler.clients.remove(self.wfile)
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass

    @classmethod
    def broadcast(cls, data):
        msg = f"data: {json.dumps(data)}\n\n"
        dead = []
        for client in cls.clients:
            try:
                client.write(msg.encode())
                client.flush()
            except:
                dead.append(client)
        for d in dead:
            cls.clients.remove(d)


def start_web_server(port=8888):
    server = HTTPServer(('0.0.0.0', port), RadarHTTPHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def find_game_pid():
    """Trouve le PID de PioneerGame via CreateToolhelp32Snapshot"""
    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE:
        return None

    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if kernel32.Process32First(snap, ctypes.byref(pe)):
        while True:
            name = pe.szExeFile.decode('utf-8', errors='ignore')
            if 'PioneerGame' in name or 'pioneer' in name.lower():
                pid = pe.th32ProcessID
                kernel32.CloseHandle(snap)
                return pid
            if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                break

    kernel32.CloseHandle(snap)
    return None


def main():
    print("=" * 50)
    print("  ARC RAIDERS RADAR v3.0 — Shared Memory")
    print("=" * 50)
    print()

    # Connexion au driver via shared memory
    print("[*] Connexion au driver CommDriver...")
    comm = DriverComm()
    try:
        comm.connect()
    except RuntimeError as e:
        print(f"[!] {e}")
        sys.exit(1)

    # Trouver le jeu
    target_pid = None
    for i, arg in enumerate(sys.argv):
        if arg == '--pid' and i + 1 < len(sys.argv):
            target_pid = int(sys.argv[i + 1])

    if target_pid:
        print(f"[*] PID forcé: {target_pid}")
        comm.pid = target_pid
        # Essayer de résoudre via le driver (pour avoir le CR3)
        # PsGetProcessImageFileName tronque à 15 chars
        found = False
        for name in ["PioneerGame.exe", "PioneerGame.ex"]:
            try:
                comm.find_process(name)
                found = True
                break
            except RuntimeError:
                continue
        if not found:
            print(f"[+] PID={target_pid} (forcé)")
    else:
        print("[*] Recherche de PioneerGame...")
        found = False
        for name in ["PioneerGame.exe", "PioneerGame.ex"]:
            try:
                comm.find_process(name)
                found = True
                break
            except RuntimeError:
                continue
        if not found:
            game_pid = find_game_pid()
            if game_pid:
                comm.pid = game_pid
                print(f"[+] PID={game_pid} (via snapshot)")
            else:
                print("[!] Jeu non trouvé! Lance Arc Raiders ou utilise --pid")
                sys.exit(1)

    # Trouver l'adresse de base
    print("[*] Recherche du module de base...")
    base = None

    # Méthode 1: NtQueryInformationProcess (usermode, fiable)
    try:
        ntdll = ctypes.windll.ntdll

        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p),
            ]

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, comm.pid)
        if handle:
            pbi = PROCESS_BASIC_INFORMATION()
            ret_len = ctypes.c_ulong(0)
            status = ntdll.NtQueryInformationProcess(
                handle, 0, ctypes.byref(pbi),
                ctypes.sizeof(pbi), ctypes.byref(ret_len)
            )
            kernel32.CloseHandle(handle)

            if status == 0 and pbi.PebBaseAddress:
                peb_addr = pbi.PebBaseAddress
                print(f"    PEB @ 0x{peb_addr:x} (via NtQueryInformationProcess)")
                raw = comm.read(peb_addr + 0x10, 8, debug=True)
                if len(raw) == 8:
                    image_base = struct.unpack('<Q', raw)[0]
                    print(f"    PEB.ImageBaseAddress = 0x{image_base:x}")
                    if image_base and image_base > 0x10000:
                        header = comm.read(image_base, 2)
                        if header == b'MZ':
                            base = image_base
                            print(f"[+] Base: 0x{base:x}")
                        else:
                            print(f"    ImageBase 0x{image_base:x} pas un PE valide")
                else:
                    print(f"    PEB read returned {len(raw)} bytes (expected 8)")
            else:
                print(f"    NtQueryInformationProcess échoué (0x{status & 0xFFFFFFFF:08x})")
        else:
            print(f"    OpenProcess échoué (erreur {kernel32.GetLastError()})")
    except Exception as e:
        print(f"    Erreur NtQuery: {e}")

    # Méthode 2: CMD_GET_PEB via driver (fallback, physical read)
    driver_image_base = None
    if base is None:
        print("    [*] Fallback: PEB via driver (physical read)...")
        peb, image_base = comm.get_peb_and_base()
        if peb and peb > 0x10000:
            print(f"    PEB @ 0x{peb:x} (via driver)")
            if image_base and image_base > 0x10000:
                driver_image_base = image_base
                print(f"    ImageBase = 0x{image_base:x}")
                header = comm.read(image_base, 2)
                if header == b'MZ':
                    base = image_base
                    print(f"[+] Base: 0x{base:x} (MZ validé)")
                else:
                    print(f"    ImageBase 0x{image_base:x} — MZ non lisible (header: {header.hex()})")
                    print(f"    [!] Le CR3 actuel ne peut PAS lire les pages user-mode (KVAS)")
                    print(f"    [!] As-tu chargé le NOUVEAU CommDriver.sys ?")
                    # Use the driver-reported ImageBase anyway — the address is correct,
                    # it's the CR3 that can't read through user page tables
                    base = image_base
                    print(f"    [*] Utilisation de ImageBase=0x{base:x} (confiance driver)")
            else:
                print(f"    ImageBase = 0x{image_base if image_base else 0:x} (invalide)")
        else:
            print(f"    PEB non trouvé")

    if base is None:
        print("[!] Base non trouvée, utilisation de l'offset par défaut")
        base = 0x140000000  # Default PE ImageBase 64-bit

    comm.base = base  # For module range checks in probes

    # === CR3 health check ===
    # Test if the CR3 can actually read user-mode pages
    cr3_can_read = False
    test_addr = base + 0x1000  # Just past the PE header
    test_data = comm.read(test_addr, 16)
    if test_data != b'\x00' * 16:
        cr3_can_read = True
        print(f"[+] CR3 0x{comm.cr3:x} peut lire les pages user ✓")
    else:
        # Try reading a few more spots to be sure
        for test_off in [0x0, 0x2000, 0x10000]:
            test_data = comm.read(base + test_off, 16)
            if test_data != b'\x00' * 16:
                cr3_can_read = True
                break
        if cr3_can_read:
            print(f"[+] CR3 0x{comm.cr3:x} peut lire les pages user ✓")
        else:
            print(f"[!] CR3 0x{comm.cr3:x} NE PEUT PAS lire les pages user-mode!")
            print(f"    Cause probable: KVAS (Kernel VA Shadow) sur Win11 24H2")
            print(f"    Le CR3 kernel (EPROCESS+0x28) ne mappe pas les pages utilisateur.")
            print(f"    → Charge le nouveau CommDriver.sys qui essaie UserDirectoryTableBase")
            print(f"    → Ou redémarre le PC et recharge le driver AVANT de lancer le jeu")

    # Démarrer le serveur web
    port = 8888
    start_web_server(port)
    print(f"[+] Radar web: http://localhost:{port}")

    # Créer le radar
    radar = Radar(comm, base)
    size_of_image = None
    sections = []

    if not radar.update_gworld():
        print("[!] GWorld non trouvé à l'offset connu — lancement du scan PE...")

        size_of_image, sections = get_pe_info(comm, base)
        if size_of_image:
            print(f"    Image size: 0x{size_of_image:x} ({size_of_image // (1024*1024)}MB)")
            for s in sections:
                print(f"    Section {s['name']:8s} RVA=0x{s['va']:08x} Size=0x{s['vsize']:08x}")

            gworld_rva = scan_for_gworld(comm, base, sections)
            if gworld_rva:
                OFFSETS['GWorld'] = gworld_rva
                radar._gworld_logged = False
                if radar.update_gworld():
                    print(f"[+] GWorld: 0x{radar.gworld:x}")
                else:
                    print("[!] GWorld scan trouvé mais lecture échouée")
            else:
                print("[!] Scan terminé — GWorld non trouvé")
                print("    Les offsets doivent être mis à jour manuellement")
        else:
            print("[!] Impossible de lire les headers PE")
    else:
        print(f"[+] GWorld: 0x{radar.gworld:x}")

    # Probe UWorld offsets — with lobby detection and polling
    if radar.gworld:
        probe_uworld_offsets(comm, radar.gworld)

        # Always run deep scan and debug — don't block on match detection
        dump_level_and_actors(comm, radar)
        radar.debug_chain()

        # Also search for TArray<ULevel*> (all loaded levels) to find match level
        print("\n=== SEARCHING ALL LOADED LEVELS ===")
        find_all_levels(comm, radar.gworld, base)

    print()
    print("[*] Radar actif (Ctrl+C pour arrêter)")
    print(f"    Ouvre http://localhost:{port}")

    # Store PE info for re-scan
    if not size_of_image:
        size_of_image, sections = get_pe_info(comm, base)

    last_rescan = time.time()
    fail_count = 0

    try:
        while True:
            if radar.update():
                fail_count = 0
                RadarHTTPHandler.broadcast({
                    'players': radar.players,
                    'local_pos': list(radar.local_pos),
                    'local_yaw': radar.local_yaw,
                })
            else:
                fail_count += 1
                # Re-scan GWorld every 10s if not working
                if fail_count > 100 and time.time() - last_rescan > 10 and sections:
                    print("[*] Re-scan GWorld...")
                    radar._gworld_logged = False
                    gworld_rva = scan_for_gworld(comm, base, sections)
                    if gworld_rva and gworld_rva != OFFSETS['GWorld']:
                        OFFSETS['GWorld'] = gworld_rva
                        print(f"[+] Nouveau GWorld offset: 0x{gworld_rva:x}")
                    last_rescan = time.time()
                    fail_count = 0
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[*] Arrêt")
    finally:
        comm.close()


if __name__ == '__main__':
    main()
