"""
Scanner mémoire externe pour Arc Raiders.
Lit la mémoire du processus via ReadProcessMemory (pas d'injection).
Cherche les strings liées au matchmaking: manifestId, matchId, ticketId, secretKey.

Usage: lance le jeu normalement, queue pour un match, puis lance ce script.
"""

import ctypes
import ctypes.wintypes as wt
import sys
import os
import time
import json
import datetime
import re

# Windows API
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x06, 0x08, 0x20, 0x40, 0x80}  # PAGE_READONLY, READWRITE, WRITECOPY, EXECUTE_READ, etc.

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
LOG_DIR = os.path.join(DATA_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)


def find_game_pid():
    """Trouve le PID du jeu via tasklist"""
    import subprocess
    result = subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"],
        capture_output=True, text=True
    )
    for line in result.stdout.strip().split("\n"):
        parts = line.strip('"').split('","')
        if len(parts) >= 2:
            name = parts[0].lower()
            if "pioneergame" in name or ("arc" in name and "raid" in name):
                return int(parts[1]), parts[0]
    return None, None


def open_process(pid):
    """Ouvre le processus en lecture"""
    # Utiliser SetLastError version pour avoir les erreurs
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.SetLastError(0)
    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not handle:
        err = kernel32.GetLastError()
        print(f"[!] OpenProcess failed: error {err}")
        if err == 5:
            print("[!] ACCESS_DENIED - EAC bloque peut-être l'accès")
            print("[*] Essaie de lancer ce script en administrateur")
        return None
    print(f"[+] Handle obtenu: {handle}")
    return handle


def scan_memory_regions(handle):
    """Énumère les régions mémoire lisibles"""
    regions = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while addr < 0x7FFFFFFFFFFF:  # User-mode address space limit x64
        result = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if result == 0:
            break

        base_addr = mbi.BaseAddress or 0
        region_size = mbi.RegionSize or 0

        if (mbi.State == MEM_COMMIT and
            mbi.Protect in PAGE_READABLE and
            region_size > 0 and
            region_size < 1024 * 1024 * 1024):  # Skip > 1GB regions
            regions.append((base_addr, region_size))

        next_addr = base_addr + region_size
        if next_addr <= addr:
            addr += 0x10000  # Skip forward to avoid infinite loop
        else:
            addr = next_addr

    return regions


def read_region(handle, base, size):
    """Lit une région mémoire"""
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(base), buf, size, ctypes.byref(bytes_read)
    )
    if ok and bytes_read.value > 0:
        return buf.raw[:bytes_read.value]
    return None


_read_fail_count = 0
_read_ok_count = 0


# Patterns à chercher dans la mémoire
SEARCH_PATTERNS = [
    # JSON fields liés au matchmaking
    b'"manifestId"',
    b'"matchId"',
    b'"ticketId"',
    b'"secretKey"',
    b'"serverAddress"',
    b'"gameSessionId"',
    b'"allocationId"',
    b'"scenarioId"',
    b'"scenarioName"',
    # URLs API
    b'/v1/shared/match/start',
    b'/v1/shared/match/status',
    b'/v1/shared/gameserver/status',
    b'/v1/shared/gameserver/join',
    # Protobuf field names (gRPC-gateway transcoding)
    b'manifest_id',
    b'match_id',
    b'ticket_id',
    b'secret_key',
    b'server_address',
]

# Patterns pour extraire du contexte (regex sur bytes)
CONTEXT_PATTERNS = [
    # JSON avec manifestId
    re.compile(rb'"manifestId"\s*:\s*"([^"]{1,200})"'),
    # JSON avec matchId
    re.compile(rb'"matchId"\s*:\s*"([^"]{1,200})"'),
    # JSON avec ticketId
    re.compile(rb'"ticketId"\s*:\s*"([^"]{1,200})"'),
    # JSON avec secretKey
    re.compile(rb'"secretKey"\s*:\s*"([^"]{1,500})"'),
    # JSON avec serverAddress
    re.compile(rb'"serverAddress"\s*:\s*"([^"]{1,200})"'),
    # URL complète
    re.compile(rb'(https?://[a-zA-Z0-9._-]+\.es-pio\.net/[^\x00\s]{5,200})'),
    # HTTP request dans le buffer
    re.compile(rb'((?:POST|GET|PUT) /v1/shared/\S+ HTTP/\d\.\d)'),
]


def scan_for_patterns(handle, regions, patterns, context_size=512):
    """Scanne les régions mémoire pour trouver les patterns"""
    findings = []
    total_scanned = 0

    for base, size in regions:
        # Lire par chunks de 1MB avec overlap (plus petit = moins d'échecs)
        chunk_size = 1 * 1024 * 1024
        overlap = 512

        offset = 0
        while offset < size:
            read_size = min(chunk_size, size - offset)
            try:
                data = read_region(handle, base + offset, read_size)
            except Exception:
                offset += read_size
                continue
            if not data:
                # Essayer un chunk plus petit
                if read_size > 4096:
                    try:
                        data = read_region(handle, base + offset, 4096)
                    except Exception:
                        pass
                if not data:
                    offset += read_size
                    continue

            total_scanned += len(data)

            for pattern in patterns:
                pos = 0
                while True:
                    idx = data.find(pattern, pos)
                    if idx == -1:
                        break

                    # Extraire le contexte autour du match
                    ctx_start = max(0, idx - context_size)
                    ctx_end = min(len(data), idx + len(pattern) + context_size)
                    context = data[ctx_start:ctx_end]

                    addr = base + offset + idx

                    findings.append({
                        'pattern': pattern.decode('utf-8', errors='replace'),
                        'address': f'0x{addr:016X}',
                        'context_raw': context,
                    })

                    pos = idx + 1

            offset += read_size - overlap if read_size == chunk_size else read_size

    return findings, total_scanned


def extract_values(context_bytes):
    """Extrait les valeurs intéressantes du contexte"""
    values = {}
    for pat in CONTEXT_PATTERNS:
        for m in pat.finditer(context_bytes):
            try:
                key = pat.pattern.decode('utf-8', errors='replace')[:30]
                val = m.group(1).decode('utf-8', errors='replace')
                values[key] = val
            except:
                pass
    return values


def continuous_scan(pid, interval=3):
    """Scan continu - cherche les patterns en boucle"""
    handle = open_process(pid)
    if not handle:
        return

    print(f"[+] Process ouvert (PID: {pid})")
    print(f"[*] Scan mémoire toutes les {interval}s")
    print(f"[*] Cherche: manifestId, matchId, ticketId, secretKey, serverAddress")
    print(f"[*] Queue pour un match pour déclencher l'activité!")
    print(f"[*] Ctrl+C pour arrêter\n")

    log_file = os.path.join(LOG_DIR, f"memscan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
    seen_values = set()
    scan_count = 0

    try:
        while True:
            scan_count += 1
            ts = datetime.datetime.now().strftime("%H:%M:%S")

            # Ré-énumérer les régions (elles changent au fil du temps)
            regions = scan_memory_regions(handle)
            total_mem = sum(size for _, size in regions)

            # Premier scan: debug détaillé
            if scan_count == 1:
                print(f"[DEBUG] {len(regions)} régions, {total_mem/1024/1024:.0f} MB total")
                # Tester la lecture des premières régions
                read_ok = 0
                read_fail = 0
                fail_errors = {}
                for base, size in regions[:200]:
                    test_size = min(4096, size)
                    buf = ctypes.create_string_buffer(test_size)
                    br = ctypes.c_size_t(0)
                    ok = kernel32.ReadProcessMemory(
                        handle, ctypes.c_void_p(base), buf, test_size, ctypes.byref(br)
                    )
                    if ok and br.value > 0:
                        read_ok += 1
                    else:
                        read_fail += 1
                        err = kernel32.GetLastError()
                        fail_errors[err] = fail_errors.get(err, 0) + 1
                print(f"[DEBUG] Test 200 premières régions: {read_ok} OK, {read_fail} FAIL")
                if fail_errors:
                    print(f"[DEBUG] Erreurs: {fail_errors}")
                    # 299 = ERROR_PARTIAL_COPY (region pas entièrement lisible)
                    # 5 = ACCESS_DENIED
                    # 998 = ERROR_NOACCESS

                if read_ok == 0:
                    print("[!] Aucune région lisible! EAC protège probablement la mémoire.")
                    print("[*] On passe au plan B: proxy DLL")
                    break

            findings, scanned = scan_for_patterns(handle, regions, SEARCH_PATTERNS)

            # Extraire et afficher les nouvelles valeurs
            new_findings = []
            for f in findings:
                ctx = f['context_raw']
                values = extract_values(ctx)

                for key, val in values.items():
                    fingerprint = f"{key}:{val}"
                    if fingerprint not in seen_values:
                        seen_values.add(fingerprint)
                        new_findings.append({
                            'pattern': f['pattern'],
                            'address': f['address'],
                            'key': key,
                            'value': val,
                        })

                # Aussi chercher du JSON brut autour
                try:
                    text = ctx.decode('utf-8', errors='replace')
                    # Chercher des blocs JSON
                    for m in re.finditer(r'\{[^{}]{10,2000}\}', text):
                        json_str = m.group()
                        fingerprint = f"json:{json_str[:100]}"
                        if fingerprint not in seen_values:
                            try:
                                parsed = json.loads(json_str)
                                # Vérifier si c'est intéressant
                                interesting_keys = {'manifestId', 'matchId', 'ticketId',
                                                   'secretKey', 'serverAddress', 'allocationId',
                                                   'gameSessionId', 'scenarioId', 'scenarioName',
                                                   'ip', 'port', 'address', 'host'}
                                if any(k in parsed for k in interesting_keys):
                                    seen_values.add(fingerprint)
                                    new_findings.append({
                                        'pattern': 'JSON_OBJECT',
                                        'address': f['address'],
                                        'json': parsed,
                                    })
                            except json.JSONDecodeError:
                                pass
                except:
                    pass

            if new_findings:
                print(f"\n{'!'*60}")
                print(f"  [{ts}] NOUVELLES DÉCOUVERTES (scan #{scan_count})!")
                print(f"{'!'*60}")
                for nf in new_findings:
                    if 'json' in nf:
                        print(f"  @ {nf['address']}: JSON = {json.dumps(nf['json'], indent=2)[:500]}")
                    else:
                        print(f"  @ {nf['address']}: {nf['value'][:200]}")

                    # Log
                    entry = {
                        'ts': datetime.datetime.now().isoformat(),
                        'scan': scan_count,
                        **{k: v for k, v in nf.items() if k != 'context_raw'},
                    }
                    with open(log_file, 'a', encoding='utf-8') as lf:
                        lf.write(json.dumps(entry, ensure_ascii=False, default=str) + '\n')

                print(f"\n[+] Log -> {log_file}")
            elif scan_count % 5 == 0:
                print(f"  [{ts}] Scan #{scan_count} - {scanned/1024/1024:.0f}MB scannés, "
                      f"{len(regions)} régions, {len(seen_values)} valeurs uniques trouvées")

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Arrêt après {scan_count} scans")
        print(f"[*] {len(seen_values)} valeurs uniques trouvées au total")
        if os.path.exists(log_file):
            print(f"[*] Log: {log_file}")

    finally:
        kernel32.CloseHandle(handle)


def single_scan(pid):
    """Un seul scan complet"""
    handle = open_process(pid)
    if not handle:
        return

    print(f"[+] Process ouvert (PID: {pid})")
    print(f"[*] Énumération des régions mémoire...")

    regions = scan_memory_regions(handle)
    total_mem = sum(size for _, size in regions)
    print(f"[+] {len(regions)} régions, {total_mem/1024/1024:.0f} MB lisibles")

    print(f"[*] Scan en cours...")
    findings, scanned = scan_for_patterns(handle, regions, SEARCH_PATTERNS)

    print(f"[+] {scanned/1024/1024:.0f} MB scannés")
    print(f"[+] {len(findings)} matches trouvés")

    # Dédupliquer et afficher
    seen = set()
    for f in findings:
        ctx = f['context_raw']
        values = extract_values(ctx)
        for key, val in values.items():
            fp = f"{key}:{val}"
            if fp not in seen:
                seen.add(fp)
                print(f"\n  [{f['address']}] {val[:200]}")

        try:
            text = ctx.decode('utf-8', errors='replace')
            for m in re.finditer(r'\{[^{}]{10,2000}\}', text):
                try:
                    parsed = json.loads(m.group())
                    interesting = {'manifestId', 'matchId', 'ticketId', 'secretKey',
                                  'serverAddress', 'allocationId'}
                    if any(k in parsed for k in interesting):
                        fp = f"json:{m.group()[:100]}"
                        if fp not in seen:
                            seen.add(fp)
                            print(f"\n  [{f['address']}] JSON: {json.dumps(parsed, indent=2)[:500]}")
                except:
                    pass
        except:
            pass

    kernel32.CloseHandle(handle)


def main():
    print("=" * 60)
    print("  ARC RAIDERS MEMORY SCANNER")
    print("  Lecture mémoire externe (pas d'injection)")
    print("=" * 60)
    print()

    pid, name = find_game_pid()
    if not pid:
        print("[!] Arc Raiders non trouvé!")
        print("[!] Lance le jeu d'abord.")
        user_input = input("[?] PID manuel (ou 'q'): ").strip()
        if user_input.lower() == 'q':
            return
        pid = int(user_input)
        name = "manual"

    print(f"[+] Trouvé: {name} (PID: {pid})")
    print()
    print("  Modes:")
    print("  1. continu - Scan en boucle (pendant le matchmaking)")
    print("  2. single  - Un seul scan")
    print()

    mode = input("[?] Mode (1/2) [défaut: 1]: ").strip() or "1"

    if mode == "1":
        continuous_scan(pid)
    else:
        single_scan(pid)


if __name__ == "__main__":
    main()
