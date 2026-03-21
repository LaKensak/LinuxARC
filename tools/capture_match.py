"""
Capture complète pendant un match Arc Raiders:
1. Détecte le processus du jeu
2. Sniffe le trafic UDP
3. Scanne la mémoire pour trouver la clé de chiffrement
4. Tente le déchiffrement en temps réel

Usage: lance le jeu, queue, puis exécute ce script en admin.
"""

import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys
import time
import threading
import datetime
from collections import defaultdict, Counter

# === CONFIG ===
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
CAPTURE_DIR = os.path.join(DATA_DIR, 'captures')
os.makedirs(CAPTURE_DIR, exist_ok=True)

PROXY_FILE = os.path.join(DATA_DIR, 'api_dump', 'v1_shared_proxy.json')
PROXY_IPS = set()
if os.path.exists(PROXY_FILE):
    with open(PROXY_FILE) as f:
        for ep in json.load(f).get('endpoints', []):
            PROXY_IPS.add(ep['host'].split(':')[0])

# Win32 API
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

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


def find_game_process():
    """Trouve le PID du processus Arc Raiders"""
    import subprocess
    result = subprocess.run(
        ['wmic', 'process', 'get', 'ProcessId,Name,ExecutablePath', '/FORMAT:CSV'],
        capture_output=True, text=True
    )

    candidates = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split(',')
        if len(parts) < 4:
            continue
        exe_path = parts[1]
        name = parts[2]
        pid = parts[3].strip()

        lower_name = name.lower()
        lower_path = exe_path.lower() if exe_path else ''

        if any(kw in lower_name for kw in ['pioneer', 'arcraiders', 'arc_raiders', 'arc-raiders']):
            candidates.append((name, pid, exe_path))
        elif any(kw in lower_path for kw in ['pioneer', 'arcraiders', 'arc raiders', 'embark']):
            candidates.append((name, pid, exe_path))

    if not candidates:
        # Méthode alternative: netstat pour trouver les processus avec UDP vers GCP
        result = subprocess.run(['netstat', '-nop', 'UDP'], capture_output=True, text=True)
        pids_with_gcp = set()
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 4 and parts[0] == 'UDP':
                remote = parts[2] if len(parts) > 2 else ''
                pid = parts[-1]
                if pid.isdigit() and any(remote.startswith(p) for p in ('34.', '35.', '136.', '8.229.')):
                    pids_with_gcp.add(pid)

        for pid in pids_with_gcp:
            try:
                r = subprocess.run(
                    ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'Name,ExecutablePath', '/FORMAT:CSV'],
                    capture_output=True, text=True, timeout=3
                )
                for line in r.stdout.strip().split('\n'):
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        path = parts[1].lower()
                        name = parts[2]
                        if any(kw in path for kw in ['pioneer', 'arcraid', 'embark', 'arc raid']):
                            candidates.append((name, pid, parts[1]))
            except:
                pass

    return candidates


def open_process(pid):
    """Ouvre un handle vers le processus"""
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, int(pid))
    if not handle:
        err = ctypes.get_last_error()
        print(f"[!] OpenProcess failed: error {err}")
        return None
    return handle


def scan_memory_for_pattern(handle, pattern, max_results=20):
    """Scanne la mémoire du processus pour trouver un pattern"""
    results = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0

    while address < 0x7FFFFFFFFFFF:
        result = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if result == 0:
            break

        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0

        if size == 0:
            break

        if (mbi.State == MEM_COMMIT and
            mbi.Protect in (PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE) and
            size < 100 * 1024 * 1024):

            try:
                buf = (ctypes.c_char * size)()
                bytes_read = ctypes.c_size_t(0)

                if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(bytes_read)):
                    data = bytes(buf[:bytes_read.value])
                    offset = 0
                    while True:
                        idx = data.find(pattern, offset)
                        if idx == -1:
                            break
                        abs_addr = base + idx
                        context = data[max(0, idx-32):idx+len(pattern)+64]
                        results.append((abs_addr, context))
                        if len(results) >= max_results:
                            return results
                        offset = idx + 1
            except (OSError, OverflowError):
                pass

        address = base + size

    return results


def scan_for_encryption_key(handle, conn_token, session_id):
    """Cherche la clé de chiffrement en mémoire."""
    key_candidates = []

    # Stratégie 1: Chercher le connection token
    print(f"[*] Scan: connection token {conn_token.hex()}")
    results = scan_memory_for_pattern(handle, conn_token, max_results=30)
    print(f"    -> {len(results)} occurrences")

    for addr, context in results:
        # Chercher des bytes à haute entropie autour (potentielles clés AES-256)
        for i in range(0, len(context) - 32, 4):
            candidate = context[i:i+32]
            unique = len(set(candidate))
            if unique >= 20:
                key_candidates.append((addr - 32 + i, candidate))

    # Stratégie 2: Chercher le session ID
    print(f"[*] Scan: session ID {session_id.hex()}")
    results = scan_memory_for_pattern(handle, session_id, max_results=30)
    print(f"    -> {len(results)} occurrences")

    for addr, context in results:
        for i in range(0, len(context) - 32, 4):
            candidate = context[i:i+32]
            unique = len(set(candidate))
            if unique >= 20:
                key_candidates.append((addr - 32 + i, candidate))

    # Stratégie 3: Chercher "EncryptionKey" ou "SecretKey" comme string
    for keyword in [b'EncryptionKey', b'SecretKey', b'encryption_key', b'secret_key', b'AESKey', b'PacketHandler']:
        print(f"[*] Scan: '{keyword.decode()}'")
        results = scan_memory_for_pattern(handle, keyword, max_results=5)
        print(f"    -> {len(results)} occurrences")
        for addr, context in results[:3]:
            print(f"    @ 0x{addr:012x}: ...{context[:80].hex()}...")

    # Dédupliquer les clés candidates
    seen = set()
    unique_keys = []
    for addr, key in key_candidates:
        key_hex = key.hex()
        if key_hex not in seen:
            seen.add(key_hex)
            unique_keys.append((addr, key))

    print(f"\n[+] {len(unique_keys)} clés candidates uniques trouvées")
    return unique_keys


def try_decrypt_aes_gcm(key, nonce, ciphertext, aad=b''):
    """Tente de déchiffrer avec AES-256-GCM"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


def try_decrypt_chacha(key, nonce, ciphertext, aad=b''):
    """Tente de déchiffrer avec ChaCha20-Poly1305"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


def try_decrypt_packet(packet_payload, key_candidates):
    """Essaye de déchiffrer un paquet avec les clés candidates"""
    if len(packet_payload) < 14:
        return None

    header = packet_payload[:13]
    encrypted = packet_payload[13:]
    seq = header[1]
    session = header[2:8]
    token = header[8:12]
    ptype = header[12]

    for addr, key in key_candidates:
        # Nonces possibles (12 bytes pour AES-GCM)
        nonces_12 = [
            session + token + bytes([seq, 0]),
            session + token + bytes([0, seq]),
            token + session + bytes([0, seq]),
            bytes([seq, 0]) + session + token,
            bytes([0, seq]) + session + token,
            header[:12],
            b'\x00' * 11 + bytes([seq]),
            bytes([seq]) + b'\x00' * 11,
            struct.pack('<I', seq) + session + bytes([0, 0]),
            struct.pack('>I', seq) + session + bytes([0, 0]),
        ]

        # Nonces 12 bytes pour ChaCha20-Poly1305
        nonces_24 = []

        for nonce in nonces_12:
            # AES-GCM
            result = try_decrypt_aes_gcm(key, nonce, encrypted)
            if result:
                return {'method': 'AES-256-GCM', 'key_addr': addr, 'key': key, 'nonce': nonce.hex(), 'plaintext': result}

            # Avec AAD = header
            result = try_decrypt_aes_gcm(key, nonce, encrypted, aad=header)
            if result:
                return {'method': 'AES-256-GCM+AAD', 'key_addr': addr, 'key': key, 'nonce': nonce.hex(), 'plaintext': result}

            # ChaCha20-Poly1305
            result = try_decrypt_chacha(key, nonce, encrypted)
            if result:
                return {'method': 'ChaCha20-Poly1305', 'key_addr': addr, 'key': key, 'nonce': nonce.hex(), 'plaintext': result}

    return None


def udp_sniffer_thread(packet_queue, stop_event):
    """Thread de capture UDP"""
    from scapy.all import sniff, UDP, IP

    def on_pkt(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        udp = pkt[UDP]
        payload = bytes(udp.payload) if udp.payload else b''

        src, dst = ip.src, ip.dst
        is_gcp = any(src.startswith(p) or dst.startswith(p)
                     for p in ('34.', '35.', '136.', '8.229.'))

        if not is_gcp and src not in PROXY_IPS and dst not in PROXY_IPS:
            return
        if dst.startswith('192.168.') and src.startswith('192.168.'):
            return

        # Ignorer QCMP (port 7600) — ce sont des pings de latence, pas du trafic de jeu
        if udp.sport == 7600 or udp.dport == 7600:
            return

        # Ignorer les paquets QLKN (Quilkin magic header)
        if len(payload) >= 4 and payload[:4] == b'QLKN':
            return

        direction = 'SEND' if any(dst.startswith(p) for p in ('34.', '35.', '136.', '8.229.')) or dst in PROXY_IPS else 'RECV'

        packet_queue.append({
            'ts': time.time(),
            'src': f'{src}:{udp.sport}',
            'dst': f'{dst}:{udp.dport}',
            'dir': direction,
            'payload': payload,
        })

    try:
        sniff(
            filter="udp and not port 53 and not port 5353 and not port 1900 and not port 5355",
            prn=on_pkt,
            store=False,
            stop_filter=lambda _: stop_event.is_set()
        )
    except Exception as e:
        print(f"[!] Sniffer error: {e}")


def main():
    print("=" * 60)
    print("  ARC RAIDERS MATCH CAPTURE")
    print("  Sniff UDP + Memory scan pour clé de chiffrement")
    print("=" * 60)
    print()

    # 1. Trouver le processus
    print("[*] Recherche du processus Arc Raiders...")
    candidates = find_game_process()

    if not candidates:
        print("[!] Processus non trouvé. En attente...")
        while not candidates:
            time.sleep(3)
            candidates = find_game_process()
            sys.stdout.write('.')
            sys.stdout.flush()
        print()

    name, pid, path = candidates[0]
    print(f"[+] Processus: {name} (PID {pid})")
    if path:
        print(f"    Path: {path}")

    # 2. Ouvrir le processus
    handle = open_process(pid)
    if not handle:
        print("[!] Impossible d'ouvrir le processus. Lance en admin!")
        return
    print(f"[+] Handle OK")

    # 3. Lancer le sniffer UDP
    packet_queue = []
    stop_event = threading.Event()
    sniffer = threading.Thread(target=udp_sniffer_thread, args=(packet_queue, stop_event), daemon=True)
    sniffer.start()
    print("[+] Sniffer UDP démarré")
    print()
    print("[*] Queue pour un match... le script détectera le trafic automatiquement.")
    print()

    # 4. Attendre le match
    conn_token = None
    session_id = None

    try:
        while True:
            time.sleep(0.5)

            if conn_token is None and len(packet_queue) > 10:
                # Chercher un vrai paquet de jeu (pas QCMP)
                # Les paquets de jeu font 39+ bytes et arrivent à haute fréquence
                for pkt in packet_queue:
                    if len(pkt['payload']) >= 39:
                        payload = pkt['payload']
                        conn_token = payload[8:12]
                        session_id = payload[2:8]
                        server = pkt['dst'] if pkt['dir'] == 'SEND' else pkt['src']
                        print(f"[+] MATCH DÉTECTÉ!")
                        print(f"    Serveur: {server}")
                        print(f"    Session: {session_id.hex()}")
                        print(f"    Token:   {conn_token.hex()}")
                        break

            if conn_token:
                # 5. Scanner la mémoire
                print()
                print("[*] === SCAN MÉMOIRE ===")
                key_candidates = scan_for_encryption_key(handle, conn_token, session_id)

                if key_candidates:
                    # Sauvegarder les clés
                    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    keys_file = os.path.join(CAPTURE_DIR, f'keys_{ts}.json')
                    with open(keys_file, 'w') as f:
                        json.dump([{'addr': hex(a), 'key': k.hex()} for a, k in key_candidates], f, indent=2)
                    print(f"[*] Clés sauvegardées: {keys_file}")

                    # Tenter le déchiffrement sur les gros paquets
                    print()
                    print("[*] Tentative de déchiffrement...")
                    test_pkts = [p for p in packet_queue if len(p['payload']) > 100][:5]
                    decrypted = False

                    for pkt in test_pkts:
                        result = try_decrypt_packet(pkt['payload'], key_candidates)
                        if result:
                            print(f"\n{'!'*60}")
                            print(f"  DÉCHIFFREMENT RÉUSSI!")
                            print(f"  Méthode: {result['method']}")
                            print(f"  Clé: {result['key'].hex()}")
                            print(f"  Nonce: {result['nonce']}")
                            print(f"  Plaintext: {result['plaintext'][:64].hex()}")
                            print(f"{'!'*60}")

                            with open(os.path.join(CAPTURE_DIR, f'working_key_{ts}.json'), 'w') as f:
                                json.dump({
                                    'method': result['method'],
                                    'key': result['key'].hex(),
                                    'nonce_pattern': result['nonce'],
                                }, f, indent=2)
                            decrypted = True
                            break

                    if not decrypted:
                        print("[!] Aucune clé n'a fonctionné. Les clés sont sauvegardées.")
                else:
                    print("[!] Aucune clé candidate trouvée")

                # Sauvegarder les paquets
                ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                pkt_file = os.path.join(CAPTURE_DIR, f'packets_{ts}.jsonl')
                with open(pkt_file, 'w') as f:
                    for p in packet_queue:
                        f.write(json.dumps({
                            'ts': p['ts'], 'src': p['src'], 'dst': p['dst'],
                            'dir': p['dir'], 'len': len(p['payload']),
                            'hex': p['payload'].hex(),
                        }) + '\n')
                print(f"[*] {len(packet_queue)} paquets: {pkt_file}")

                # Continuer la capture
                print()
                print("[*] Capture continue... Ctrl+C pour arrêter")
                prev = len(packet_queue)
                while True:
                    time.sleep(5)
                    n = len(packet_queue)
                    if n > prev:
                        print(f"  {n} paquets ({(n-prev)/5:.0f}/s)")
                        prev = n

    except KeyboardInterrupt:
        print("\n[*] Arrêt...")
    finally:
        stop_event.set()
        kernel32.CloseHandle(handle)
        print("[*] Terminé.")


if __name__ == "__main__":
    main()
