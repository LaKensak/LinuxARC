"""
Sniffer UDP pour Arc Raiders.
Capture le trafic vers/depuis les proxies Quilkin (port 7777).
Analyse le format des paquets en temps réel.

Usage: lance le jeu, queue pour un match, puis ce script capture tout.
"""

import json
import os
import sys
import time
import datetime
import struct
from collections import defaultdict

# Scapy
from scapy.all import sniff, UDP, IP, conf, get_if_list, get_if_addr

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
LOG_DIR = os.path.join(DATA_DIR, 'logs')
CAPTURE_DIR = os.path.join(DATA_DIR, 'captures', 'udp')
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CAPTURE_DIR, exist_ok=True)

# Charger les IPs des proxies Quilkin
PROXY_FILE = os.path.join(DATA_DIR, 'api_dump', 'v1_shared_proxy.json')
PROXY_IPS = set()
PROXY_REGIONS = {}

if os.path.exists(PROXY_FILE):
    with open(PROXY_FILE) as f:
        data = json.load(f)
    for ep in data.get('endpoints', []):
        ip = ep['host'].split(':')[0]
        PROXY_IPS.add(ip)
        PROXY_REGIONS[ip] = ep.get('region', '?')

print(f"[+] {len(PROXY_IPS)} proxy IPs chargées")

# Stats
stats = {
    'start_time': None,
    'total_packets': 0,
    'game_packets': 0,
    'bytes_sent': 0,
    'bytes_recv': 0,
    'connections': defaultdict(lambda: {'sent': 0, 'recv': 0, 'first': None, 'last': None,
                                         'sizes_sent': [], 'sizes_recv': []}),
    'packet_log': [],
}

# Fichier log
LOG_FILE = os.path.join(LOG_DIR, f"udp_capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
PCAP_FILE = os.path.join(CAPTURE_DIR, f"game_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin")


def analyze_packet_header(payload):
    """Analyse le header d'un paquet UDP Quilkin/game.

    Quilkin routing token format (v1):
    - Premiers bytes: routing token (variable length)
    - Reste: game payload

    Formats possibles:
    - DTLS: commence par 0x14-0x19 (content types) ou 0xFE (DTLS 1.2)
    - Custom: à déterminer par l'analyse
    """
    if not payload or len(payload) < 4:
        return {'type': 'too_short', 'len': len(payload) if payload else 0}

    b = payload[:16]
    info = {
        'len': len(payload),
        'hex_header': payload[:32].hex(),
    }

    # Check DTLS
    if b[0] in (0x14, 0x15, 0x16, 0x17):
        # DTLS record: content_type(1) version(2) epoch(2) seq(6) length(2)
        if len(b) >= 13:
            content_type = b[0]
            version = (b[1] << 8) | b[2]
            epoch = (b[3] << 8) | b[4]
            seq = int.from_bytes(b[5:11], 'big')
            length = (b[11] << 8) | b[12]
            types = {0x14: 'ChangeCipherSpec', 0x15: 'Alert', 0x16: 'Handshake', 0x17: 'AppData'}
            info['type'] = 'DTLS'
            info['dtls_type'] = types.get(content_type, f'0x{content_type:02x}')
            info['dtls_version'] = f'0x{version:04x}'
            info['dtls_epoch'] = epoch
            info['dtls_seq'] = seq
            info['dtls_length'] = length
            return info

    # Check STUN (pour NAT traversal)
    if len(b) >= 20 and b[0] in (0x00, 0x01) and b[1] in (0x01, 0x11):
        info['type'] = 'STUN'
        return info

    # Quilkin utilise un header custom
    # Le premier byte pourrait être un version/type indicator
    info['type'] = 'game_data'
    info['first_byte'] = f'0x{b[0]:02x}'
    info['first_4'] = struct.unpack('>I', b[:4])[0] if len(b) >= 4 else 0

    # Chercher des patterns
    # Si le payload commence par un token de routage (Quilkin v1: 5 bytes de routing)
    if len(payload) > 5:
        info['possible_routing_token'] = payload[:5].hex()
        info['payload_after_token'] = payload[5:21].hex() if len(payload) > 21 else payload[5:].hex()

    return info


def on_packet(pkt):
    """Callback pour chaque paquet capturé"""
    if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    udp = pkt[UDP]
    src = ip.src
    dst = ip.dst
    sport = udp.sport
    dport = udp.dport
    payload = bytes(udp.payload) if udp.payload else b''

    # Filtrer: garder le trafic vers les proxies OU vers des IPs GCP (34.x, 35.x, 136.x, 8.229.x)
    # Ignorer le trafic local, multicast, broadcast
    is_proxy = dst in PROXY_IPS or src in PROXY_IPS
    is_gcp = (dst.startswith('34.') or dst.startswith('35.') or dst.startswith('136.') or dst.startswith('8.229.') or
              src.startswith('34.') or src.startswith('35.') or src.startswith('136.') or src.startswith('8.229.'))
    is_local = dst.startswith('192.168.') and src.startswith('192.168.')
    is_multicast = dst.startswith('224.') or dst.startswith('239.')

    if not is_proxy and not is_gcp:
        return
    if is_local or is_multicast:
        return

    stats['total_packets'] += 1
    now = time.time()

    if stats['start_time'] is None:
        stats['start_time'] = now
        print(f"\n{'!'*60}")
        print(f"  PREMIER PAQUET DÉTECTÉ!")
        print(f"{'!'*60}\n")

    # Direction: on envoie si la destination est un serveur connu
    is_outgoing = is_proxy and (dst in PROXY_IPS) or (not src.startswith('192.168.') and not src.startswith('10.') and not src.startswith('25.'))
    if dst in PROXY_IPS or dst.startswith('34.') or dst.startswith('35.') or dst.startswith('136.') or dst.startswith('8.229.'):
        direction = 'SEND'
        proxy_ip = dst
        stats['bytes_sent'] += len(payload)
        conn_key = f"{dst}:{dport}"
        stats['connections'][conn_key]['sent'] += 1
        stats['connections'][conn_key]['sizes_sent'].append(len(payload))
    else:
        direction = 'RECV'
        proxy_ip = src
        stats['bytes_recv'] += len(payload)
        conn_key = f"{src}:{sport}"
        stats['connections'][conn_key]['recv'] += 1
        stats['connections'][conn_key]['sizes_recv'].append(len(payload))

    conn = stats['connections'][conn_key]
    if conn['first'] is None:
        conn['first'] = now
        region = PROXY_REGIONS.get(proxy_ip, '?')
        print(f"[+] Nouvelle connexion: {conn_key} (region: {region})")
    conn['last'] = now

    stats['game_packets'] += 1

    # Analyser le header
    header_info = analyze_packet_header(payload)

    # Log les premiers paquets en détail
    if stats['game_packets'] <= 50 or stats['game_packets'] % 100 == 0:
        elapsed = now - stats['start_time']
        print(f"  [{elapsed:7.2f}s] {direction:4s} {src}:{sport} -> {dst}:{dport} "
              f"len={len(payload):5d} type={header_info.get('type', '?'):15s} "
              f"| {header_info.get('hex_header', '')[:40]}")

    # Sauvegarder les données brutes des 200 premiers paquets
    if stats['game_packets'] <= 200:
        entry = {
            'ts': datetime.datetime.now().isoformat(),
            'elapsed': round(now - stats['start_time'], 4) if stats['start_time'] else 0,
            'dir': direction,
            'src': f'{src}:{sport}',
            'dst': f'{dst}:{dport}',
            'len': len(payload),
            'header': header_info,
            'raw_hex': payload[:128].hex(),
        }
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    # Sauvegarder le payload brut dans le fichier binaire
    if stats['game_packets'] <= 5000:
        with open(PCAP_FILE, 'ab') as f:
            # Format simple: [direction(1)] [timestamp_ms(8)] [src_port(2)] [dst_port(2)] [length(4)] [payload]
            ts_ms = int(now * 1000)
            d = 0 if direction == 'SEND' else 1
            f.write(struct.pack('>BqHHI', d, ts_ms, sport, dport, len(payload)))
            f.write(payload)

    # Stats périodiques
    if stats['game_packets'] % 500 == 0:
        elapsed = now - stats['start_time']
        pps = stats['game_packets'] / elapsed if elapsed > 0 else 0
        total_kb = (stats['bytes_sent'] + stats['bytes_recv']) / 1024
        print(f"\n  === Stats @ {elapsed:.0f}s: {stats['game_packets']} paquets, "
              f"{pps:.0f} pkt/s, {total_kb:.0f} KB total ===")
        for k, v in stats['connections'].items():
            print(f"    {k}: sent={v['sent']} recv={v['recv']}")
        print()


def find_interface():
    """Trouve la bonne interface réseau"""
    ifaces = get_if_list()
    print(f"[*] Interfaces disponibles: {len(ifaces)}")

    # Chercher l'interface avec une IP locale
    for iface in ifaces:
        try:
            addr = get_if_addr(iface)
            if addr and not addr.startswith('127.') and not addr.startswith('0.'):
                print(f"  {iface}: {addr}")
        except:
            pass

    return None  # Utiliser l'interface par défaut


def main():
    print("=" * 60)
    print("  ARC RAIDERS UDP SNIFFER")
    print("  Capture du trafic Quilkin (port 7777)")
    print("=" * 60)
    print()
    print(f"[*] Proxies: {len(PROXY_IPS)} IPs connues")
    print(f"[*] Log: {LOG_FILE}")
    print(f"[*] Raw: {PCAP_FILE}")
    print()

    find_interface()

    # Construire le filtre BPF
    # Le jeu peut utiliser des ports dynamiques et des IPs hors de la liste proxy
    # On capture TOUT le trafic UDP sauf DNS (53), mDNS, SSDP
    bpf = "udp and not port 53 and not port 5353 and not port 1900 and not port 5355"
    print(f"[*] Filtre BPF: {bpf}")
    print()
    print("[*] Lance le jeu et queue pour un match!")
    print("[*] Le sniffer capturera automatiquement le trafic.")
    print("[*] Ctrl+C pour arrêter")
    print()

    try:
        sniff(filter=bpf, prn=on_packet, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[!] Permission refusée - lance en administrateur!")
        return

    # Résumé final
    print(f"\n{'='*60}")
    print(f"  RÉSUMÉ")
    print(f"{'='*60}")
    print(f"  Paquets totaux: {stats['total_packets']}")
    print(f"  Paquets jeu:    {stats['game_packets']}")
    print(f"  Envoyés:        {stats['bytes_sent']/1024:.1f} KB")
    print(f"  Reçus:          {stats['bytes_recv']/1024:.1f} KB")
    print(f"  Connexions:     {len(stats['connections'])}")

    for key, conn in stats['connections'].items():
        region = PROXY_REGIONS.get(key.split(':')[0], '?')
        duration = (conn['last'] - conn['first']) if conn['first'] and conn['last'] else 0
        avg_sent = sum(conn['sizes_sent']) / len(conn['sizes_sent']) if conn['sizes_sent'] else 0
        avg_recv = sum(conn['sizes_recv']) / len(conn['sizes_recv']) if conn['sizes_recv'] else 0
        print(f"\n  {key} (region: {region})")
        print(f"    Durée: {duration:.1f}s")
        print(f"    Sent: {conn['sent']} paquets (avg {avg_sent:.0f} bytes)")
        print(f"    Recv: {conn['recv']} paquets (avg {avg_recv:.0f} bytes)")

        # Tailles les plus fréquentes
        if conn['sizes_recv']:
            size_counts = defaultdict(int)
            for s in conn['sizes_recv']:
                size_counts[s] += 1
            top = sorted(size_counts.items(), key=lambda x: -x[1])[:5]
            print(f"    Top tailles reçues: {top}")

    print(f"\n[*] Données brutes: {PCAP_FILE}")
    print(f"[*] Log détaillé:   {LOG_FILE}")


if __name__ == "__main__":
    main()
