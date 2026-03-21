"""
Poll l'API Arc Raiders pendant un match pour trouver le secretKey.
Le jeu appelle gameserver/status avec le matchId.
Ce script essaye de trouver le matchId en cours et récupérer le secretKey.

Usage: lance pendant un match actif.
"""

import requests
import urllib3
import json
import time
import os
import itertools

urllib3.disable_warnings()

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
API = 'https://api-gateway.europe.es-pio.net'

token = open(os.path.join(DATA_DIR, 'jwt_token.txt')).read().strip()
MID = '6869061741499557498'

headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json',
    'User-Agent': 'PioneerGame/pioneer_1.20.x-CL-1096520 (http-legacy)',
    'x-embark-request-id': 'poll-match',
    'x-embark-manifest-id': MID,
    'x-embark-telemetry-uuid': 'tu',
    'x-embark-telemetry-client-platform': '12',
}

session = requests.Session()


def try_endpoint(method, path, body=None, label=''):
    """Teste un endpoint et affiche le résultat s'il est intéressant"""
    try:
        if method == 'GET':
            r = session.get(f'{API}{path}', headers=headers, timeout=5, verify=False)
        else:
            r = session.post(f'{API}{path}', headers=headers, json=body or {}, timeout=5, verify=False)

        if r.status_code not in (404, 405):
            text = r.text[:300] if r.text else '(empty)'
            print(f'  {r.status_code:3d} {method:4s} {path:50s} {label}')
            if r.text and r.status_code == 200:
                print(f'       {text}')

                # Chercher des clés intéressantes
                try:
                    data = r.json()
                    for key in ['secretKey', 'secret_key', 'encryptionKey', 'encryption_key',
                                'matchId', 'match_id', 'gameSessionId', 'serverId',
                                'connectionInfo', 'connection_info', 'serverAddress']:
                        if key in str(data):
                            print(f'  >>> FOUND KEY: {key}')
                except json.JSONDecodeError:
                    pass
            return r
    except Exception as e:
        pass
    return None


def main():
    print("=" * 60)
    print("  ARC RAIDERS API MATCH POLLER")
    print("=" * 60)
    print()

    # Phase 1: Essayer tous les endpoints match/gameserver
    print("[*] Phase 1: Scan des endpoints match/gameserver...")
    endpoints = [
        ('POST', '/v1/shared/match/status', {}),
        ('POST', '/v1/shared/match/current', {}),
        ('GET', '/v1/shared/match/current', None),
        ('POST', '/v1/shared/match/info', {}),
        ('POST', '/v1/shared/gameserver/status', {}),
        ('POST', '/v1/shared/gameserver/connect', {}),
        ('POST', '/v1/shared/gameserver/info', {}),
        ('GET', '/v1/shared/gameserver/info', None),
        ('POST', '/v1/shared/gameserver/session', {}),
        ('GET', '/v1/shared/session', None),
        ('POST', '/v1/shared/session', {}),
        ('POST', '/v1/shared/session/current', {}),
        ('GET', '/v1/shared/session/current', None),
        ('POST', '/v1/shared/connection', {}),
        ('POST', '/v1/shared/connection/info', {}),
        ('POST', '/v1/pioneer/match', {}),
        ('POST', '/v1/pioneer/match/current', {}),
        ('GET', '/v1/pioneer/match/current', None),
        ('POST', '/v1/pioneer/gameserver', {}),
        ('POST', '/v1/pioneer/session', {}),
        ('GET', '/v1/pioneer/session', None),
        # Variantes avec le serveur IP connu
        ('POST', '/v1/shared/gameserver/status', {'server_address': '34.12.18.222:7751'}),
        ('POST', '/v1/shared/gameserver/status', {'serverAddress': '34.12.18.222:7751'}),
        ('POST', '/v1/shared/gameserver/status', {'ip': '34.12.18.222', 'port': 7751}),
    ]

    for method, path, body in endpoints:
        try_endpoint(method, path, body)

    # Phase 2: Fuzzer les champs de gameserver/status
    print()
    print("[*] Phase 2: Fuzzing gameserver/status body fields...")

    # Le endpoint retourne 400 validation error - on doit trouver les bons champs
    # Essayons avec des protobuf-style fields
    field_combos = [
        {'manifest_id': int(MID)},
        {'manifest_id': int(MID), 'match_id': ''},
        {'match_id': 'test', 'manifest_id': int(MID)},
        {'server_id': 'test'},
        {'game_session_id': 'test'},
        {'allocation_id': 'test'},
        {'connection_token': 'test'},
        {'player_id': 'test'},
        {'build_id': 'CL1112387-64D2A17F-BK3676'},
        {'manifest_id': int(MID), 'server_address': '34.12.18.222:7751'},
        {'ip': '34.12.18.222', 'port': 7751},
        {'host': '34.12.18.222:7751'},
        {'address': '34.12.18.222:7751'},
    ]

    for body in field_combos:
        r = try_endpoint('POST', '/v1/shared/gameserver/status', body, label=str(body)[:60])
        if r and r.status_code == 200:
            print(f'  !!! SUCCESS with body: {json.dumps(body)}')
            print(f'  Response: {r.text[:500]}')

    # Phase 3: Vérifier si le profil contient des infos de match
    print()
    print("[*] Phase 3: Check profile pour match info...")
    r = try_endpoint('GET', '/v1/shared/profile')

    # Phase 4: Heartbeat pourrait contenir des infos si on est en match
    print()
    print("[*] Phase 4: Heartbeat...")
    r = try_endpoint('POST', '/v1/shared/heartbeat')

    print()
    print("[*] Terminé.")


if __name__ == '__main__':
    main()
