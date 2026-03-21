"""
Script mitmproxy pour capturer les requêtes HTTPS du jeu Arc Raiders.
Intercepte spécifiquement les appels gameserver/status pour récupérer le secretKey.

Usage:
1. Lance: mitmdump -s tools/mitm_capture.py -p 8080 --set stream_large_bodies=1
2. Configure le proxy Windows: 127.0.0.1:8080
3. Lance le jeu et entre en match
4. Le secretKey sera affiché et sauvegardé automatiquement

Note: il faut installer le certificat mitmproxy dans le store Windows
      (http://mitm.it depuis le navigateur avec le proxy actif)
"""

import json
import os
import datetime
from mitmproxy import http

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
CAPTURE_DIR = os.path.join(DATA_DIR, 'captures', 'https')
os.makedirs(CAPTURE_DIR, exist_ok=True)

LOG_FILE = os.path.join(CAPTURE_DIR, f"mitm_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")

# Compteur
request_count = 0


def response(flow: http.HTTPFlow) -> None:
    global request_count

    # Filtrer: on veut uniquement les requêtes vers l'API Embark
    host = flow.request.host
    if 'es-pio.net' not in host and 'embark' not in host:
        return

    request_count += 1
    url = flow.request.url
    method = flow.request.method
    status = flow.response.status_code if flow.response else 0

    # Décoder le body de la réponse
    resp_body = ''
    resp_data = None
    if flow.response and flow.response.content:
        try:
            resp_body = flow.response.content.decode('utf-8', errors='replace')
            resp_data = json.loads(resp_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Décoder le body de la requête
    req_body = ''
    if flow.request.content:
        try:
            req_body = flow.request.content.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            pass

    # Log toutes les requêtes
    path = flow.request.path
    print(f"[{request_count:4d}] {method} {path} -> {status}")

    # Détecter les endpoints critiques
    is_critical = any(kw in path for kw in [
        'gameserver', 'match', 'secret', 'encrypt', 'key', 'token',
        'session', 'connect', 'handshake', 'party'
    ])

    if is_critical:
        print(f"  !!! CRITICAL ENDPOINT: {url}")
        if req_body:
            print(f"  REQ: {req_body[:200]}")
        if resp_body:
            print(f"  RSP: {resp_body[:500]}")

        # Chercher le secretKey
        if resp_data:
            for key_name in ['secretKey', 'secret_key', 'encryptionKey', 'encryption_key',
                             'key', 'token', 'secret', 'connectionToken']:
                if key_name in resp_data:
                    value = resp_data[key_name]
                    print(f"\n{'!'*60}")
                    print(f"  SECRET KEY TROUVÉ!")
                    print(f"  Endpoint: {url}")
                    print(f"  Field: {key_name}")
                    print(f"  Value: {value}")
                    print(f"{'!'*60}\n")

                    # Sauvegarder immédiatement
                    key_file = os.path.join(CAPTURE_DIR, 'secret_key.json')
                    with open(key_file, 'w') as f:
                        json.dump({
                            'endpoint': url,
                            'field': key_name,
                            'value': value,
                            'timestamp': datetime.datetime.now().isoformat(),
                            'full_response': resp_data,
                        }, f, indent=2)

            # Chercher récursivement dans les sous-objets
            def search_keys(obj, prefix=''):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if any(kw in k.lower() for kw in ['secret', 'key', 'encrypt', 'token', 'cipher']):
                            print(f"  >> {prefix}{k} = {str(v)[:100]}")
                        search_keys(v, prefix=f"{prefix}{k}.")
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        search_keys(item, prefix=f"{prefix}[{i}].")

            search_keys(resp_data)

    # Sauvegarder dans le log
    entry = {
        'ts': datetime.datetime.now().isoformat(),
        'method': method,
        'url': url,
        'status': status,
        'req_headers': dict(flow.request.headers),
        'req_body': req_body[:1000] if req_body else '',
        'resp_body': resp_body[:5000] if resp_body else '',
    }

    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(entry) + '\n')
