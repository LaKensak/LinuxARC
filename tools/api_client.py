"""
Client API direct pour Arc Raiders
Utilise le JWT capturé par mitmproxy pour appeler l'API gateway directement,
sans passer par le jeu (donc pas de cert pinning).

Usage:
    python tools/api_client.py              # Utilise le JWT sauvegardé
    python tools/api_client.py --token eyJ... # JWT manuel
    python tools/api_client.py --discover    # Découvrir les endpoints
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import requests
import urllib3

# Désactiver les warnings SSL (on se connecte au vrai serveur, pas de MITM ici)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
LOG_DIR = os.path.join(DATA_DIR, 'logs')

API_GATEWAY = "https://api-gateway.europe.es-pio.net"
AUTH_HOST = "https://auth.embark.net"

# Endpoints connus (d'après le thread UC + captures)
KNOWN_ENDPOINTS = [
    # Anticheat
    ("GET", "/v1/shared/anticheat/config"),
    # Health
    ("GET", "/healthz"),
    # Profile
    ("GET", "/v1/profile"),
    ("GET", "/v1/profile/me"),
    ("GET", "/v1/user/profile"),
    # Inventory
    ("GET", "/v1/inventory"),
    ("GET", "/v1/inventory/sync"),
    ("GET", "/v1/shared/inventory"),
    # Loadout
    ("GET", "/v1/loadout"),
    ("GET", "/v1/loadout/sync"),
    ("GET", "/v1/shared/loadout"),
    # Currencies
    ("GET", "/v1/currencies"),
    ("GET", "/v1/currencies/sync"),
    ("GET", "/v1/shared/currencies"),
    # Social
    ("GET", "/v1/friends"),
    ("GET", "/v1/friends/list"),
    ("GET", "/v1/presence"),
    ("GET", "/v1/presence/friends"),
    # Matchmaking
    ("GET", "/v1/matchmaking/scenarios"),
    ("GET", "/v1/matchmaking/status"),
    # Match / Gameserver
    ("GET", "/v1/gameserver/status"),
    ("GET", "/v1/match/status"),
    ("GET", "/v1/squad/layout"),
    # Quilkin (UDP proxy)
    ("GET", "/v1/quilkin/config"),
    ("GET", "/v1/shared/quilkin/config"),
    # Store / Offers
    ("GET", "/v1/store"),
    ("GET", "/v1/store/offers"),
    ("GET", "/v1/shared/store/offers"),
    # Quests / Challenges
    ("GET", "/v1/quests"),
    ("GET", "/v1/challenges"),
    ("GET", "/v1/codex"),
    # Seasons
    ("GET", "/v1/season"),
    ("GET", "/v1/season/progress"),
    ("GET", "/v1/shared/season"),
    # Stats
    ("GET", "/v1/stats"),
    ("GET", "/v1/stats/me"),
    # Settings
    ("GET", "/v1/settings"),
    ("GET", "/v1/shared/settings"),
    # News / MOTD
    ("GET", "/v1/news"),
    ("GET", "/v1/motd"),
    ("GET", "/v1/shared/motd"),
    # Discovery
    ("GET", "/v1/discovery"),
    ("GET", "/v1/shared/discovery"),
]


def load_jwt():
    """Charge le JWT depuis le fichier sauvegardé"""
    jwt_file = os.path.join(DATA_DIR, "jwt_token.json")
    txt_file = os.path.join(DATA_DIR, "jwt_token.txt")

    if os.path.exists(jwt_file):
        with open(jwt_file, 'r') as f:
            data = json.load(f)
        token = data.get('token')
        if token:
            print(f"[+] JWT chargé depuis {jwt_file}")
            print(f"    Capturé: {data.get('captured_at', '?')}")
            print(f"    Source: {data.get('source', '?')}")
            if 'claims' in data:
                claims = data['claims']
                print(f"    Subject: {claims.get('sub', '?')}")
                print(f"    Issuer: {claims.get('iss', '?')}")
                exp = claims.get('exp')
                if exp:
                    from datetime import datetime as dt
                    exp_dt = dt.fromtimestamp(exp)
                    remaining = exp_dt - dt.now()
                    print(f"    Expire: {exp_dt} ({remaining})")
                    if remaining.total_seconds() < 0:
                        print("[!] TOKEN EXPIRÉ!")
            return token

    if os.path.exists(txt_file):
        with open(txt_file, 'r') as f:
            token = f.read().strip()
        if token:
            print(f"[+] JWT chargé depuis {txt_file} ({len(token)} chars)")
            return token

    return None


def call_api(session, method, path, token, base_url=API_GATEWAY):
    """Appelle un endpoint de l'API"""
    url = f"{base_url}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        if method == "GET":
            resp = session.get(url, headers=headers, timeout=10)
        elif method == "POST":
            resp = session.post(url, headers=headers, timeout=10, json={})
        else:
            return None

        return {
            "method": method,
            "path": path,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:2000],
            "body_json": resp.json() if resp.headers.get('content-type', '').startswith('application/json') else None,
            "size": len(resp.content),
        }
    except requests.exceptions.ConnectionError as e:
        return {"method": method, "path": path, "error": f"Connection error: {e}"}
    except requests.exceptions.Timeout:
        return {"method": method, "path": path, "error": "Timeout"}
    except Exception as e:
        return {"method": method, "path": path, "error": str(e)}


def discover_endpoints(token):
    """Essaye tous les endpoints connus et affiche les résultats"""
    print("\n" + "=" * 60)
    print("   ARC RAIDERS API DISCOVERY")
    print("=" * 60 + "\n")

    session = requests.Session()
    results = []
    working = []

    for method, path in KNOWN_ENDPOINTS:
        result = call_api(session, method, path, token)
        results.append(result)

        if 'error' in result:
            status_str = f"ERR: {result['error'][:40]}"
            print(f"  [-] {method:4s} {path:45s} {status_str}")
        else:
            status = result['status']
            size = result['size']
            if status == 200:
                print(f"  [+] {method:4s} {path:45s} {status} ({size}b)")
                working.append(result)
            elif status == 404:
                print(f"  [ ] {method:4s} {path:45s} {status}")
            elif status == 401 or status == 403:
                print(f"  [!] {method:4s} {path:45s} {status} (auth failed)")
            else:
                print(f"  [?] {method:4s} {path:45s} {status} ({size}b)")

        time.sleep(0.2)  # Rate limiting

    print(f"\n{'=' * 60}")
    print(f"  Résultat: {len(working)}/{len(results)} endpoints fonctionnels")
    print(f"{'=' * 60}")

    # Sauvegarder les résultats
    os.makedirs(LOG_DIR, exist_ok=True)
    output_file = os.path.join(LOG_DIR, f"api_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'total': len(results),
            'working': len(working),
            'results': results,
        }, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n[+] Résultats sauvegardés -> {output_file}")

    # Afficher les données des endpoints fonctionnels
    if working:
        print(f"\n{'=' * 60}")
        print("   DONNÉES CAPTURÉES")
        print(f"{'=' * 60}\n")

        for result in working:
            print(f"--- {result['method']} {result['path']} ---")
            if result.get('body_json'):
                print(json.dumps(result['body_json'], indent=2, ensure_ascii=False)[:1000])
            else:
                print(result.get('body', '')[:500])
            print()

    return working


def interactive_mode(token):
    """Mode interactif pour tester des endpoints"""
    session = requests.Session()

    print("\n[*] Mode interactif - tape un endpoint ou 'quit' pour quitter")
    print("[*] Exemples: /v1/profile, /v1/inventory, /healthz\n")

    while True:
        try:
            user_input = input("endpoint> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not user_input or user_input.lower() in ('quit', 'exit', 'q'):
            break

        # Déterminer la méthode
        if user_input.startswith("POST "):
            method = "POST"
            path = user_input[5:].strip()
        else:
            method = "GET"
            path = user_input

        if not path.startswith("/"):
            path = "/" + path

        result = call_api(session, method, path, token)
        if 'error' in result:
            print(f"  Error: {result['error']}")
        else:
            print(f"  Status: {result['status']} | Size: {result['size']}b")
            if result.get('body_json'):
                print(json.dumps(result['body_json'], indent=2, ensure_ascii=False)[:2000])
            elif result.get('body'):
                print(result['body'][:1000])
        print()


def main():
    parser = argparse.ArgumentParser(description="Arc Raiders API Client")
    parser.add_argument("--token", help="JWT token (sinon charge depuis data/jwt_token.json)")
    parser.add_argument("--discover", action="store_true", help="Découvrir les endpoints")
    parser.add_argument("--interactive", action="store_true", help="Mode interactif")
    parser.add_argument("--endpoint", help="Appeler un endpoint spécifique")
    args = parser.parse_args()

    print("""
╔═══════════════════════════════════════════════════════════╗
║          ARC RAIDERS API CLIENT (Direct)                  ║
║                                                           ║
║   Appelle l'API gateway directement avec le JWT capturé   ║
║   Pas de cert pinning car on contrôle le client TLS       ║
╚═══════════════════════════════════════════════════════════╝
    """)

    # Charger le token
    token = args.token
    if not token:
        token = load_jwt()

    if not token:
        print("[!] Aucun JWT trouvé!")
        print("[*] Lance d'abord start_frida.py pour capturer le JWT via mitmproxy")
        print("[*] Ou fournis un token avec --token eyJ...")
        sys.exit(1)

    # Health check
    print("\n[*] Test de connectivité vers api-gateway.europe.es-pio.net...")
    session = requests.Session()
    health = call_api(session, "GET", "/healthz", token)
    if 'error' in health:
        print(f"[!] Erreur de connexion: {health['error']}")
        print("[*] Vérifier la connexion réseau")
    else:
        print(f"[+] Gateway accessible: {health['status']} ({health['size']}b)")
        if health.get('body'):
            print(f"    Response: {health['body'][:100]}")

    # Mode selon les arguments
    if args.discover:
        discover_endpoints(token)
    elif args.endpoint:
        result = call_api(session, "GET", args.endpoint, token)
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Status: {result['status']}")
            if result.get('body_json'):
                print(json.dumps(result['body_json'], indent=2, ensure_ascii=False))
            else:
                print(result.get('body', ''))
    elif args.interactive:
        interactive_mode(token)
    else:
        # Par défaut: discover + interactive
        discover_endpoints(token)
        interactive_mode(token)


if __name__ == "__main__":
    main()
