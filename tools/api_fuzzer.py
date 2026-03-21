"""
Fuzzer d'endpoints pour l'API Arc Raiders (Pioneer)
Essaye de nombreuses combinaisons de chemins pour trouver les vraies routes
"""

import json
import os
import sys
import time
from datetime import datetime
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
LOG_DIR = os.path.join(DATA_DIR, 'logs')

API_GATEWAY = "https://api-gateway.europe.es-pio.net"

# Préfixes possibles
PREFIXES = [
    "/v1",
    "/v1/shared",
    "/v1/pioneer",
    "/v1/game",
    "/v1/user",
    "/v1/player",
    "/v1/client",
    "/api/v1",
    "/api",
    "",
]

# Noms de ressources possibles (d'après SDK: PioneerOnlineInventoryModel, etc.)
RESOURCES = [
    # Trouvé
    "anticheat/config",
    # Profile / Account
    "profile", "account", "me", "user", "player",
    "profile/me", "account/me", "player/me",
    "displayname", "display-name",
    # Inventory (PioneerOnlineInventoryModel)
    "inventory", "inventory/sync", "inventory/items",
    "items", "item",
    "online-inventory",
    # Loadout
    "loadout", "loadout/sync", "loadout/active",
    "loadouts", "equipment",
    # Currencies
    "currencies", "currency", "currencies/sync",
    "wallet", "balance",
    # Social
    "friends", "friends/list", "friend",
    "social", "social/friends",
    "presence", "presence/friends", "presence/online",
    "squad", "squad/layout", "squad/members",
    "party", "party/members",
    # Matchmaking
    "matchmaking", "matchmaking/scenarios",
    "matchmaking/status", "matchmaking/queue",
    "scenarios", "match", "match/status",
    "match/start", "match/find",
    # Gameserver
    "gameserver", "gameserver/status",
    "server", "server/status",
    "session", "session/status",
    # Quilkin (UDP proxy)
    "quilkin", "quilkin/config",
    "proxy", "proxy/config", "proxy/endpoints",
    # Store
    "store", "store/offers", "shop", "offers",
    "catalog", "storefront",
    # Progression
    "quests", "quest", "challenges", "challenge",
    "codex", "progression", "progress",
    "season", "season/progress", "battlepass",
    "xp", "level", "rank",
    # Stats
    "stats", "stats/me", "statistics",
    "leaderboard", "leaderboards",
    # Settings
    "settings", "config", "configuration",
    "client-config", "game-config",
    # News / MOTD
    "news", "motd", "announcements",
    "messages", "notifications",
    # Discovery (FApiGatewayDiscoveryServer)
    "discovery", "discover", "services",
    "gateway", "gateway/discover",
    "routes", "endpoints",
    # Telemetry
    "telemetry", "analytics", "events",
    # Rewards
    "rewards", "claims", "entitlements",
    "drops", "loot",
    # Crafting
    "crafting", "recipes", "blueprints",
    # Map / World
    "map", "world", "zones", "locations",
    # Ping
    "ping", "health", "status",
    "version", "info",
]


def load_jwt():
    jwt_file = os.path.join(DATA_DIR, "jwt_token.txt")
    if os.path.exists(jwt_file):
        with open(jwt_file, 'r') as f:
            return f.read().strip()
    jwt_json = os.path.join(DATA_DIR, "jwt_token.json")
    if os.path.exists(jwt_json):
        with open(jwt_json, 'r') as f:
            return json.load(f).get('token')
    return None


def fuzz_endpoint(session, method, path, token):
    url = f"{API_GATEWAY}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "EmbarkGameBoot/1.0 (Windows; 10.0.26200.1.768.64bit)",
    }
    try:
        if method == "GET":
            resp = session.get(url, headers=headers, timeout=5)
        else:
            resp = session.post(url, headers=headers, timeout=5, json={})
        return resp.status_code, len(resp.content), resp.text[:300]
    except Exception as e:
        return -1, 0, str(e)[:100]


def main():
    token = load_jwt()
    if not token:
        print("[!] Pas de JWT trouvé dans data/jwt_token.txt")
        sys.exit(1)

    print(f"[+] JWT chargé ({len(token)} chars)")

    session = requests.Session()

    # Vérifier la connectivité
    status, size, body = fuzz_endpoint(session, "GET", "/healthz", token)
    if status != 200:
        print(f"[!] Gateway inaccessible: {status}")
        sys.exit(1)
    print(f"[+] Gateway OK: {body.strip()}")

    # Générer toutes les combinaisons
    paths = set()
    for prefix in PREFIXES:
        for resource in RESOURCES:
            paths.add(f"{prefix}/{resource}")

    paths = sorted(paths)
    print(f"\n[*] Fuzzing {len(paths)} endpoints (GET + POST = {len(paths)*2} requêtes)...")
    print(f"[*] Cible: {API_GATEWAY}\n")

    found = []
    total = len(paths) * 2
    done = 0

    for path in paths:
        for method in ["GET", "POST"]:
            done += 1
            status, size, body = fuzz_endpoint(session, method, path, token)

            if status == 404 or status == -1:
                pass  # Skip silently
            elif status == 200:
                print(f"  [+] {method:4s} {path:50s} {status} ({size}b)")
                found.append({"method": method, "path": path, "status": status, "size": size, "body": body})
            elif status == 405:
                # Method not allowed = l'endpoint existe mais pas avec cette méthode
                print(f"  [?] {method:4s} {path:50s} {status} (method not allowed)")
                found.append({"method": method, "path": path, "status": status, "size": size, "body": body})
            elif status == 401 or status == 403:
                print(f"  [!] {method:4s} {path:50s} {status} (auth issue)")
                found.append({"method": method, "path": path, "status": status, "size": size, "body": body})
            elif status == 400:
                # Bad request = l'endpoint existe mais le body est mauvais
                print(f"  [~] {method:4s} {path:50s} {status} (bad request - endpoint exists!)")
                found.append({"method": method, "path": path, "status": status, "size": size, "body": body})
            elif status != 404:
                print(f"  [?] {method:4s} {path:50s} {status} ({size}b)")
                found.append({"method": method, "path": path, "status": status, "size": size, "body": body})

            # Progress tous les 100
            if done % 200 == 0:
                print(f"  ... {done}/{total} ({len(found)} trouvés)")

            time.sleep(0.05)  # Rate limit léger

    print(f"\n{'='*60}")
    print(f"  RÉSULTAT: {len(found)} endpoints non-404 sur {total} testés")
    print(f"{'='*60}\n")

    for f in found:
        print(f"  {f['method']:4s} {f['path']:50s} -> {f['status']} ({f['size']}b)")
        if f['status'] == 200 and f['body']:
            print(f"       {f['body'][:150]}")
        print()

    # Sauvegarder
    os.makedirs(LOG_DIR, exist_ok=True)
    out = os.path.join(LOG_DIR, f"api_fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out, 'w', encoding='utf-8') as fp:
        json.dump({"timestamp": datetime.now().isoformat(), "found": found, "total_tested": total}, fp, indent=2)
    print(f"[+] Sauvegardé -> {out}")


if __name__ == "__main__":
    main()
