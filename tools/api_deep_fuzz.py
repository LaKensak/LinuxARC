"""
Deep fuzzer - maintenant qu'on connaît les préfixes /v1/pioneer/ et /v1/shared/
"""

import json
import os
import sys
import time
from datetime import datetime
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
LOG_DIR = os.path.join(DATA_DIR, 'logs')
API = "https://api-gateway.europe.es-pio.net"

RESOURCES = [
    # Confirmés
    "inventory", "quests", "profile",
    "proxy", "quilkin", "anticheat/config",
    "gameserver/status", "match/start", "match/status",
    "scenarios", "party", "announcements",
    "squad/layout", "notifications",
    # À tester - gameplay
    "loadout", "loadouts", "loadout/active", "loadout/sync",
    "equipment", "gear", "weapons",
    "currencies", "currency", "wallet", "balance",
    "crafting", "recipes", "blueprints",
    "stash", "storage", "vault",
    "characters", "character",
    # Progression
    "stats", "statistics", "stats/summary",
    "level", "xp", "rank", "ranking",
    "season", "season/progress", "season/rewards",
    "battlepass", "battle-pass",
    "progression", "progress",
    "challenges", "challenge", "daily", "weekly",
    "quests/active", "quests/completed", "quests/available",
    "codex", "codex/entries",
    "achievements", "achievement",
    "milestones", "contracts",
    "rewards", "rewards/pending", "rewards/claim",
    "entitlements",
    # Social
    "friends", "friends/list", "friends/online",
    "friend/requests", "friend/request",
    "social", "social/friends",
    "presence", "presence/friends",
    "squad", "squad/members", "squad/invite",
    "party/members", "party/invite", "party/leave",
    "clan", "guild", "group",
    "chat", "messages",
    "block", "blocked", "blocklist",
    # Match / Server
    "gameserver", "gameserver/list", "gameserver/find",
    "server", "server/list", "server/find",
    "session", "session/status", "session/create",
    "match", "match/find", "match/history", "match/result",
    "matchmaking", "matchmaking/queue", "matchmaking/cancel",
    "matchmaking/status", "matchmaking/scenarios",
    "lobby", "lobby/create", "lobby/join",
    "queue", "queue/status",
    "region", "regions", "datacenter",
    # Store
    "store", "store/offers", "store/featured",
    "shop", "shop/offers",
    "offers", "catalog",
    "bundles", "packs",
    "mtx", "microtransactions",
    "purchase", "purchases", "purchase/history",
    "premium", "premium/currency",
    # Map / World
    "map", "maps", "world",
    "zones", "zone", "locations", "location",
    "poi", "points-of-interest",
    "extraction", "extract",
    "spawn", "spawn/points",
    # Config
    "config", "configuration", "settings",
    "client-config", "game-config",
    "features", "feature-flags", "flags",
    "version", "versions", "build",
    "maintenance", "status",
    # News
    "news", "motd", "welcome",
    "events", "event", "event/active",
    "rotation", "rotations",
    "playlist", "playlists",
    # Telemetry / Analytics
    "telemetry", "analytics",
    "ping", "heartbeat", "keepalive",
    # Auth
    "auth", "token", "refresh",
    "account", "account/me",
    "user", "user/me",
    "player", "player/me",
    # Misc
    "discovery", "discover", "services",
    "gateway", "routes", "endpoints",
    "health", "healthz", "ready",
    "info", "about", "manifest",
    "anticheat", "eac",
    "ban", "bans", "report",
    "feedback",
    "tutorial", "onboarding",
    "drops", "loot", "loot-table",
    "cosmetics", "skins", "customization",
    "emotes", "sprays", "banners",
]


def load_jwt():
    f = os.path.join(DATA_DIR, "jwt_token.txt")
    if os.path.exists(f):
        with open(f, 'r') as fp:
            return fp.read().strip()
    return None


def test(session, method, path, token, body=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "EmbarkGameBoot/1.0 (Windows; 10.0.26200.1.768.64bit)",
    }
    try:
        if method == "GET":
            r = session.get(f"{API}{path}", headers=headers, timeout=5)
        else:
            r = session.post(f"{API}{path}", headers=headers, timeout=5,
                           json=body if body else {})
        return r.status_code, len(r.content), r.text[:500]
    except:
        return -1, 0, ""


def main():
    token = load_jwt()
    if not token:
        print("[!] Pas de JWT"); sys.exit(1)

    session = requests.Session()
    s, _, b = test(session, "GET", "/healthz", token)
    if s != 200:
        print(f"[!] Gateway down: {s}"); sys.exit(1)
    print(f"[+] Gateway OK\n")

    found = []
    total = 0

    for prefix in ["/v1/pioneer", "/v1/shared"]:
        print(f"=== Fuzzing {prefix}/ ===\n")
        for resource in RESOURCES:
            path = f"{prefix}/{resource}"
            for method in ["GET", "POST"]:
                total += 1
                s, sz, body = test(session, method, path, token)
                if s == 404 or s == -1:
                    continue
                tag = {200: "+", 405: "?", 400: "~", 401: "!", 403: "!", 500: "x"}.get(s, "?")
                print(f"  [{tag}] {method:4s} {path:55s} {s} ({sz}b)")
                found.append({"method": method, "path": path, "status": s,
                             "size": sz, "body": body})
                time.sleep(0.05)
            time.sleep(0.02)

    # Aussi tester /v1/ directement pour quelques cas
    print(f"\n=== Fuzzing /v1/ ===\n")
    for resource in ["pioneer", "shared", "server", "health", "healthz",
                     "discovery", "services", "config", "version", "info",
                     "gateway", "routes"]:
        for method in ["GET", "POST"]:
            path = f"/v1/{resource}"
            total += 1
            s, sz, body = test(session, method, path, token)
            if s != 404 and s != -1:
                tag = {200: "+", 405: "?", 400: "~", 401: "!", 500: "x"}.get(s, "?")
                print(f"  [{tag}] {method:4s} {path:55s} {s} ({sz}b)")
                found.append({"method": method, "path": path, "status": s,
                             "size": sz, "body": body})
            time.sleep(0.02)

    print(f"\n{'='*70}")
    print(f"  TOTAL: {len(found)} endpoints trouvés sur {total} testés")
    print(f"{'='*70}\n")

    # Résumé par statut
    by_status = {}
    for f_ in found:
        s = f_['status']
        by_status.setdefault(s, []).append(f_)

    for status in sorted(by_status.keys()):
        items = by_status[status]
        print(f"\n  --- Status {status} ({len(items)} endpoints) ---")
        for item in items:
            print(f"    {item['method']:4s} {item['path']:55s} ({item['size']}b)")
            if status == 200 and item['body']:
                print(f"         {item['body'][:120]}")

    os.makedirs(LOG_DIR, exist_ok=True)
    out = os.path.join(LOG_DIR, f"api_deep_fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out, 'w', encoding='utf-8') as fp:
        json.dump({"found": found, "total": total}, fp, indent=2)
    print(f"\n[+] Sauvegardé -> {out}")


if __name__ == "__main__":
    main()
