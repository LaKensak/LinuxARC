"""
Probe les endpoints POST pour trouver le bon format de body.
Teste différentes structures JSON pour gameserver/status, match/start, scenarios, etc.
"""

import json
import os
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
API = "https://api-gateway.europe.es-pio.net"


def load_jwt():
    with open(os.path.join(DATA_DIR, "jwt_token.txt"), 'r') as f:
        return f.read().strip()


def post(session, path, body, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "EmbarkGameBoot/1.0 (Windows; 10.0.26200.1.768.64bit)",
    }
    try:
        r = session.post(f"{API}{path}", headers=headers, timeout=10, json=body)
        return r.status_code, r.text[:500]
    except Exception as e:
        return -1, str(e)[:200]


def probe_gameserver_status(session, token):
    """Probe /v1/shared/gameserver/status avec différents bodies"""
    path = "/v1/shared/gameserver/status"
    print(f"\n{'='*60}")
    print(f"  PROBING: POST {path}")
    print(f"{'='*60}\n")

    bodies = [
        # Structures basiques
        {},
        {"ticketId": ""},
        {"ticketId": "test"},
        {"ticket_id": "test"},
        {"sessionId": "test"},
        {"session_id": "test"},
        # Avec les données du profil
        {"accountId": 2861568149698259187},
        {"account_id": "2861568149698259187"},
        {"userId": "1490730819930708316"},
        {"user_id": "1490730819930708316"},
        # Structure matchmaking
        {"scenarioName": "default"},
        {"scenario_name": "default"},
        {"region": "europe"},
        {"datacenter": "EHGG"},
        # Combinaisons
        {"ticketId": "", "scenarioName": ""},
        {"ticket_id": "", "scenario_name": ""},
        {"matchId": ""},
        {"match_id": ""},
        # Structure serveur
        {"serverId": ""},
        {"server_id": ""},
        {"host": ""},
        {"gameServerId": ""},
        # Proto-like nested
        {"gameserver": {}},
        {"gameserver": {"id": ""}},
        {"status": {}},
        {"request": {}},
        # Listes
        {"filters": []},
        {"preferences": {"region": "europe"}},
    ]

    for body in bodies:
        status, resp = post(session, path, body, token)
        body_str = json.dumps(body)
        if len(body_str) > 60:
            body_str = body_str[:57] + "..."
        # Highlight anything that's not the standard validation error
        marker = "  "
        if status != 400 or "validation error" not in resp:
            marker = ">>"
        print(f"  {marker} {status:3d} | {body_str:60s} | {resp[:80]}")


def probe_match_start(session, token):
    """Probe /v1/shared/match/start"""
    path = "/v1/shared/match/start"
    print(f"\n{'='*60}")
    print(f"  PROBING: POST {path}")
    print(f"{'='*60}\n")

    bodies = [
        {},
        {"scenarioName": ""},
        {"scenarioName": "Salvage"},
        {"scenarioName": "salvage"},
        {"scenarioName": "default"},
        {"scenario_name": "salvage"},
        {"scenario": "salvage"},
        {"mode": "salvage"},
        {"gameMode": "salvage"},
        {"game_mode": "salvage"},
        {"scenarioName": "Salvage", "region": "europe"},
        {"scenarioName": "Salvage", "datacenter": "EHGG"},
        {"queueType": "casual"},
        {"queue_type": "casual"},
        {"playlist": "default"},
        {"matchType": "public"},
    ]

    for body in bodies:
        status, resp = post(session, path, body, token)
        body_str = json.dumps(body)
        marker = "  "
        if status != 400:
            marker = ">>"
        print(f"  {marker} {status:3d} | {body_str:60s} | {resp[:80]}")


def probe_scenarios(session, token):
    """Probe /v1/shared/scenarios"""
    path = "/v1/shared/scenarios"
    print(f"\n{'='*60}")
    print(f"  PROBING: POST {path}")
    print(f"{'='*60}\n")

    bodies = [
        {},
        {"region": "europe"},
        {"platform": "steam"},
        {"platform": "pc"},
        {"filter": {}},
        {"active": True},
        {"version": "1.0"},
        {"client_version": "1.0"},
        {"appId": "1808500"},
        {"app_id": "1808500"},
        # Le profil a tos_version_seen: "3"
        {"tos_version": "3"},
        {"locale": "fr"},
        {"language": "fr"},
    ]

    for body in bodies:
        status, resp = post(session, path, body, token)
        body_str = json.dumps(body)
        marker = "  "
        if status != 500:
            marker = ">>"
        print(f"  {marker} {status:3d} | {body_str:60s} | {resp[:80]}")


def probe_announcements(session, token):
    """Probe /v1/shared/announcements"""
    path = "/v1/shared/announcements"
    print(f"\n{'='*60}")
    print(f"  PROBING: POST {path}")
    print(f"{'='*60}\n")

    bodies = [
        {},
        {"locale": "fr"},
        {"language": "fr"},
        {"platform": "steam"},
        {"version": "1.0"},
        {"app_id": "1808500"},
        {"region": "europe"},
        {"locale": "en"},
    ]

    for body in bodies:
        status, resp = post(session, path, body, token)
        body_str = json.dumps(body)
        marker = "  "
        if status != 500:
            marker = ">>"
        print(f"  {marker} {status:3d} | {body_str:60s} | {resp[:80]}")


def probe_clan(session, token):
    """Probe /v1/shared/clan"""
    path = "/v1/shared/clan"
    print(f"\n{'='*60}")
    print(f"  PROBING: POST {path}")
    print(f"{'='*60}\n")

    bodies = [
        {},
        {"name": "test"},
        {"clanId": ""},
        {"clan_id": ""},
        {"id": ""},
        {"action": "list"},
        {"action": "get"},
        {"userId": "1490730819930708316"},
    ]

    for body in bodies:
        status, resp = post(session, path, body, token)
        body_str = json.dumps(body)
        marker = "  "
        if status != 400:
            marker = ">>"
        print(f"  {marker} {status:3d} | {body_str:60s} | {resp[:80]}")


def probe_feature_flags(session, token):
    """Probe /v1/shared/feature-flags"""
    path = "/v1/shared/feature-flags"
    print(f"\n{'='*60}")
    print(f"  PROBING: POST {path}")
    print(f"{'='*60}\n")

    bodies = [
        {},
        {"platform": "steam"},
        {"platform": "pc"},
        {"version": "1.0"},
        {"app_id": "1808500"},
        {"flags": []},
        {"client_version": "1.0.0"},
    ]

    for body in bodies:
        status, resp = post(session, path, body, token)
        body_str = json.dumps(body)
        marker = "  "
        if status != 500:
            marker = ">>"
        print(f"  {marker} {status:3d} | {body_str:60s} | {resp[:80]}")


def probe_match_status(session, token):
    """Probe /v1/shared/match/status - on sait qu'il attend un ticketId"""
    path = "/v1/shared/match/status"
    print(f"\n{'='*60}")
    print(f"  PROBING: POST {path}")
    print(f"{'='*60}\n")

    bodies = [
        {},
        {"ticketId": ""},
        {"ticketId": "test-ticket"},
        {"ticket_id": "test"},
        {"matchId": "test"},
    ]

    for body in bodies:
        status, resp = post(session, path, body, token)
        body_str = json.dumps(body)
        marker = "  "
        if "TICKET_NOT_FOUND" not in resp and status != 404:
            marker = ">>"
        print(f"  {marker} {status:3d} | {body_str:60s} | {resp[:80]}")


def main():
    token = load_jwt()
    session = requests.Session()

    print("=" * 60)
    print("  ARC RAIDERS API POST BODY PROBER")
    print("=" * 60)

    probe_scenarios(session, token)
    probe_announcements(session, token)
    probe_feature_flags(session, token)
    probe_match_start(session, token)
    probe_gameserver_status(session, token)
    probe_match_status(session, token)
    probe_clan(session, token)

    print("\n[*] Probing terminé")
    print("[*] Les lignes marquées >> sont des réponses intéressantes (pas l'erreur standard)")


if __name__ == "__main__":
    main()
