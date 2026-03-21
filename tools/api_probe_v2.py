"""
Probing avance des endpoints POST - v2
Exploite les infos connues:
  - Backend = Go + gRPC-gateway (protobuf transcoded to JSON)
  - gameserver/status: "validation error" (champs inconnus)
  - match/start: besoin d'un manifestId
  - clan: Go struct CreateClanRequest avec privacyMode type openapi (string)
  - Profil: accountId=2861568149698259187, tenancyUserId=1490730819930708316
"""

import json
import os
import sys
import requests
import urllib3
import itertools

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
API = "https://api-gateway.europe.es-pio.net"


def load_jwt():
    with open(os.path.join(DATA_DIR, "jwt_token.txt"), 'r') as f:
        return f.read().strip()


def post(session, path, body, token, content_type="application/json"):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": content_type,
        "Accept": "application/json",
        "User-Agent": "EmbarkGameBoot/1.0 (Windows; 10.0.26200.1.768.64bit)",
    }
    try:
        if content_type == "application/json":
            r = session.post(f"{API}{path}", headers=headers, timeout=10, json=body)
        else:
            r = session.post(f"{API}{path}", headers=headers, timeout=10, data=body)
        return r.status_code, r.text[:500]
    except Exception as e:
        return -1, str(e)[:200]


def get(session, path, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "EmbarkGameBoot/1.0 (Windows; 10.0.26200.1.768.64bit)",
    }
    try:
        r = session.get(f"{API}{path}", headers=headers, timeout=10)
        return r.status_code, r.text[:500]
    except Exception as e:
        return -1, str(e)[:200]


def probe_gameserver_status_v2(session, token):
    """
    Probing systematique de /v1/shared/gameserver/status
    L'erreur gRPC "validation error" = le message protobuf ne valide pas.
    On doit trouver les bons noms de champs.

    Strategie: tester des champs un par un - si un champ est accepte,
    l'erreur change (devient plus specifique ou 200).
    """
    path = "/v1/shared/gameserver/status"
    print(f"\n{'='*60}")
    print(f"  GAMESERVER/STATUS - PROBING SYSTEMATIQUE")
    print(f"{'='*60}\n")

    baseline_status, baseline_resp = post(session, path, {}, token)
    print(f"  Baseline (empty body): {baseline_status} | {baseline_resp[:80]}")
    print()

    # Phase 1: Tester des noms de champs individuels avec valeurs string
    field_names = [
        # gRPC/protobuf conventions (camelCase)
        "allocationId", "serverId", "gameServerId", "matchId", "ticketId",
        "sessionId", "connectionToken", "secretKey", "serverKey",
        "ip", "host", "address", "port", "endpoint",
        "playerId", "accountId", "userId", "teamId",
        "region", "datacenter", "zone",
        "scenarioName", "scenarioId", "scenario",
        "manifestId", "buildId", "version",
        "token", "authToken", "gameToken",
        "allocationUuid", "serverUuid", "matchUuid",
        # snake_case alternatives
        "allocation_id", "server_id", "game_server_id", "match_id",
        "ticket_id", "session_id", "connection_token", "secret_key",
        # Embark/Arc specific
        "queueId", "lobbyId", "instanceId", "worldId",
        "gameSessionId", "gameInstanceId",
        "proxyEndpoint", "quilkinToken",
        # Status specific
        "status", "state", "action", "type", "request",
        "ready", "connected", "alive",
    ]

    print(f"  Phase 1: Test {len(field_names)} champs individuels (string)")
    interesting = []
    for name in field_names:
        body = {name: "test"}
        status, resp = post(session, path, body, token)
        is_different = (status != baseline_status or resp != baseline_resp)
        marker = ">>" if is_different else "  "
        if is_different:
            interesting.append((name, status, resp))
        print(f"  {marker} {status:3d} | {name:30s} | {resp[:60]}")

    if interesting:
        print(f"\n  [!] {len(interesting)} champs avec reponse differente:")
        for name, s, r in interesting:
            print(f"      {name}: {s} | {r[:80]}")

    # Phase 2: Tester avec des valeurs entieres
    print(f"\n  Phase 2: Champs avec valeurs int")
    int_fields = [
        "allocationId", "serverId", "gameServerId", "matchId",
        "accountId", "playerId", "port", "scenarioId",
    ]
    for name in int_fields:
        body = {name: 12345}
        status, resp = post(session, path, body, token)
        is_different = (status != baseline_status or resp != baseline_resp)
        marker = ">>" if is_different else "  "
        if is_different:
            print(f"  {marker} {status:3d} | {name}=12345 | {resp[:80]}")

    # Phase 3: Tester avec des structs vides
    print(f"\n  Phase 3: Champs nested (objets vides)")
    nested_fields = [
        "server", "gameServer", "game_server", "match",
        "allocation", "connection", "proxy", "endpoint",
        "player", "session", "request", "query", "filter",
        "status", "config", "metadata", "context",
    ]
    for name in nested_fields:
        body = {name: {}}
        status, resp = post(session, path, body, token)
        is_different = (status != baseline_status or resp != baseline_resp)
        marker = ">>" if is_different else "  "
        if is_different:
            print(f"  {marker} {status:3d} | {name}={{}} | {resp[:80]}")

    # Phase 4: Tester des combinaisons avec des IPs de proxy connues
    print(f"\n  Phase 4: Avec des IPs proxy connues")
    proxy_ips = ["34.53.163.10", "34.62.249.53"]
    for ip in proxy_ips:
        bodies = [
            {"host": ip, "port": 7777},
            {"ip": ip, "port": 7777},
            {"address": ip, "port": 7777},
            {"endpoint": f"{ip}:7777"},
            {"server": {"host": ip, "port": 7777}},
            {"gameServer": {"host": ip, "port": 7777}},
            {"host": ip, "trafficPort": 7777, "qcmpPort": 7600},
        ]
        for body in bodies:
            status, resp = post(session, path, body, token)
            is_different = (status != baseline_status or resp != baseline_resp)
            marker = ">>" if is_different else "  "
            body_str = json.dumps(body)
            if len(body_str) > 55:
                body_str = body_str[:52] + "..."
            if is_different:
                print(f"  {marker} {status:3d} | {body_str:55s} | {resp[:60]}")

    # Phase 5: Body vide en bytes (protobuf empty message = valid)
    print(f"\n  Phase 5: Content-types alternatifs")
    alt_types = [
        ("application/grpc-web+proto", b""),
        ("application/grpc-web+proto", b"\x00\x00\x00\x00\x00"),
        ("application/x-protobuf", b""),
        ("application/protobuf", b""),
        ("application/octet-stream", b""),
    ]
    for ct, data in alt_types:
        status, resp = post(session, path, data, token, content_type=ct)
        is_different = (status != baseline_status or resp != baseline_resp)
        marker = ">>" if is_different else "  "
        print(f"  {marker} {status:3d} | CT={ct:35s} | {resp[:60]}")


def probe_match_start_v2(session, token):
    """
    Probing /v1/shared/match/start
    On sait qu'il faut un manifestId valide.
    """
    path = "/v1/shared/match/start"
    print(f"\n{'='*60}")
    print(f"  MATCH/START - PROBING manifestId")
    print(f"{'='*60}\n")

    # Tester differents formats de manifestId
    # Le jeu doit envoyer un hash/version du client
    manifest_candidates = [
        # Formats hash
        "22327254",  # Steam buildid
        "9143068400471950198",  # Steam manifest
        "1808500",  # Steam appid
        # UUID formats
        "00000000-0000-0000-0000-000000000000",
        # Version strings
        "1.0.0",
        "0.1.0",
        "1",
        # Hex hashes
        "a" * 32,
        "a" * 40,
        "a" * 64,
        # Embark-specific
        "9e8b37541e614575b4de303d2c2e44cf",  # EAC product ID
        # vide
        "",
    ]

    for mid in manifest_candidates:
        body = {"manifestId": mid}
        status, resp = post(session, path, body, token)
        marker = "  "
        if "INVALID_MANIFEST_ID" not in resp:
            marker = ">>"
        print(f"  {marker} {status:3d} | manifestId={mid[:40]:40s} | {resp[:60]}")

    # Tester d'autres champs en plus de manifestId
    print(f"\n  Avec manifestId + autres champs:")
    extra_fields = [
        {"manifestId": "22327254", "scenarioName": "Salvage"},
        {"manifestId": "22327254", "region": "europe"},
        {"manifestId": "22327254", "platform": "steam"},
        {"manifestId": "22327254", "buildId": "22327254"},
        {"manifestId": "22327254", "appId": "1808500"},
        {"manifestId": "22327254", "version": "1.0.0"},
    ]
    for body in extra_fields:
        status, resp = post(session, path, body, token)
        marker = "  "
        if "INVALID_MANIFEST_ID" not in resp:
            marker = ">>"
        body_str = json.dumps(body)
        print(f"  {marker} {status:3d} | {body_str[:55]:55s} | {resp[:60]}")

    # Tester sans manifestId - quels autres champs sont requis?
    print(f"\n  Sans manifestId - chercher d'autres champs requis:")
    alt_bodies = [
        {"scenario": "Salvage"},
        {"scenarioName": "Salvage"},
        {"queueType": "casual"},
        {"gameMode": "Salvage"},
        {"playlist": "Salvage"},
        {"mapName": "Salvage"},
        {"mode": "pve"},
        {"type": "quickplay"},
    ]
    for body in alt_bodies:
        status, resp = post(session, path, body, token)
        marker = ">>"  # tout est interessant ici
        body_str = json.dumps(body)
        print(f"  {marker} {status:3d} | {body_str:55s} | {resp[:60]}")


def probe_clan_v2(session, token):
    """
    On sait: name + tag + privacyMode (string openapi)
    Tester les valeurs de privacyMode
    """
    path = "/v1/shared/clan"
    print(f"\n{'='*60}")
    print(f"  CLAN - PROBING privacyMode values")
    print(f"{'='*60}\n")

    privacy_modes = [
        "Open", "Closed", "InviteOnly", "Private", "Public",
        "open", "closed", "invite_only", "private", "public",
        "OPEN", "CLOSED", "INVITE_ONLY", "PRIVATE", "PUBLIC",
        "CLAN_PRIVACY_OPEN", "CLAN_PRIVACY_CLOSED", "CLAN_PRIVACY_INVITE_ONLY",
        "clan_privacy_open", "clan_privacy_closed",
        "OpenToAll", "FriendsOnly", "RequestToJoin",
    ]

    for mode in privacy_modes:
        body = {"name": "TestClan", "tag": "TST", "privacyMode": mode}
        status, resp = post(session, path, body, token)
        marker = "  "
        if "INVALID_CLAN_PRIVACY_MODE" not in resp:
            marker = ">>"
        print(f"  {marker} {status:3d} | privacyMode={mode:30s} | {resp[:60]}")


def probe_new_endpoints(session, token):
    """Tester des endpoints GET supplementaires qu'on n'a peut-etre pas essayes"""
    print(f"\n{'='*60}")
    print(f"  ENDPOINTS SUPPLEMENTAIRES")
    print(f"{'='*60}\n")

    paths = [
        # Pioneer endpoints
        "/v1/pioneer/loadout",
        "/v1/pioneer/loadouts",
        "/v1/pioneer/progress",
        "/v1/pioneer/quests",
        "/v1/pioneer/challenges",
        "/v1/pioneer/stats",
        "/v1/pioneer/achievements",
        "/v1/pioneer/currency",
        "/v1/pioneer/wallet",
        "/v1/pioneer/store",
        "/v1/pioneer/shop",
        "/v1/pioneer/crafting",
        "/v1/pioneer/recipes",
        "/v1/pioneer/stash",
        "/v1/pioneer/vault",
        "/v1/pioneer/characters",
        "/v1/pioneer/cosmetics",
        "/v1/pioneer/settings",
        "/v1/pioneer/preferences",
        "/v1/pioneer/friends",
        "/v1/pioneer/social",
        "/v1/pioneer/notifications",
        "/v1/pioneer/seasons",
        "/v1/pioneer/battlepass",
        "/v1/pioneer/rewards",
        "/v1/pioneer/contracts",
        "/v1/pioneer/missions",
        # Shared game data
        "/v1/shared/manifest",
        "/v1/shared/manifests",
        "/v1/shared/version",
        "/v1/shared/config",
        "/v1/shared/settings",
        "/v1/shared/maps",
        "/v1/shared/modes",
        "/v1/shared/playlists",
        "/v1/shared/items",
        "/v1/shared/assets",
        "/v1/shared/catalog",
        "/v1/shared/store",
        "/v1/shared/shop",
        "/v1/shared/seasons",
        "/v1/shared/leaderboard",
        "/v1/shared/leaderboards",
        "/v1/shared/news",
        "/v1/shared/motd",
        "/v1/shared/maintenance",
        "/v1/shared/regions",
        "/v1/shared/datacenters",
        "/v1/shared/servers",
        "/v1/shared/friends",
    ]

    for path in paths:
        status, resp = get(session, path, token)
        if status not in (404, 405):
            print(f"  >> GET {status:3d} | {path:45s} | {resp[:50]}")

    # Aussi tester en POST
    post_paths = [
        "/v1/pioneer/loadout",
        "/v1/pioneer/loadouts",
        "/v1/pioneer/progress",
        "/v1/pioneer/quests",
        "/v1/pioneer/stats",
        "/v1/pioneer/stash",
        "/v1/shared/manifest",
        "/v1/shared/config",
        "/v1/shared/items",
        "/v1/shared/catalog",
        "/v1/shared/regions",
        "/v1/shared/servers",
    ]

    for path in post_paths:
        status, resp = post(session, path, {}, token)
        if status not in (404, 405):
            print(f"  >> POST {status:3d} | {path:45s} | {resp[:50]}")


def main():
    token = load_jwt()
    session = requests.Session()

    print("=" * 60)
    print("  ARC RAIDERS API PROBE v2")
    print("=" * 60)

    # Probing principal: gameserver/status
    probe_gameserver_status_v2(session, token)

    # Match/start avec manifestId
    probe_match_start_v2(session, token)

    # Clan privacyMode
    probe_clan_v2(session, token)

    # Endpoints supplementaires
    probe_new_endpoints(session, token)

    print(f"\n{'='*60}")
    print("[*] Probing v2 termine")
    print("[*] >> = reponse differente de la baseline (interessant)")
    print("=" * 60)


if __name__ == "__main__":
    main()
