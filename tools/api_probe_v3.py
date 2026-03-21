"""
Probe v3 - Exploiter les decouvertes:
1. gameserver/status accepte matchId (string) -> 404
   Tester des formats de matchId pour trouver un valide
2. Clan cree avec succes - explorer les endpoints clan
3. Capturer plus d'infos sur le struct GameServerStatusRequest
"""

import json
import os
import uuid
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
API = "https://api-gateway.europe.es-pio.net"


def load_jwt():
    with open(os.path.join(DATA_DIR, "jwt_token.txt"), 'r') as f:
        return f.read().strip()


def req(session, method, path, token, body=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "EmbarkGameBoot/1.0 (Windows; 10.0.26200.1.768.64bit)",
    }
    try:
        if method == "GET":
            r = session.get(f"{API}{path}", headers=headers, timeout=10)
        elif method == "POST":
            r = session.post(f"{API}{path}", headers=headers, timeout=10, json=body or {})
        elif method == "DELETE":
            r = session.delete(f"{API}{path}", headers=headers, timeout=10)
        elif method == "PUT":
            r = session.put(f"{API}{path}", headers=headers, timeout=10, json=body or {})
        elif method == "PATCH":
            r = session.patch(f"{API}{path}", headers=headers, timeout=10, json=body or {})
        return r.status_code, r.text[:1000]
    except Exception as e:
        return -1, str(e)[:200]


def explore_gameserver_status(session, token):
    """Approfondir gameserver/status avec matchId"""
    print(f"\n{'='*60}")
    print(f"  GAMESERVER/STATUS - matchId deep probe")
    print(f"{'='*60}\n")

    path = "/v1/shared/gameserver/status"

    # Phase 1: Le champ matchId seul donne 404 avec "test"
    # Tester si c'est le seul champ requis ou s'il en faut d'autres
    print("  Phase 1: matchId seul vs matchId + autres champs")

    # D'abord confirmer que matchId seul = 404
    s, r = req(session, "POST", path, token, {"matchId": "test"})
    print(f"  matchId='test': {s} | {r[:80]}")

    # Tester matchId + d'autres champs pour voir si l'erreur change
    combos = [
        {"matchId": "test", "allocationId": "test"},
        {"matchId": "test", "serverId": "test"},
        {"matchId": "test", "token": "test"},
        {"matchId": "test", "secretKey": "test"},
        {"matchId": "test", "connectionToken": "test"},
        {"matchId": "test", "host": "34.53.163.10"},
        {"matchId": "test", "port": 7777},
        {"matchId": "test", "region": "europe"},
        {"matchId": "test", "playerId": "test"},
        {"matchId": "test", "accountId": "2861568149698259187"},
        {"matchId": "test", "scenarioName": "Salvage"},
    ]

    for body in combos:
        s, r = req(session, "POST", path, token, body)
        marker = "  " if s == 404 else ">>"
        keys = [k for k in body.keys() if k != "matchId"]
        print(f"  {marker} {s:3d} | matchId + {keys[0]:25s} | {r[:60]}")

    # Phase 2: Formats de matchId
    print(f"\n  Phase 2: Formats de matchId")
    match_ids = [
        # UUID
        str(uuid.uuid4()),
        "c109ed93-677d-43fd-821e-000000000000",  # format similaire au clanId
        # Numeros
        "1", "0", "12345", "999999",
        # Hex
        "abcdef1234567890",
        # Long integers (comme accountId)
        "2861568149698259187",
        "1490730819930708316",
    ]

    for mid in match_ids:
        s, r = req(session, "POST", path, token, {"matchId": mid})
        marker = "  " if s == 404 else ">>"
        print(f"  {marker} {s:3d} | matchId={mid[:45]:45s} | {r[:60]}")

    # Phase 3: Le path pourrait aussi accepter matchId dans l'URL
    print(f"\n  Phase 3: matchId dans l'URL")
    url_variants = [
        "/v1/shared/gameserver/status/test",
        "/v1/shared/gameserver/status?matchId=test",
        "/v1/shared/gameserver/test",
        "/v1/shared/gameserver/test/status",
    ]
    for url in url_variants:
        s, r = req(session, "GET", url, token)
        if s != 404:
            print(f"  >> GET  {s:3d} | {url:50s} | {r[:50]}")
        s, r = req(session, "POST", url, token, {})
        if s != 404:
            print(f"  >> POST {s:3d} | {url:50s} | {r[:50]}")


def explore_clan(session, token):
    """Explorer les endpoints clan maintenant qu'on en a cree un"""
    print(f"\n{'='*60}")
    print(f"  CLAN - Explorer les sous-endpoints")
    print(f"{'='*60}\n")

    # Le clan cree: c109ed93-677d-43fd-821e...
    # D'abord recuperer les infos completes du clan
    print("  GET du clan:")
    s, r = req(session, "GET", "/v1/shared/clan", token)
    print(f"  GET /v1/shared/clan: {s} | {r[:200]}")

    # Si on a le clanId complet, tester des sous-routes
    if s == 200:
        try:
            data = json.loads(r)
            print(f"\n  Donnees clan completes:")
            print(json.dumps(data, indent=2)[:500])
            clan_id = data.get("clanId", "")

            if clan_id:
                print(f"\n  clanId: {clan_id}")
                # Sous-endpoints
                sub_paths = [
                    f"/v1/shared/clan/{clan_id}",
                    f"/v1/shared/clan/{clan_id}/members",
                    f"/v1/shared/clan/{clan_id}/info",
                    f"/v1/shared/clan/{clan_id}/settings",
                    "/v1/shared/clan/members",
                    "/v1/shared/clan/info",
                    "/v1/shared/clan/search",
                    "/v1/shared/clan/leave",
                    "/v1/shared/clan/invite",
                    "/v1/shared/clan/kick",
                ]
                for sp in sub_paths:
                    gs, gr = req(session, "GET", sp, token)
                    if gs != 404:
                        print(f"  >> GET  {gs:3d} | {sp:50s} | {gr[:50]}")
                    ps, pr = req(session, "POST", sp, token, {})
                    if ps != 404:
                        print(f"  >> POST {ps:3d} | {sp:50s} | {pr[:50]}")
        except:
            pass

    # Supprimer le clan de test si possible
    print(f"\n  Tentative de suppression du clan de test:")
    s, r = req(session, "DELETE", "/v1/shared/clan", token)
    print(f"  DELETE /v1/shared/clan: {s} | {r[:100]}")


def explore_match_flow(session, token):
    """
    Explorer le flow de matchmaking complet.
    Le manifestId est probablement un hash du build client.
    Chercher dans les logs du jeu ou les fichiers locaux.
    """
    print(f"\n{'='*60}")
    print(f"  MATCH FLOW - Recherche manifestId")
    print(f"{'='*60}\n")

    # Tester si match/status donne plus d'infos avec un vrai format
    path = "/v1/shared/match/status"
    print("  match/status avec differents ticketId:")
    tickets = [
        {"ticketId": str(uuid.uuid4())},
        {"ticketId": "test"},
        {"ticketId": ""},
        {"ticketId": "1"},
    ]
    for body in tickets:
        s, r = req(session, "POST", path, token, body)
        print(f"  {s:3d} | ticketId={body['ticketId'][:30]:30s} | {r[:60]}")

    # Tester match/cancel, match/leave etc
    print(f"\n  Sous-endpoints match:")
    match_paths = [
        "/v1/shared/match/cancel",
        "/v1/shared/match/leave",
        "/v1/shared/match/end",
        "/v1/shared/match/result",
        "/v1/shared/match/results",
        "/v1/shared/match/history",
        "/v1/shared/match/current",
        "/v1/shared/match/active",
        "/v1/shared/match/queue",
        "/v1/shared/match/dequeue",
        "/v1/shared/match/accept",
        "/v1/shared/match/reject",
        "/v1/shared/match/ready",
        "/v1/shared/match/info",
        "/v1/shared/matchmaking",
        "/v1/shared/matchmaking/status",
        "/v1/shared/matchmaking/queue",
        "/v1/shared/matchmaking/start",
    ]
    for mp in match_paths:
        gs, gr = req(session, "GET", mp, token)
        if gs not in (404, 405):
            print(f"  >> GET  {gs:3d} | {mp:45s} | {gr[:50]}")
        ps, pr = req(session, "POST", mp, token, {})
        if ps not in (404, 405):
            print(f"  >> POST {ps:3d} | {mp:45s} | {pr[:50]}")


def explore_pioneer_endpoints(session, token):
    """Explorer les endpoints pioneer en detail"""
    print(f"\n{'='*60}")
    print(f"  PIONEER - Endpoints supplementaires")
    print(f"{'='*60}\n")

    paths = [
        "/v1/pioneer/quests",
        "/v1/pioneer/loadout",
        "/v1/pioneer/loadouts",
        "/v1/pioneer/progress",
        "/v1/pioneer/stash",
        "/v1/pioneer/vault",
        "/v1/pioneer/characters",
        "/v1/pioneer/character",
        "/v1/pioneer/equipment",
        "/v1/pioneer/cosmetics",
        "/v1/pioneer/currency",
        "/v1/pioneer/wallet",
        "/v1/pioneer/seasons",
        "/v1/pioneer/battlepass",
        "/v1/pioneer/contracts",
        "/v1/pioneer/missions",
        "/v1/pioneer/crafting",
        "/v1/pioneer/recipes",
        "/v1/pioneer/upgrades",
        "/v1/pioneer/profile",
        "/v1/pioneer/settings",
        "/v1/pioneer/preferences",
        "/v1/pioneer/stats",
        "/v1/pioneer/history",
        "/v1/pioneer/rewards",
        "/v1/pioneer/claims",
        "/v1/pioneer/notifications",
        "/v1/pioneer/inbox",
        "/v1/pioneer/friends",
        "/v1/pioneer/social",
        "/v1/pioneer/squads",
        "/v1/pioneer/squad",
        "/v1/pioneer/party",
    ]

    for p in paths:
        gs, gr = req(session, "GET", p, token)
        if gs not in (404, 405):
            print(f"  >> GET  {gs:3d} | {p:45s} | {gr[:60]}")
        ps, pr = req(session, "POST", p, token, {})
        if ps not in (404, 405):
            print(f"  >> POST {ps:3d} | {p:45s} | {pr[:60]}")


def save_results(session, token):
    """Sauvegarder les donnees des endpoints qui marchent"""
    print(f"\n{'='*60}")
    print(f"  SAUVEGARDE DES NOUVELLES DONNEES")
    print(f"{'='*60}\n")

    dump_dir = os.path.join(DATA_DIR, 'api_dump')
    os.makedirs(dump_dir, exist_ok=True)

    # Clan data
    s, r = req(session, "GET", "/v1/shared/clan", token)
    if s == 200:
        with open(os.path.join(dump_dir, 'v1_shared_clan.json'), 'w') as f:
            f.write(r)
        print(f"  [+] Clan data sauvegardee ({len(r)} bytes)")

    # Quests (meme si 500, on sauvegarde l'erreur)
    s, r = req(session, "GET", "/v1/pioneer/quests", token)
    if s != 404:
        with open(os.path.join(dump_dir, 'v1_pioneer_quests.json'), 'w') as f:
            f.write(r)
        print(f"  [+] Quests response sauvegardee ({s}, {len(r)} bytes)")


def main():
    token = load_jwt()
    session = requests.Session()

    print("=" * 60)
    print("  ARC RAIDERS API PROBE v3")
    print("=" * 60)

    explore_gameserver_status(session, token)
    explore_clan(session, token)
    explore_match_flow(session, token)
    explore_pioneer_endpoints(session, token)
    save_results(session, token)

    print(f"\n{'='*60}")
    print("[*] Probe v3 termine")
    print("=" * 60)


if __name__ == "__main__":
    main()
