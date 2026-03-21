"""
Probe manifestId avec les valeurs extraites du crash context UE5.
BuildVersion: pioneer_1.17.x-CL-1096520
EngineVersion: 5.3.2-1096520+pioneer_1.17.x
GameSessionID: d6hf7hfoeoj4hc6mbo3g (session Salvage)
"""

import json
import os
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
    r = session.post(f"{API}{path}", headers=headers, timeout=10, json=body)
    return r.status_code, r.text[:500]


def main():
    token = load_jwt()
    session = requests.Session()

    print("=" * 60)
    print("  MANIFEST ID PROBING")
    print("=" * 60)

    # --- match/start avec differents formats de manifestId ---
    path = "/v1/shared/match/start"
    print(f"\n  POST {path}\n")

    manifest_candidates = [
        # Build versions du crash context
        "pioneer_1.17.x-CL-1096520",
        "pioneer_1.7.x-CL-1040958",
        # Just the CL number
        "1096520",
        "1040958",
        # CL prefix
        "CL-1096520",
        "CL-1040958",
        # Engine version format
        "5.3.2-1096520+pioneer_1.17.x",
        "5.3.2-1096520",
        # pioneer versions
        "pioneer_1.17.x",
        "pioneer_1.7.x",
        "1.17.x",
        "1.17",
        "1.7.x",
        "1.7",
        # Symbols format
        "pioneer_1.17.x-CL-1096520-Win64-Shipping",
        # Combinations with build id
        "22327254",
        f"22327254-1096520",
        f"1096520-22327254",
        # Just numbers that could be CL
        "1096520",
        # Hash-like from EpicAccountId format
        "31ee9ca276ee40ee8292d0b97e634fe3",
        # Game session IDs
        "d6hf7hfoeoj4hc6mbo3g",
        "d54rfnfoeoj3qv0ulkng",
        # BOOTARGS tokens
        "d6hf7i7oeoj4hc6mbo4g",
        "d54rfnvoeoj3qv0ulkog",
        # MachineId
        "0ADEBF9F4A08DE2AA80D04A4B9233AB1",
        # Depot ID
        "1808501",
        # Steam manifest (depot manifest)
        "9143068400471950198",
        # Could be a simple integer version
        "117",
        "17",
        "107",
        "7",
    ]

    for mid in manifest_candidates:
        status, resp = post(session, path, {"manifestId": mid}, token)
        marker = "  "
        if "INVALID_MANIFEST_ID" not in resp:
            marker = ">>"
        print(f"  {marker} {status:3d} | {mid[:50]:50s} | {resp[:60]}")

    # --- gameserver/status avec les game session IDs ---
    path = "/v1/shared/gameserver/status"
    print(f"\n{'='*60}")
    print(f"  GAMESERVER/STATUS avec session IDs")
    print(f"{'='*60}\n")

    match_candidates = [
        "d6hf7hfoeoj4hc6mbo3g",  # GameSessionID crash 1
        "d54rfnfoeoj3qv0ulkng",  # GameSessionID crash 2
        "d6hf7i7oeoj4hc6mbo4g",  # BOOTARGS crash 1
        "d54rfnvoeoj3qv0ulkog",  # BOOTARGS crash 2
        "B1E3F14C4831B806C08711ADF6882593",  # ExecutionGuid
        "31ee9ca276ee40ee8292d0b97e634fe3",  # EpicAccountId
        "0ADEBF9F4A08DE2AA80D04A4B9233AB1",  # MachineId
    ]

    for mid in match_candidates:
        status, resp = post(session, path, {"matchId": mid}, token)
        print(f"  {status:3d} | matchId={mid:45s} | {resp[:60]}")

    # --- Aussi tester le champ Go complet ---
    # L'erreur etait: "cannot unmarshal number into Go struct field GameS..."
    # Probablement GameServerStatusRequest
    # Tester si d'autres champs du struct changent la reponse
    print(f"\n{'='*60}")
    print(f"  GAMESERVER/STATUS - Struct fields additionnels")
    print(f"{'='*60}\n")

    # Avec un matchId valide (format), tester d'autres champs
    base_id = "d6hf7hfoeoj4hc6mbo3g"
    extra_fields = [
        {"matchId": base_id, "status": "connecting"},
        {"matchId": base_id, "status": "connected"},
        {"matchId": base_id, "status": "ready"},
        {"matchId": base_id, "status": "playing"},
        {"matchId": base_id, "state": "connecting"},
        {"matchId": base_id, "playerCount": 1},
        {"matchId": base_id, "players": []},
        {"matchId": base_id, "gameSessionId": base_id},
        {"matchId": base_id, "scenarioName": "Salvage"},
        {"matchId": base_id, "region": "europe"},
        {"matchId": base_id, "datacenter": "EHGG"},
    ]

    for body in extra_fields:
        status, resp = post(session, path, body, token)
        extra = {k: v for k, v in body.items() if k != "matchId"}
        extra_str = json.dumps(extra)
        marker = "  " if status == 404 else ">>"
        print(f"  {marker} {status:3d} | +{extra_str:50s} | {resp[:60]}")


if __name__ == "__main__":
    main()
