"""
Probe l'endpoint /v1/shared/manifest et d'autres endpoints
pour trouver le manifestId.
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


def req(session, method, path, body, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "EmbarkGameBoot/1.0 (Windows; 10.0.26200.1.768.64bit)",
    }
    try:
        if method == "POST":
            r = session.post(f"{API}{path}", headers=headers, timeout=10, json=body)
        elif method == "GET":
            r = session.get(f"{API}{path}", headers=headers, timeout=10)
        elif method == "PUT":
            r = session.put(f"{API}{path}", headers=headers, timeout=10, json=body)
        elif method == "PATCH":
            r = session.patch(f"{API}{path}", headers=headers, timeout=10, json=body)
        return r.status_code, r.text[:2000]
    except Exception as e:
        return -1, str(e)[:200]


def main():
    token = load_jwt()
    session = requests.Session()

    print("=" * 60)
    print("  MANIFEST ENDPOINT PROBING")
    print("=" * 60)

    # 1. POST /v1/shared/manifest - endpoint confirmé existant (GET=405)
    print("\n--- POST /v1/shared/manifest ---")
    bodies = [
        {},
        {"manifestId": ""},
        {"version": ""},
        {"buildVersion": ""},
        {"clientVersion": ""},
        {"platform": "windows"},
        {"platform": "steam"},
        {"appId": "1808500"},
        {"appId": 1808500},
        {"buildId": ""},
        {"gameVersion": "pioneer_1.20.x"},
    ]
    for body in bodies:
        s, r = req(session, "POST", "/v1/shared/manifest", body, token)
        print(f"  {s:3d} | {json.dumps(body):50s} | {r[:80]}")

    # 2. Sous-paths de /v1/shared/manifest
    print("\n--- /v1/shared/manifest/* ---")
    subpaths = [
        "current", "latest", "version", "id", "active",
        "game", "client", "build", "config", "check",
    ]
    for sub in subpaths:
        for method in ["GET", "POST"]:
            s, r = req(session, method, f"/v1/shared/manifest/{sub}", {}, token)
            if s != 404:
                print(f"  {method} /v1/shared/manifest/{sub}: {s} | {r[:80]}")

    # 3. /v1/pioneer/manifest
    print("\n--- /v1/pioneer/manifest ---")
    for method in ["GET", "POST"]:
        s, r = req(session, method, "/v1/pioneer/manifest", {}, token)
        print(f"  {method}: {s} | {r[:80]}")

    # 4. /v1/shared/version ou /v1/shared/config
    print("\n--- Endpoints config/version ---")
    config_paths = [
        "/v1/shared/version",
        "/v1/shared/config",
        "/v1/shared/settings",
        "/v1/shared/client/config",
        "/v1/shared/game/config",
        "/v1/shared/game/version",
        "/v1/shared/boot",
        "/v1/shared/boot/config",
        "/v1/shared/login",
        "/v1/shared/login/config",
        "/v1/shared/session",
        "/v1/shared/session/start",
        "/v1/pioneer/config",
        "/v1/pioneer/version",
        "/v1/pioneer/boot",
        "/v1/pioneer/session",
        "/v1/pioneer/manifest",
        "/v1/pioneer/settings",
        "/v1/shared/match/manifest",
        "/v1/shared/match/config",
        "/v1/shared/manifest/current",
        "/v1/shared/build",
        "/v1/shared/build/version",
        "/v1/shared/build/manifest",
        "/v1/shared/client",
        "/v1/shared/client/version",
    ]
    for path in config_paths:
        for method in ["GET", "POST"]:
            s, r = req(session, method, path, {}, token)
            if s not in (404, 401):
                marker = ">>" if s == 200 else "  "
                print(f"  {marker} {method:4s} {path:45s} {s:3d} | {r[:80]}")

    # 5. feature-flags en détail
    print("\n--- POST /v1/shared/feature-flags ---")
    flag_bodies = [
        {},
        {"flags": []},
        {"flags": ["manifest"]},
        {"names": []},
        {"platform": "windows"},
        {"clientVersion": "pioneer_1.20.x"},
        {"gameVersion": "pioneer_1.20.x"},
    ]
    for body in flag_bodies:
        s, r = req(session, "POST", "/v1/shared/feature-flags", body, token)
        print(f"  {s:3d} | {json.dumps(body):50s} | {r[:100]}")

    # 6. Tester match/start avec des formats UUID
    print("\n--- match/start avec UUID ---")
    import uuid
    uuid_tests = [
        str(uuid.uuid4()),  # Random UUID
        "00000000-0000-0000-0000-000000000000",  # Nil UUID
        str(uuid.uuid5(uuid.NAMESPACE_DNS, "pioneer_1.20.x")),
        str(uuid.uuid5(uuid.NAMESPACE_DNS, "arc-raiders")),
        str(uuid.uuid5(uuid.NAMESPACE_URL, "https://api-gateway.europe.es-pio.net")),
    ]
    for uid in uuid_tests:
        s, r = req(session, "POST", "/v1/shared/match/start", {"manifestId": uid}, token)
        marker = ">>" if "INVALID_MANIFEST_ID" not in r else "  "
        print(f"  {marker} {s:3d} | {uid} | {r[:60]}")

    # 7. scenarios - pourrait contenir des manifest IDs
    print("\n--- POST /v1/shared/scenarios ---")
    scenario_bodies = [
        {},
        {"manifestId": ""},
        {"scenarioId": ""},
        {"name": ""},
        {"type": "salvage"},
        {"scenarioName": "Salvage"},
        {"mode": "salvage"},
        {"region": "europe"},
    ]
    for body in scenario_bodies:
        s, r = req(session, "POST", "/v1/shared/scenarios", body, token)
        if s != 500 or body == {}:
            print(f"  {s:3d} | {json.dumps(body):50s} | {r[:100]}")


if __name__ == "__main__":
    main()
