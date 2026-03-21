"""
Dump toutes les données des endpoints connus d'Arc Raiders
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

ENDPOINTS = [
    ("GET", "/v1/pioneer/inventory"),
    ("GET", "/v1/pioneer/quests"),
    ("GET", "/v1/shared/profile"),
    ("GET", "/v1/shared/proxy"),
    ("GET", "/v1/shared/quilkin"),
    ("GET", "/v1/shared/anticheat/config"),
    ("POST", "/v1/shared/gameserver/status", {}),
    ("POST", "/v1/shared/match/status", {}),
    ("POST", "/v1/shared/scenarios", {}),
    ("POST", "/v1/shared/announcements", {}),
    ("POST", "/v1/shared/party", {}),
]


def main():
    jwt_file = os.path.join(DATA_DIR, "jwt_token.txt")
    with open(jwt_file, 'r') as f:
        token = f.read().strip()

    session = requests.Session()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "EmbarkGameBoot/1.0 (Windows; 10.0.26200.1.768.64bit)",
    }

    dump_dir = os.path.join(DATA_DIR, "api_dump")
    os.makedirs(dump_dir, exist_ok=True)

    for ep in ENDPOINTS:
        method = ep[0]
        path = ep[1]
        body = ep[2] if len(ep) > 2 else None

        print(f"\n{'='*60}")
        print(f"  {method} {path}")
        print(f"{'='*60}")

        try:
            if method == "GET":
                r = session.get(f"{API}{path}", headers=headers, timeout=10)
            else:
                r = session.post(f"{API}{path}", headers=headers, timeout=10, json=body)

            print(f"  Status: {r.status_code} | Size: {len(r.content)}b")
            print(f"  Content-Type: {r.headers.get('content-type', '?')}")

            # Sauvegarder
            safe_name = path.replace("/", "_").strip("_")
            out_file = os.path.join(dump_dir, f"{safe_name}.json")

            try:
                data = r.json()
                with open(out_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                # Afficher un résumé
                if isinstance(data, dict):
                    keys = list(data.keys())
                    print(f"  Keys: {keys}")
                    for k in keys[:5]:
                        v = data[k]
                        if isinstance(v, list):
                            print(f"    {k}: [{len(v)} items]")
                        elif isinstance(v, str) and len(v) > 100:
                            print(f"    {k}: {v[:80]}...")
                        else:
                            print(f"    {k}: {v}")
                elif isinstance(data, list):
                    print(f"  Array: {len(data)} items")

            except:
                out_file = os.path.join(dump_dir, f"{safe_name}.txt")
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(r.text)
                print(f"  Body: {r.text[:200]}")

            print(f"  -> {out_file}")

        except Exception as e:
            print(f"  Error: {e}")

    print(f"\n[+] Dump terminé -> {dump_dir}")


if __name__ == "__main__":
    main()
