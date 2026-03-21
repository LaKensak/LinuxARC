"""
Addon mitmproxy pour capturer les requetes de matchmaking Arc Raiders.
Usage: mitmproxy --mode local --set block_global=false -s capture_match_addon.py
"""

import json
import os
import datetime
from mitmproxy import http

DUMP_DIR = r"F:\\Raid\\pythonProject4\\data\\captures"
os.makedirs(DUMP_DIR, exist_ok=True)

INTERESTING_PATHS = [
    "/v1/shared/match/",
    "/v1/shared/gameserver/",
    "/v1/shared/party/",
    "/v1/shared/scenarios",
    "/v1/shared/feature-flags",
]

class MatchCapture:
    def __init__(self):
        self.captures = []
        print("[*] MatchCapture addon loaded - watching for match/gameserver requests")

    def response(self, flow: http.HTTPFlow):
        if not flow.request.pretty_host.endswith("es-pio.net"):
            return

        path = flow.request.path
        is_interesting = any(p in path for p in INTERESTING_PATHS)

        # Log tout ce qui va vers l'API gateway
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        method = flow.request.method
        status = flow.response.status_code

        req_body = ""
        if flow.request.content:
            try:
                req_body = flow.request.content.decode("utf-8", errors="replace")
            except:
                req_body = f"<binary {len(flow.request.content)} bytes>"

        resp_body = ""
        if flow.response.content:
            try:
                resp_body = flow.response.content.decode("utf-8", errors="replace")
            except:
                resp_body = f"<binary {len(flow.response.content)} bytes>"

        # Highlight les requetes interessantes
        marker = ">>>" if is_interesting else "   "
        print(f"{marker} [{ts}] {method} {path} -> {status}")
        if is_interesting:
            if req_body:
                print(f"    REQ: {req_body[:200]}")
            if resp_body:
                print(f"    RESP: {resp_body[:500]}")

            # Sauvegarder
            capture = {
                "timestamp": ts,
                "method": method,
                "path": path,
                "status": status,
                "request_headers": dict(flow.request.headers),
                "request_body": req_body[:5000],
                "response_headers": dict(flow.response.headers),
                "response_body": resp_body[:50000],
            }
            self.captures.append(capture)

            # Sauvegarder a chaque capture interessante
            dump_file = os.path.join(DUMP_DIR, "match_captures.json")
            with open(dump_file, "w") as f:
                json.dump(self.captures, f, indent=2)

            # Si on capture un match/start avec un ticketId, c'est jackpot!
            if "match/start" in path and status == 200:
                print(f"\n{'!'*60}")
                print(f"  JACKPOT! match/start reussie!")
                print(f"  Response: {resp_body[:1000]}")
                print(f"{'!'*60}\n")

            # Si on capture gameserver/status avec des donnees
            if "gameserver/status" in path and status == 200:
                print(f"\n{'!'*60}")
                print(f"  JACKPOT! gameserver/status avec donnees!")
                print(f"  Response: {resp_body[:1000]}")
                print(f"{'!'*60}\n")

        # Capturer aussi les headers Authorization pour le JWT
        auth = flow.request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            jwt_file = os.path.join(DUMP_DIR, "latest_jwt.txt")
            with open(jwt_file, "w") as f:
                f.write(auth[7:])

addons = [MatchCapture()]
