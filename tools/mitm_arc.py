"""
mitmproxy addon pour intercepter l'API Arc Raiders
Capture toutes les requêtes/réponses vers les serveurs Embark Studios (IPv4+IPv6)
Capture le JWT OAuth2 pour réutilisation directe

Usage:
    mitmdump -s tools/mitm_arc.py --mode local --ssl-insecure
"""

import json
import os
import time
from datetime import datetime
from mitmproxy import http, ctx

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'logs')
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')

# Hosts Embark Studios (IPv4 + IPv6)
EMBARK_HOSTS = {
    "34.160.204.112",       # api-gateway IPv4
    "2600:1901:0:6f08::",   # api-gateway IPv6
    "2600:1901:0:4ab5::",   # auth.embark.net IPv6
    "api-gateway.europe.es-pio.net",
    "auth.embark.net",
    "client2pubsub.europe.es-pio.net",
}

# Données capturées
captured = {
    'jwt_token': None,
    'jwt_raw_response': None,
    'gameserver': None,
    'secret_key': None,
    'routing_token': None,
    'players': [],
    'proxy_endpoints': [],
    'match': None,
    'anticheat_config': None,
    'all_requests': [],
}


def is_embark_host(host):
    """Check si le host est un serveur Embark"""
    if not host:
        return False
    # Nettoyer les crochets IPv6
    clean = host.strip("[]")
    if clean in EMBARK_HOSTS:
        return True
    # Check partiel
    for h in EMBARK_HOSTS:
        if h in clean or clean in h:
            return True
    # Check domaine
    if "es-pio" in clean or "embark" in clean:
        return True
    return False


class ArcRaidersInterceptor:
    def __init__(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        os.makedirs(DATA_DIR, exist_ok=True)
        self.log_file = os.path.join(LOG_DIR, f"ARC_Sniffer_{datetime.now().strftime('%Y%m%d')}_api.jsonl")
        self.jwt_file = os.path.join(DATA_DIR, "jwt_token.json")
        ctx.log.info(f"[ARC] Intercepteur actif - log: {self.log_file}")
        ctx.log.info(f"[ARC] Surveillance: IPv6 [2600:1901:0:6f08::] + [2600:1901:0:4ab5::] + 34.160.204.112")

    def response(self, flow: http.HTTPFlow):
        """Intercepte les réponses des serveurs Embark"""
        host = flow.request.host or ''
        if not is_embark_host(host):
            return

        url = flow.request.url
        path = flow.request.path
        method = flow.request.method
        status = flow.response.status_code

        # Log toutes les requêtes Embark
        ctx.log.warn(f"[ARC] >>> {method} {path} -> {status}")

        # Capturer les headers de la requête (pour le JWT Bearer)
        req_headers = dict(flow.request.headers)
        resp_headers = dict(flow.response.headers)

        # Décoder le body de la réponse (peut être JSON, protobuf, ou autre)
        resp_body_raw = flow.response.get_content()
        resp_body_text = None
        resp_data = None

        try:
            resp_body_text = flow.response.get_text()
            if resp_body_text:
                resp_data = json.loads(resp_body_text)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            pass

        # Décoder le body de la requête
        req_body = None
        req_body_text = None
        try:
            req_body_text = flow.request.get_text()
            if req_body_text:
                req_body = json.loads(req_body_text)
        except:
            pass

        timestamp = datetime.now().isoformat()

        # === CAPTURE JWT TOKEN ===
        if '/oauth2/token' in path:
            self._capture_jwt(resp_data, resp_body_text, req_body, req_body_text, req_headers, timestamp)

        # === CAPTURE AUTHORIZATION HEADER ===
        auth_header = req_headers.get('authorization', req_headers.get('Authorization', ''))
        if auth_header.startswith('Bearer ') and not captured['jwt_token']:
            token = auth_header[7:]
            captured['jwt_token'] = token
            ctx.log.warn(f"[ARC] JWT capturé depuis header Authorization! ({len(token)} chars)")
            self._save_jwt(token, timestamp, "authorization_header")

        # Log dans le fichier JSONL
        entry = {
            'timestamp': timestamp,
            'host': host,
            'method': method,
            'path': path,
            'url': url,
            'status': status,
            'request_headers': {k: v for k, v in req_headers.items()
                               if k.lower() in ('authorization', 'content-type', 'user-agent', 'x-request-id')},
            'request_body': req_body if req_body else req_body_text,
            'response_headers': {k: v for k, v in resp_headers.items()
                                if k.lower() in ('content-type', 'x-request-id', 'grpc-status')},
            'response_body': resp_data if resp_data else (resp_body_text[:500] if resp_body_text else
                                                          resp_body_raw.hex()[:200] if resp_body_raw else None),
            'response_size': len(resp_body_raw) if resp_body_raw else 0,
        }

        # Sauver dans le JSONL
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + '\n')

        # Track toutes les requêtes
        captured['all_requests'].append({
            'timestamp': timestamp,
            'method': method,
            'path': path,
            'status': status,
        })

        # Analyser les réponses importantes
        if resp_data:
            self._analyze(path, resp_data, timestamp)

    def _capture_jwt(self, resp_data, resp_text, req_body, req_text, req_headers, timestamp):
        """Capture le JWT depuis la réponse oauth2/token"""
        ctx.log.warn("=" * 60)
        ctx.log.warn("[ARC] !!! OAUTH2 TOKEN RESPONSE CAPTURED !!!")

        # Le token peut être dans différents champs
        token = None
        if resp_data:
            token = (resp_data.get('access_token') or
                     resp_data.get('token') or
                     resp_data.get('id_token'))
            ctx.log.warn(f"[ARC] Response keys: {list(resp_data.keys())}")
            # Log tout le contenu
            for key, value in resp_data.items():
                val_str = str(value)
                if len(val_str) > 100:
                    ctx.log.warn(f"[ARC]   {key}: {val_str[:80]}...({len(val_str)} chars)")
                else:
                    ctx.log.warn(f"[ARC]   {key}: {val_str}")
        elif resp_text:
            ctx.log.warn(f"[ARC] Raw response: {resp_text[:500]}")
            # Essayer de trouver un JWT dans le texte brut (format: eyJ...)
            import re
            jwt_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp_text)
            if jwt_match:
                token = jwt_match.group(0)

        if token:
            captured['jwt_token'] = token
            ctx.log.warn(f"[ARC] JWT TOKEN: {token[:60]}...")
            ctx.log.warn(f"[ARC] JWT length: {len(token)}")
            self._save_jwt(token, timestamp, "oauth2_response")
        else:
            ctx.log.warn("[ARC] No JWT found in response - saving raw response")
            captured['jwt_raw_response'] = resp_text or str(resp_data)

        # Log aussi la requête pour comprendre le flow
        if req_body:
            ctx.log.warn(f"[ARC] Request body: {json.dumps(req_body)[:200]}")
        elif req_text:
            ctx.log.warn(f"[ARC] Request text: {req_text[:200]}")

        ctx.log.warn("=" * 60)

    def _save_jwt(self, token, timestamp, source):
        """Sauvegarde le JWT dans un fichier"""
        jwt_data = {
            'token': token,
            'captured_at': timestamp,
            'source': source,
        }

        # Décoder le JWT (base64) pour extraire les claims
        try:
            import base64
            parts = token.split('.')
            if len(parts) >= 2:
                # Padding base64
                payload = parts[1]
                padding = 4 - len(payload) % 4
                if padding != 4:
                    payload += '=' * padding
                claims = json.loads(base64.urlsafe_b64decode(payload))
                jwt_data['claims'] = claims
                jwt_data['subject'] = claims.get('sub')
                jwt_data['issuer'] = claims.get('iss')
                jwt_data['expires_at'] = claims.get('exp')
                jwt_data['audience'] = claims.get('aud')
                ctx.log.warn(f"[ARC] JWT sub: {claims.get('sub')}")
                ctx.log.warn(f"[ARC] JWT iss: {claims.get('iss')}")
                ctx.log.warn(f"[ARC] JWT exp: {claims.get('exp')}")
                ctx.log.warn(f"[ARC] JWT aud: {claims.get('aud')}")
        except Exception as e:
            ctx.log.warn(f"[ARC] JWT decode error: {e}")

        with open(self.jwt_file, 'w', encoding='utf-8') as f:
            json.dump(jwt_data, f, indent=2, ensure_ascii=False, default=str)

        ctx.log.warn(f"[ARC] JWT sauvegardé -> {self.jwt_file}")

        # Aussi sauvegarder le token brut pour usage facile
        token_file = os.path.join(DATA_DIR, "jwt_token.txt")
        with open(token_file, 'w') as f:
            f.write(token)

    def _analyze(self, path, data, timestamp):
        """Analyse et affiche les données importantes"""

        # === ANTICHEAT CONFIG ===
        if '/anticheat/config' in path:
            captured['anticheat_config'] = data
            ctx.log.warn(f"[ARC] Anticheat config: {json.dumps(data)[:200]}")

        # === GAMESERVER STATUS (secretKey!) ===
        elif '/gameserver/status' in path:
            gs = data.get('gameserver', {})
            captured['gameserver'] = gs
            captured['secret_key'] = gs.get('secretKey')
            captured['routing_token'] = gs.get('routingToken')

            ctx.log.warn("=" * 60)
            ctx.log.warn("[ARC] GAMESERVER CAPTURED!")
            ctx.log.warn(f"  Host: {gs.get('host')}:{gs.get('port')}")
            ctx.log.warn(f"  DC: {gs.get('datacenterIcaoCode')}")
            ctx.log.warn(f"  SecretKey: {gs.get('secretKey', 'N/A')[:20]}...")
            ctx.log.warn(f"  RoutingToken: {gs.get('routingToken', 'N/A')[:20]}...")
            ctx.log.warn("=" * 60)
            self._save_captured()

        # === SQUAD LAYOUT ===
        elif '/squad/layout' in path:
            players = []
            for squad in data.get('squads', []):
                squad_id = squad.get('squad_id', '?')
                for member in squad.get('squad_members', []):
                    p = member.get('profile', {})
                    dn = p.get('displayName', {})
                    name = f"{dn.get('name', '?')}#{dn.get('discriminator', '?')}"
                    players.append({
                        'name': name,
                        'squad_id': squad_id,
                        'account_id': p.get('accountId'),
                        'tenancy_user_id': p.get('tenancyUserId'),
                    })
            captured['players'] = players
            ctx.log.warn(f"[ARC] SQUAD LAYOUT - {len(players)} joueurs")
            for p in players:
                ctx.log.warn(f"  > {p['name']} (Squad: {p['squad_id'][:8]}...)")

        # === MATCH ===
        elif '/match/start' in path or '/match/status' in path:
            captured['match'] = data
            ctx.log.info(f"[ARC] Match: {data.get('matchState', '?')} | {data.get('scenarioName', '?')}")

        # === PROXY ENDPOINTS ===
        elif '/proxy' in path and 'endpoints' in data:
            captured['proxy_endpoints'] = data.get('endpoints', [])
            ctx.log.info(f"[ARC] {len(captured['proxy_endpoints'])} proxy endpoints")

        # === Tout le reste ===
        else:
            keys = list(data.keys())[:5]
            ctx.log.info(f"[ARC] {path} -> {keys}")

        # Sauvegarder après chaque réponse Embark
        self._save_captured()

    def _save_captured(self):
        """Sauvegarde les données capturées"""
        save_file = os.path.join(LOG_DIR, f"ARC_Sniffer_{datetime.now().strftime('%Y%m%d')}_captured.json")
        with open(save_file, 'w', encoding='utf-8') as f:
            json.dump(captured, f, indent=2, ensure_ascii=False, default=str)


addons = [ArcRaidersInterceptor()]
