"""
Intercepteur API REST Arc Raiders
Capture les appels HTTPS vers l'API Embark pour extraire:
- secretKey (déchiffrement UDP)
- routingToken
- squad layout (joueurs dans le match)
- gameserver info (IP, port)
"""

import json
import logging
import threading
import time
import re
from datetime import datetime
from scapy.all import sniff, TCP, Raw, IP

logger = logging.getLogger(__name__)


class APIInterceptor:
    """Intercepte et décode les appels API REST d'Arc Raiders"""

    API_HOST = "34.160.204.112"

    # Endpoints à surveiller
    ENDPOINTS = {
        '/shared/gameserver/status': 'gameserver_status',
        '/shared/squad/layout': 'squad_layout',
        '/shared/match/start': 'match_start',
        '/shared/match/status': 'match_status',
        '/shared/proxy': 'proxy_info',
        '/shared/quilkin': 'quilkin_config',
        '/shared/social/presence/get': 'presence',
        '/shared/profile': 'profile',
        '/pioneer/inventory': 'inventory',
        '/shared/scenarios': 'scenarios',
    }

    def __init__(self, interface=None):
        self.interface = interface
        self.running = False
        self.thread = None
        self.data = {
            'gameserver': None,
            'secret_key': None,
            'routing_token': None,
            'squad': None,
            'match': None,
            'proxy_endpoints': None,
            'players_in_match': [],
            'last_update': None,
        }
        self.raw_responses = []
        self.callbacks = []
        self._buffer = {}  # TCP reassembly buffer

    def start(self):
        """Démarre l'interception"""
        self.running = True
        self.thread = threading.Thread(
            target=self._capture_loop,
            name="APIInterceptor",
            daemon=True
        )
        self.thread.start()
        logger.info(f"API Interceptor démarré - surveillance de {self.API_HOST}")

    def stop(self):
        """Arrête l'interception"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def on_data(self, callback):
        """Enregistre un callback pour les nouvelles données"""
        self.callbacks.append(callback)

    def _notify(self, event_type, data):
        """Notifie les callbacks"""
        for cb in self.callbacks:
            try:
                cb(event_type, data)
            except Exception as e:
                logger.debug(f"Callback error: {e}")

    def _capture_loop(self):
        """Boucle de capture des paquets HTTPS"""
        bpf = f"host {self.API_HOST} and tcp"

        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    filter=bpf,
                    stop_filter=lambda x: not self.running,
                    timeout=5
                )
            except Exception as e:
                logger.error(f"API Interceptor error: {e}")
                if self.running:
                    time.sleep(1)

    def _packet_handler(self, packet):
        """Traite chaque paquet TCP"""
        if not self.running or TCP not in packet or Raw not in packet:
            return

        try:
            raw = bytes(packet[Raw])
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            # Réponses du serveur API (venant de l'API_HOST)
            if src_ip == self.API_HOST:
                self._process_response(raw, sport, dport)

        except Exception as e:
            logger.debug(f"API packet error: {e}")

    def _process_response(self, raw_data, sport, dport):
        """Traite une réponse HTTP du serveur"""
        try:
            text = raw_data.decode('utf-8', errors='ignore')
        except:
            return

        # Chercher du JSON dans la réponse HTTP
        json_match = re.search(r'\{[\s\S]*\}', text)
        if not json_match:
            return

        try:
            json_str = json_match.group()
            data = json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            return

        # Identifier le type de réponse par son contenu
        self._classify_and_store(data)

    def _classify_and_store(self, data):
        """Classifie la réponse API et stocke les données pertinentes"""
        timestamp = datetime.now()

        # Gameserver status (contient secretKey)
        if 'gameserver' in data:
            gs = data['gameserver']
            self.data['gameserver'] = {
                'host': gs.get('host'),
                'port': gs.get('port'),
                'name': gs.get('name'),
                'datacenter': gs.get('datacenterIcaoCode'),
                'proxy_enabled': gs.get('proxyEnabled'),
            }
            self.data['secret_key'] = gs.get('secretKey')
            self.data['routing_token'] = gs.get('routingToken')
            self.data['last_update'] = timestamp.isoformat()

            logger.warning(
                f"[API] Gameserver: {gs.get('host')}:{gs.get('port')} "
                f"| DC: {gs.get('datacenterIcaoCode')} "
                f"| SecretKey: {'CAPTURED' if gs.get('secretKey') else 'N/A'}"
            )
            self._notify('gameserver', self.data['gameserver'])

        # Squad layout (joueurs dans le match)
        if 'squads' in data:
            players = []
            for squad in data.get('squads', []):
                squad_id = squad.get('squad_id', 'unknown')
                for member in squad.get('squad_members', []):
                    profile = member.get('profile', {})
                    display = profile.get('displayName', {})
                    players.append({
                        'squad_id': squad_id,
                        'name': display.get('name', 'unknown'),
                        'discriminator': display.get('discriminator', ''),
                        'tenancy_user_id': profile.get('tenancyUserId'),
                        'account_id': profile.get('accountId'),
                        'platform_id': profile.get('thirdPartyUserId'),
                    })

            self.data['players_in_match'] = players
            self.data['squad'] = data
            self.data['last_update'] = timestamp.isoformat()

            logger.warning(f"[API] Squad layout: {len(players)} joueurs détectés")
            for p in players:
                logger.info(f"  > {p['name']}#{p['discriminator']} (Squad: {p['squad_id'][:8]})")
            self._notify('squad_layout', players)

        # Match status
        if 'matchState' in data:
            self.data['match'] = {
                'state': data.get('matchState'),
                'ticket_id': data.get('ticketId'),
                'scenario': data.get('scenarioName'),
                'polling_interval': data.get('pollingInterval'),
            }
            self.data['last_update'] = timestamp.isoformat()

            logger.info(f"[API] Match: {data.get('matchState')} | {data.get('scenarioName')}")
            self._notify('match_status', self.data['match'])

        # Proxy endpoints
        if 'endpoints' in data and isinstance(data['endpoints'], list):
            if data['endpoints'] and 'qcmpPort' in data['endpoints'][0]:
                self.data['proxy_endpoints'] = data['endpoints']
                self.data['last_update'] = timestamp.isoformat()

                logger.info(f"[API] {len(data['endpoints'])} proxy endpoints détectés")
                for ep in data['endpoints']:
                    logger.info(f"  > {ep.get('region')}: {ep.get('host')}:{ep.get('trafficPort')}")
                self._notify('proxy_endpoints', data['endpoints'])

        # Player presence
        if 'usersRichPresence' in data:
            online = [u for u in data['usersRichPresence'] if u.get('isOnline')]
            logger.info(f"[API] Presence: {len(online)} joueurs en ligne")
            self._notify('presence', data['usersRichPresence'])

        # Stocker la réponse brute
        self.raw_responses.append({
            'timestamp': timestamp.timestamp(),
            'data': data,
        })
        # Limiter la taille
        if len(self.raw_responses) > 500:
            self.raw_responses = self.raw_responses[-500:]

    def get_secret_key(self):
        """Retourne la secretKey capturée"""
        return self.data.get('secret_key')

    def get_gameserver(self):
        """Retourne les infos du gameserver"""
        return self.data.get('gameserver')

    def get_players(self):
        """Retourne les joueurs dans le match"""
        return self.data.get('players_in_match', [])

    def save_data(self, filename):
        """Sauvegarde toutes les données capturées"""
        export = {
            'captured_at': datetime.now().isoformat(),
            'gameserver': self.data['gameserver'],
            'secret_key': self.data['secret_key'],
            'routing_token': self.data['routing_token'],
            'players': self.data['players_in_match'],
            'match': self.data['match'],
            'proxy_endpoints': self.data['proxy_endpoints'],
            'raw_responses_count': len(self.raw_responses),
            'raw_responses': self.raw_responses[-50:],  # 50 dernières
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export, f, indent=2, ensure_ascii=False)
        logger.info(f"API data sauvegardée -> {filename}")
