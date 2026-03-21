#!/usr/bin/env python3
"""
ARC Raiders Network Sniffer - Système de capture réseau indétectable
Version: 1.0.0
Auteur: Research Team
Licence: Éducatif uniquement
"""

import sys
import os
import signal
import atexit
import asyncio
import threading
import ctypes
import json
import time
from pathlib import Path
from datetime import datetime

# Ajouter le chemin du projet
sys.path.insert(0, str(Path(__file__).parent))

# Import des modules internes
from utils.logger import Logger
from utils.config import ConfigManager
from core.sniffer_engine import SnifferEngine
from core.packet_decoder import PacketDecoder
from core.entity_manager import EntityManager
from overlay.radar_overlay import RadarOverlay
from analyzers.threat_analyzer import ThreatAnalyzer
from core.api_interceptor import APIInterceptor


class ARCSniffer:
    """Classe principale du sniffer"""

    def __init__(self):
        self.logger = Logger("ARC_Sniffer")
        self.config = ConfigManager()
        self.running = False
        self.sniffer_engine = None
        self.decoder = None
        self.entity_manager = None
        self.overlay = None
        self.threat_analyzer = None
        self.api_interceptor = None

        # Threads
        self.sniffer_thread = None
        self.analyzer_thread = None
        self.render_thread = None

        # Stats
        self.stats = {
            'packets_captured': 0,
            'packets_decoded': 0,
            'entities_tracked': 0,
            'start_time': None,
            'errors': 0
        }
        self._stopped = False
        atexit.register(self._save_packets)

    def check_admin(self) -> bool:
        """Vérifie si le programme est lancé en administrateur"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def elevate(self):
        """Relance le programme en administrateur"""
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)

    def init_components(self):
        """Initialise tous les composants"""
        self.logger.info("Initialisation des composants...")

        # 1. Sniffer Engine
        self.sniffer_engine = SnifferEngine(
            ports=self.config.get('network.ports', [4549, 7200, 4175, 4179, 4171]),
            port_ranges=self.config.get('network.port_ranges', [[7000, 7999]]),
            interface=self.config.get('network.interface', None),
            buffer_size=self.config.get('network.buffer_size', 65536)
        )

        # 2. Packet Decoder
        self.decoder = PacketDecoder(
            signatures_file='data/signatures/packet_signatures.json'
        )

        # 3. Entity Manager
        self.entity_manager = EntityManager()

        # 4. Threat Analyzer
        self.threat_analyzer = ThreatAnalyzer(
            self.entity_manager,
            self.config.get('threat', {})
        )

        # 5. API Interceptor
        self.api_interceptor = APIInterceptor(
            interface=self.config.get('network.interface', None)
        )
        self.api_interceptor.on_data(self._on_api_data)

        # 6. Overlay
        self.overlay = RadarOverlay(
            self.entity_manager,
            width=self.config.get('overlay.width', 800),
            height=self.config.get('overlay.height', 600),
            zoom=self.config.get('overlay.zoom', 1.0)
        )

        self.logger.info("✓ Tous les composants initialisés")

    def start(self):
        """Démarre tous les modules"""
        if not self.check_admin():
            self.logger.warning("Droits administrateur requis, élévation...")
            self.elevate()
            return

        self.running = True
        self.stats['start_time'] = datetime.now()

        # Initialisation
        self.init_components()

        # Démarrage des threads
        self.sniffer_thread = threading.Thread(
            target=self._sniffer_loop,
            name="SnifferThread",
            daemon=True
        )

        self.analyzer_thread = threading.Thread(
            target=self._analyzer_loop,
            name="AnalyzerThread",
            daemon=True
        )

        self.render_thread = threading.Thread(
            target=self._render_loop,
            name="RenderThread",
            daemon=True
        )

        self.sniffer_thread.start()
        self.analyzer_thread.start()
        self.render_thread.start()
        self.api_interceptor.start()

        self._print_banner()

        try:
            self._hotkey_listener()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _sniffer_loop(self):
        """Boucle du sniffer réseau"""
        self.sniffer_engine.start()
        last_save = time.time()

        while self.running:
            try:
                # Récupérer un paquet
                raw_packet = self.sniffer_engine.get_packet(timeout=1)
                if raw_packet:
                    self.stats['packets_captured'] += 1

                    # Décoder le paquet
                    decoded = self.decoder.decode(raw_packet)
                    if decoded:
                        self.stats['packets_decoded'] += 1

                        # Mettre à jour l'entity manager
                        self.entity_manager.update_from_packet(decoded)

                        # Log debug
                        if decoded.get('type') == 'position_update':
                            self.logger.debug(
                                f"Entity {decoded['entity_id']} -> "
                                f"({decoded['position'][0]:.1f}, {decoded['position'][1]:.1f})"
                            )

                # Auto-save toutes les 30 secondes
                if time.time() - last_save >= 30 and self.decoder.unknown_packets:
                    self._save_packets()
                    last_save = time.time()

            except Exception as e:
                self.stats['errors'] += 1
                self.logger.error(f"Sniffer error: {e}")

    def _on_api_data(self, event_type, data):
        """Callback quand l'API interceptor capture des données"""
        if event_type == 'squad_layout':
            # Mettre à jour l'entity manager avec les joueurs
            for player in data:
                self.entity_manager.update_from_packet({
                    'type': 'player_join',
                    'timestamp': datetime.now().timestamp(),
                    'entity_id': player.get('tenancy_user_id', 0),
                    'name': f"{player['name']}#{player['discriminator']}",
                    'squad_id': player.get('squad_id'),
                })
        elif event_type == 'gameserver':
            self.logger.success(
                f"Serveur de jeu capturé: {data.get('host')}:{data.get('port')} "
                f"({data.get('datacenter')})"
            )

    def _analyzer_loop(self):
        """Boucle d'analyse des menaces"""
        while self.running:
            try:
                # Analyser les menaces
                threats = self.threat_analyzer.analyze()

                # Enregistrer les menaces
                for threat in threats:
                    self.logger.warning(
                        f"Threat detected: {threat['type']} at distance {threat['distance']:.0f}m"
                    )

                # Vérifier les zones de danger
                danger_zones = self.threat_analyzer.get_danger_zones()

                time.sleep(0.5)  # 2 analyses par seconde

            except Exception as e:
                self.logger.error(f"Analyzer error: {e}")
                time.sleep(1)

    def _render_loop(self):
        """Boucle de rendu de l'overlay"""
        self.overlay.start()

        while self.running:
            try:
                # Mettre à jour l'affichage
                self.overlay.update()
                time.sleep(0.016)  # ~60 FPS

            except Exception as e:
                self.logger.error(f"Render error: {e}")
                break

    def _hotkey_listener(self):
        """Écoute des raccourcis clavier"""
        import keyboard

        self.logger.info("Raccourcis clavier actifs:")
        self.logger.info("  F10 - Toggle ESP")
        self.logger.info("  F11 - Toggle Radar")
        self.logger.info("  F12 - Stats")
        self.logger.info("  ESC - Quitter")

        keyboard.add_hotkey('f10', self.overlay.toggle_esp)
        keyboard.add_hotkey('f11', self.overlay.toggle_radar)
        keyboard.add_hotkey('f12', self._print_stats)

        keyboard.wait('esc')

    def _print_stats(self):
        """Affiche les statistiques"""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()

        print("\n" + "=" * 50)
        print("STATISTIQUES DU SNIFFER")
        print("=" * 50)
        print(f"Uptime: {uptime:.0f} secondes")
        print(f"Paquets capturés: {self.stats['packets_captured']}")
        print(f"Paquets décodés: {self.stats['packets_decoded']}")
        print(f"Taux de décodage: {self.stats['packets_decoded'] / max(1, self.stats['packets_captured']) * 100:.1f}%")
        print(f"Entités suivies: {len(self.entity_manager.entities)}")
        print(f"Erreurs: {self.stats['errors']}")
        print("=" * 50)

    def _print_banner(self):
        """Affiche la bannière de démarrage"""
        print("""
╔═══════════════════════════════════════════════════════════════╗
║     ARC RAIDERS NETWORK SNIFFER v2.0                         ║
║     Capture réseau + API Interceptor + ESP + Radar           ║
║                                                               ║
║     [✓] Sniffer UDP actif                                    ║
║     [✓] API Interceptor HTTPS actif                          ║
║     [✓] Décodeur de paquets chargé                          ║
║     [✓] ESP Overlay prêt                                     ║
║     [✓] Analyse des menaces active                           ║
╚═══════════════════════════════════════════════════════════════╝
        """)
        self.logger.info("Système opérationnel. En attente de données réseau...")

    def _save_packets(self):
        """Sauvegarde les paquets inconnus et les données API"""
        dump_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'logs')
        os.makedirs(dump_dir, exist_ok=True)
        date = datetime.now().strftime("%Y%m%d")

        # Sauvegarder les paquets UDP
        try:
            if self.decoder and self.decoder.unknown_packets:
                dump_file = os.path.join(dump_dir, f'ARC_Sniffer_{date}_packets.json')
                with open(dump_file, 'w', encoding='utf-8') as f:
                    json.dump(self.decoder.unknown_packets, f, indent=2)
                print(f"[SAVE] {len(self.decoder.unknown_packets)} paquets UDP -> {dump_file}")
        except Exception as e:
            print(f"[!] Erreur sauvegarde paquets: {e}")

        # Sauvegarder les données API
        try:
            if self.api_interceptor and self.api_interceptor.raw_responses:
                api_file = os.path.join(dump_dir, f'ARC_Sniffer_{date}_api.json')
                self.api_interceptor.save_data(api_file)
                print(f"[SAVE] {len(self.api_interceptor.raw_responses)} réponses API -> {api_file}")
        except Exception as e:
            print(f"[!] Erreur sauvegarde API: {e}")

    def stop(self):
        """Arrête proprement le système"""
        if self._stopped:
            return
        self._stopped = True

        self.logger.info("Arrêt du système...")
        self.running = False

        try:
            if self.sniffer_engine:
                self.sniffer_engine.stop()
        except:
            pass
        try:
            if self.overlay:
                self.overlay.stop()
        except:
            pass
        try:
            if self.api_interceptor:
                self.api_interceptor.stop()
        except:
            pass

        self._save_packets()
        self._print_stats()
        self.logger.info("Système arrêté proprement")


if __name__ == "__main__":
    sniffer = ARCSniffer()
    sniffer.start()