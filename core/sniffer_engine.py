"""
Moteur de capture réseau - Noyau du sniffer
Utilise Scapy avec des optimisations pour minimiser la détection
"""

import threading
import queue
import time
import socket
import struct
from scapy.all import sniff, IP, UDP, TCP, Raw, conf
from scapy.arch import get_windows_if_list
import logging

from utils.logger import get_logger

logger = logging.getLogger(__name__)


class SnifferEngine:
    """Moteur de capture réseau optimisé"""

    def __init__(self, ports=None, port_ranges=None, interface=None, buffer_size=65536):
        self.ports = ports or [4549, 7200, 4175, 4179, 4171]
        self.port_ranges = port_ranges or [[7000, 7999]]
        self.interface = interface
        self.buffer_size = buffer_size
        self.running = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.sniffer_thread = None
        self.stats = {'packets': 0, 'bytes': 0, 'errors': 0}

        # Optimisations Scapy
        conf.use_pcap = True
        conf.verb = 0  # Mode silencieux
        self.logger = get_logger()

    def start(self):
        """Démarre la capture"""
        self.running = True
        self.sniffer_thread = threading.Thread(
            target=self._capture_loop,
            name="SnifferEngine",
            daemon=True
        )
        self.sniffer_thread.start()
        logger.info(f"Sniffer démarré sur les ports {self.ports}")

    def stop(self):
        """Arrête la capture"""
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        logger.info("Sniffer arrêté")

    def get_packet(self, timeout=1):
        """Récupère un paquet de la file"""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _capture_loop(self):
        """Boucle de capture principale"""
        bpf_filter = self._build_bpf_filter()
        logger.info(f"Filtre BPF: {bpf_filter}")

        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    filter=bpf_filter,
                    stop_filter=lambda x: not self.running,
                    timeout=5
                )
            except Exception as e:
                logger.error(f"Erreur de capture: {e}")
                if self.running:
                    time.sleep(1)

    def _build_bpf_filter(self):
        """Construit un filtre BPF optimisé"""
        parts = []
        for p in self.ports:
            parts.append(f"port {p}")
        for r in self.port_ranges:
            parts.append(f"portrange {r[0]}-{r[1]}")

        if not parts:
            return ""

        port_filter = " or ".join(parts)
        return f"({port_filter})"

    def _packet_handler(self, packet):
        """Callback pour chaque paquet capturé"""
        if not self.running:
            return

        try:
            if (UDP in packet or TCP in packet) and Raw in packet:
                raw_data = bytes(packet[Raw])
                if raw_data:
                    self.stats['packets'] += 1
                    self.stats['bytes'] += len(raw_data)

                    # Ajouter à la file
                    try:
                        self.packet_queue.put_nowait(raw_data)
                    except queue.Full:
                        pass  # File pleine, on ignore

        except Exception as e:
            self.stats['errors'] += 1
            logger.debug(f"Erreur handler: {e}")

    def get_stats(self):
        """Retourne les statistiques"""
        return {
            'packets': self.stats['packets'],
            'bytes': self.stats['bytes'],
            'errors': self.stats['errors'],
            'queue_size': self.packet_queue.qsize()
        }

    def get_available_interfaces(self):
        """Liste les interfaces réseau disponibles"""
        interfaces = []
        for iface in get_windows_if_list():
            interfaces.append({
                'name': iface.get('name', 'unknown'),
                'description': iface.get('description', ''),
                'ips': iface.get('ips', []),
                'mac': iface.get('mac', '')
            })
        return interfaces