"""
Décodeur de paquets - Transforme les données brutes en entités exploitables
"""

import struct
import json
import hashlib
from typing import Dict, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class PacketDecoder:
    """Décodeur intelligent de paquets réseau"""

    # Codes d'opération ARC Raiders (à identifier via reverse engineering)
    OPCODES = {
        0x01: 'position_update',
        0x02: 'entity_spawn',
        0x03: 'entity_despawn',
        0x04: 'health_update',
        0x05: 'inventory_update',
        0x06: 'loot_spawn',
        0x07: 'damage_event',
        0x08: 'chat_message',
        0x09: 'player_join',
        0x0A: 'player_leave',
        0x0B: 'game_state',
        0x0C: 'mission_update',
        0x0D: 'vehicle_update',
    }

    def __init__(self, signatures_file: str = None):
        self.signatures = self._load_signatures(signatures_file)
        self.packet_cache = {}
        self.unknown_packets = []

    def _load_signatures(self, filename: str) -> Dict:
        """Charge les signatures de paquets"""
        if filename and Path(filename).exists():
            with open(filename, 'r') as f:
                return json.load(f)
        return {}

    def decode(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Décode un paquet brut
        Retourne un dictionnaire structuré ou None
        """
        if not raw_data or len(raw_data) < 4:
            return None

        try:
            # 1. Vérifier les signatures connues
            packet_hash = hashlib.md5(raw_data[:20]).hexdigest()
            if packet_hash in self.packet_cache:
                return self.packet_cache[packet_hash]

            # 2. Identifier le type de paquet
            opcode = self._get_opcode(raw_data)
            if opcode is None:
                self._log_unknown(raw_data)
                return None

            # 3. Décoder selon le type
            decoder_method = getattr(self, f"_decode_{self.OPCODES[opcode]}", None)
            if decoder_method:
                decoded = decoder_method(raw_data)
                if decoded:
                    self.packet_cache[packet_hash] = decoded
                    return decoded

            return None

        except Exception as e:
            logger.debug(f"Erreur décodage: {e}")
            return None

    def _get_opcode(self, data: bytes) -> Optional[int]:
        """Extrait l'opcode du paquet"""
        # Structure hypothétique: [opcode (1-2 bytes)][size][data...]
        if len(data) >= 2:
            # Premier octet = opcode
            opcode = data[0]
            if opcode in self.OPCODES:
                return opcode
        return None

    def _decode_position_update(self, data: bytes) -> Dict:
        """
        Décode une mise à jour de position
        Structure hypothétique: [opcode][entity_id(4)][pos_x(4)][pos_y(4)][pos_z(4)]
        """
        if len(data) < 17:  # 1 + 4 + 12
            return None

        entity_id = struct.unpack('<I', data[1:5])[0]
        x, y, z = struct.unpack('<fff', data[5:17])

        return {
            'type': 'position_update',
            'timestamp': datetime.now().timestamp(),
            'entity_id': entity_id,
            'position': (x, y, z)
        }

    def _decode_entity_spawn(self, data: bytes) -> Dict:
        """
        Décode l'apparition d'une entité
        Structure: [opcode][entity_id(4)][type(2)][name_length(2)][name(...)]
        """
        if len(data) < 9:
            return None

        entity_id = struct.unpack('<I', data[1:5])[0]
        entity_type = struct.unpack('<H', data[5:7])[0]

        name = ""
        if len(data) > 9:
            name_len = struct.unpack('<H', data[7:9])[0]
            if len(data) >= 9 + name_len:
                name = data[9:9 + name_len].decode('utf-8', errors='ignore')

        return {
            'type': 'entity_spawn',
            'timestamp': datetime.now().timestamp(),
            'entity_id': entity_id,
            'entity_type': entity_type,
            'name': name
        }

    def _decode_entity_despawn(self, data: bytes) -> Dict:
        """Décode la disparition d'une entité"""
        if len(data) < 5:
            return None

        entity_id = struct.unpack('<I', data[1:5])[0]

        return {
            'type': 'entity_despawn',
            'timestamp': datetime.now().timestamp(),
            'entity_id': entity_id
        }

    def _decode_health_update(self, data: bytes) -> Dict:
        """Décode une mise à jour de santé"""
        if len(data) < 13:
            return None

        entity_id = struct.unpack('<I', data[1:5])[0]
        health = struct.unpack('<f', data[5:9])[0]
        max_health = struct.unpack('<f', data[9:13])[0]

        return {
            'type': 'health_update',
            'timestamp': datetime.now().timestamp(),
            'entity_id': entity_id,
            'health': health,
            'max_health': max_health,
            'health_percent': health / max_health if max_health > 0 else 0
        }

    def _log_unknown(self, data: bytes):
        """Enregistre les paquets inconnus pour analyse"""
        if len(self.unknown_packets) < 1000:  # Limite
            self.unknown_packets.append({
                'timestamp': datetime.now().timestamp(),
                'size': len(data),
                'first_20': data[:20].hex(),
                'data': data.hex()[:200]
            })

            if len(self.unknown_packets) % 100 == 0:
                logger.warning(f"{len(self.unknown_packets)} paquets inconnus détectés")

    def save_unknown_packets(self, filename: str):
        """Sauvegarde les paquets inconnus pour analyse"""
        with open(filename, 'w') as f:
            json.dump(self.unknown_packets, f, indent=2)