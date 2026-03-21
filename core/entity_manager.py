"""
Gestionnaire d'entités - Suit tous les objets en jeu
"""

import math
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class Entity:
    """Représente une entité en jeu"""
    entity_id: int
    entity_type: int = 0
    name: str = ""
    position: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    health: float = 100.0
    max_health: float = 100.0
    last_update: float = 0.0
    spawn_time: float = 0.0
    velocity: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    is_player: bool = False
    is_enemy: bool = False
    is_loot: bool = False
    is_resource: bool = False

    # Attributs spécifiques
    tier: int = 0  # Pour les ressources
    rarity: int = 0  # Rareté
    charges: int = 0  # Charges restantes
    distance: float = 0.0  # Distance par rapport au joueur

    def update_position(self, x: float, y: float, z: float):
        """Met à jour la position et calcule la vélocité"""
        old_pos = self.position
        self.position = (x, y, z)
        self.last_update = datetime.now().timestamp()

        # Calculer la vélocité
        if old_pos != (0.0, 0.0, 0.0):
            dt = 0.1  # Intervalle approximatif
            vx = (x - old_pos[0]) / dt
            vy = (y - old_pos[1]) / dt
            vz = (z - old_pos[2]) / dt
            self.velocity = (vx, vy, vz)


class EntityManager:
    """Gère toutes les entités détectées"""

    # Types d'entités
    TYPE_PLAYER = 1
    TYPE_ENEMY = 2
    TYPE_RESOURCE = 3
    TYPE_LOOT = 4
    TYPE_VEHICLE = 5
    TYPE_NPC = 6

    def __init__(self):
        self.entities: Dict[int, Entity] = {}
        self.local_player_id: Optional[int] = None
        self.lock = threading.Lock()
        self.stats = {
            'total_entities': 0,
            'players': 0,
            'enemies': 0,
            'resources': 0,
            'loot': 0
        }

    def update_from_packet(self, packet: Dict):
        """Met à jour les entités à partir d'un paquet décodé"""
        packet_type = packet.get('type')

        with self.lock:
            if packet_type == 'entity_spawn':
                self._handle_spawn(packet)
            elif packet_type == 'entity_despawn':
                self._handle_despawn(packet)
            elif packet_type == 'position_update':
                self._handle_position(packet)
            elif packet_type == 'health_update':
                self._handle_health(packet)

    def _handle_spawn(self, packet: Dict):
        """Gère l'apparition d'une entité"""
        entity_id = packet.get('entity_id')
        if not entity_id:
            return

        if entity_id not in self.entities:
            entity = Entity(
                entity_id=entity_id,
                entity_type=packet.get('entity_type', 0),
                name=packet.get('name', f"Entity_{entity_id}"),
                spawn_time=packet.get('timestamp', 0)
            )

            # Classifier l'entité
            entity.is_player = entity.entity_type == self.TYPE_PLAYER
            entity.is_enemy = entity.entity_type == self.TYPE_ENEMY
            entity.is_loot = entity.entity_type == self.TYPE_LOOT
            entity.is_resource = entity.entity_type == self.TYPE_RESOURCE

            self.entities[entity_id] = entity
            self._update_stats()

            logger.debug(f"Entity spawned: {entity_id} (type={entity.entity_type})")

    def _handle_despawn(self, packet: Dict):
        """Gère la disparition d'une entité"""
        entity_id = packet.get('entity_id')
        if entity_id and entity_id in self.entities:
            del self.entities[entity_id]
            self._update_stats()
            logger.debug(f"Entity despawned: {entity_id}")

    def _handle_position(self, packet: Dict):
        """Gère la mise à jour de position"""
        entity_id = packet.get('entity_id')
        position = packet.get('position')

        if entity_id and position and entity_id in self.entities:
            self.entities[entity_id].update_position(*position)

    def _handle_health(self, packet: Dict):
        """Gère la mise à jour de santé"""
        entity_id = packet.get('entity_id')
        health = packet.get('health')
        max_health = packet.get('max_health')

        if entity_id and entity_id in self.entities:
            self.entities[entity_id].health = health or 100
            self.entities[entity_id].max_health = max_health or 100

    def _update_stats(self):
        """Met à jour les statistiques"""
        self.stats['total_entities'] = len(self.entities)
        self.stats['players'] = sum(1 for e in self.entities.values() if e.is_player)
        self.stats['enemies'] = sum(1 for e in self.entities.values() if e.is_enemy)
        self.stats['resources'] = sum(1 for e in self.entities.values() if e.is_resource)
        self.stats['loot'] = sum(1 for e in self.entities.values() if e.is_loot)

    def get_entities_in_range(self, center_x: float, center_y: float, radius: float) -> List[Entity]:
        """Retourne les entités dans un rayon donné"""
        result = []
        for entity in self.entities.values():
            dx = entity.position[0] - center_x
            dy = entity.position[1] - center_y
            distance = math.hypot(dx, dy)
            if distance <= radius:
                entity.distance = distance
                result.append(entity)
        return sorted(result, key=lambda e: e.distance)

    def get_threats(self, player_pos: Tuple[float, float, float]) -> List[Entity]:
        """Retourne les menaces triées par distance"""
        threats = []
        for entity in self.entities.values():
            if entity.is_enemy and entity.health > 0:
                dx = entity.position[0] - player_pos[0]
                dy = entity.position[1] - player_pos[1]
                entity.distance = math.hypot(dx, dy)
                threats.append(entity)
        return sorted(threats, key=lambda e: e.distance)

    def get_resources(self, player_pos: Tuple[float, float, float]) -> List[Entity]:
        """Retourne les ressources à proximité"""
        resources = []
        for entity in self.entities.values():
            if entity.is_resource:
                dx = entity.position[0] - player_pos[0]
                dy = entity.position[1] - player_pos[1]
                entity.distance = math.hypot(dx, dy)
                resources.append(entity)
        return sorted(resources, key=lambda e: e.distance)

    def get_loot(self, player_pos: Tuple[float, float, float]) -> List[Entity]:
        """Retourne les loots à proximité"""
        loots = []
        for entity in self.entities.values():
            if entity.is_loot:
                dx = entity.position[0] - player_pos[0]
                dy = entity.position[1] - player_pos[1]
                entity.distance = math.hypot(dx, dy)
                loots.append(entity)
        return sorted(loots, key=lambda e: e.distance)

    def set_local_player(self, entity_id: int):
        """Définit le joueur local"""
        self.local_player_id = entity_id
        if entity_id in self.entities:
            self.entities[entity_id].is_player = True
            logger.info(f"Local player set to: {entity_id}")