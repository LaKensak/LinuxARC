# Analyse des menaces
class ThreatAnalyzer:
    def __init__(self, entity_manager, config=None):
        self.entity_manager = entity_manager
        self.config = config or {}
        self.danger_distance = self.config.get('danger_distance', 40)
        self.critical_health = self.config.get('critical_health', 30)

    def analyze(self):
        """Analyse les entités pour détecter les menaces"""
        threats = []
        entities = self.entity_manager.get_all() if hasattr(self.entity_manager, 'get_all') else []
        for entity in entities:
            if entity.get('type') == 'enemy':
                dist = entity.get('distance', float('inf'))
                if dist <= self.danger_distance:
                    threats.append({
                        'type': entity.get('name', 'unknown'),
                        'distance': dist,
                        'health': entity.get('health', 0),
                        'critical': dist <= self.danger_distance / 2
                    })
        return threats

    def get_danger_zones(self):
        """Retourne les zones de danger actives"""
        zones = []
        entities = self.entity_manager.get_all() if hasattr(self.entity_manager, 'get_all') else []
        for entity in entities:
            if entity.get('type') == 'enemy' and entity.get('distance', float('inf')) <= self.danger_distance:
                zones.append({
                    'position': entity.get('position', (0, 0, 0)),
                    'radius': self.danger_distance,
                    'level': 'critical' if entity.get('distance', float('inf')) <= self.danger_distance / 2 else 'warning'
                })
        return zones