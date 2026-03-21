"""
Gestionnaire de configuration
"""

import json
import os
from pathlib import Path
from typing import Any, Dict


class ConfigManager:
    """Gère la configuration de l'application"""

    DEFAULT_CONFIG = {
        'network': {
            'ports': [5055, 5056, 4535],
            'interface': None,
            'buffer_size': 65536,
            'timeout': 5
        },
        'overlay': {
            'width': 800,
            'height': 600,
            'zoom': 1.0,
            'radar_radius': 150,
            'transparency': 200,
            'always_on_top': True
        },
        'threat': {
            'danger_distance': 50,
            'warning_distance': 100,
            'critical_health': 30,
            'scan_interval': 0.5
        },
        'logging': {
            'level': 'INFO',
            'file_enabled': True,
            'console_enabled': True,
            'max_size_mb': 10
        },
        'hotkeys': {
            'toggle_esp': 'f10',
            'toggle_radar': 'f11',
            'show_stats': 'f12',
            'quit': 'esc'
        }
    }

    def __init__(self, config_dir: str = "data/config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Charge la configuration depuis les fichiers"""
        config = self.DEFAULT_CONFIG.copy()

        # Charger settings.json
        settings_file = self.config_dir / 'settings.json'
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                user_config = json.load(f)
                self._deep_update(config, user_config)

        # Charger network.json
        network_file = self.config_dir / 'network.json'
        if network_file.exists():
            with open(network_file, 'r') as f:
                network_config = json.load(f)
                self._deep_update(config['network'], network_config)

        # Charger hotkeys.json
        hotkeys_file = self.config_dir / 'hotkeys.json'
        if hotkeys_file.exists():
            with open(hotkeys_file, 'r') as f:
                hotkeys_config = json.load(f)
                self._deep_update(config['hotkeys'], hotkeys_config)

        return config

    def _deep_update(self, target: Dict, source: Dict):
        """Met à jour récursivement un dictionnaire"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_update(target[key], value)
            else:
                target[key] = value

    def get(self, key: str, default=None) -> Any:
        """Récupère une valeur de configuration"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        """Définit une valeur de configuration"""
        keys = key.split('.')
        target = self.config
        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]
        target[keys[-1]] = value

    def save(self):
        """Sauvegarde la configuration"""
        settings_file = self.config_dir / 'settings.json'
        with open(settings_file, 'w') as f:
            json.dump(self.config, f, indent=2)