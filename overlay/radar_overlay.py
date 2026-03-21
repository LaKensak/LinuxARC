"""
Overlay radar - Affichage minimaliste des entités
"""

import pygame
import math
import threading
import ctypes
import ctypes.wintypes
from typing import List, Tuple
from core.entity_manager import EntityManager


class RadarOverlay:
    """Radar minimaliste en overlay"""

    def __init__(self, entity_manager: EntityManager, width=800, height=600, zoom=1.0):
        self.entity_manager = entity_manager
        self.width = width
        self.height = height
        self.zoom = zoom
        self.running = False
        self.screen = None
        self.clock = None
        self.player_pos = (0.0, 0.0)

        # Configuration
        self.show_esp = True
        self.show_radar = True
        self.radar_radius = 150
        self.radar_center = (width // 2, height // 2)

        # Couleurs
        self.COLORS = {
            'player': (0, 255, 0),
            'enemy': (255, 0, 0),
            'resource': (255, 255, 0),
            'loot': (0, 255, 255),
            'vehicle': (255, 165, 0),
            'background': (0, 0, 0, 0)
        }

    def start(self):
        """Démarre l'overlay"""
        self.running = True
        self._init_pygame()

    def stop(self):
        """Arrête l'overlay"""
        self.running = False
        if self.screen:
            pygame.quit()

    def toggle_esp(self):
        """Active/désactive l'ESP"""
        self.show_esp = not self.show_esp
        print(f"ESP: {'ON' if self.show_esp else 'OFF'}")

    def toggle_radar(self):
        """Active/désactive le radar"""
        self.show_radar = not self.show_radar
        print(f"Radar: {'ON' if self.show_radar else 'OFF'}")

    def _init_pygame(self):
        """Initialise pygame et la fenêtre overlay"""
        pygame.init()

        # Créer la fenêtre
        self.screen = pygame.display.set_mode(
            (self.width, self.height),
            pygame.NOFRAME | pygame.HWSURFACE | pygame.SRCALPHA
        )
        pygame.display.set_caption("ARC Raiders Radar")

        # Rendre la fenêtre transparente et click-through
        hwnd = pygame.display.get_wm_info()['window']

        # WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST
        ctypes.windll.user32.SetWindowLongW(
            hwnd,
            -20,  # GWL_EXSTYLE
            ctypes.windll.user32.GetWindowLongW(hwnd, -20) | 0x80000 | 0x20 | 0x8
        )

        # Fond transparent
        self.screen.fill((0, 0, 0, 0))
        self.clock = pygame.time.Clock()

        # Boucle principale
        self._main_loop()

    def _main_loop(self):
        """Boucle principale de rendu"""
        font = pygame.font.Font(None, 16)

        while self.running:
            # Gestion des événements
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.running = False
                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_ESCAPE:
                        self.running = False

            # Effacer l'écran
            self.screen.fill((0, 0, 0, 0))

            # Dessiner le radar
            if self.show_radar:
                self._draw_radar(font)

            # Dessiner l'ESP
            if self.show_esp:
                self._draw_esp(font)

            # Mettre à jour l'affichage
            pygame.display.flip()
            self.clock.tick(60)

        pygame.quit()

    def _draw_radar(self, font):
        """Dessine le radar circulaire"""
        center_x, center_y = self.radar_center

        # Cercle extérieur
        pygame.draw.circle(
            self.screen,
            (50, 50, 50),
            (center_x, center_y),
            self.radar_radius,
            2
        )

        # Lignes de direction
        pygame.draw.line(self.screen, (50, 50, 50),
                         (center_x - self.radar_radius, center_y),
                         (center_x + self.radar_radius, center_y), 1)
        pygame.draw.line(self.screen, (50, 50, 50),
                         (center_x, center_y - self.radar_radius),
                         (center_x, center_y + self.radar_radius), 1)

        # Entités sur le radar
        entities = self.entity_manager.get_entities_in_range(
            self.player_pos[0],
            self.player_pos[1],
            self.radar_radius / self.zoom
        )

        for entity in entities:
            # Convertir coordonnées monde → radar
            dx = (entity.position[0] - self.player_pos[0]) * self.zoom
            dy = (entity.position[1] - self.player_pos[1]) * self.zoom

            radar_x = center_x + dx
            radar_y = center_y + dy

            if 0 <= radar_x <= self.width and 0 <= radar_y <= self.height:
                # Couleur selon type
                if entity.is_enemy:
                    color = self.COLORS['enemy']
                    size = 6
                elif entity.is_resource:
                    color = self.COLORS['resource']
                    size = 4
                elif entity.is_loot:
                    color = self.COLORS['loot']
                    size = 3
                else:
                    color = self.COLORS['player']
                    size = 5

                pygame.draw.circle(
                    self.screen,
                    color,
                    (int(radar_x), int(radar_y)),
                    size
                )

                # Texte de distance pour les ennemis proches
                if entity.is_enemy and entity.distance < 50:
                    dist_text = font.render(str(int(entity.distance)), True, (255, 255, 255))
                    self.screen.blit(dist_text, (int(radar_x) + 8, int(radar_y) - 8))

        # Point central (joueur)
        pygame.draw.circle(
            self.screen,
            self.COLORS['player'],
            (center_x, center_y),
            8
        )

    def _draw_esp(self, font):
        """Dessine l'ESP (boîtes autour des entités)"""
        # Cette fonction nécessite la matrice de vue du jeu
        # Pour l'instant, elle est laissée vide en attendant les données 3D
        pass

    def update(self):
        """Met à jour la position du joueur (appelée depuis main)"""
        # À implémenter: détection de la position du joueur
        pass