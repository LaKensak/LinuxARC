#!/usr/bin/env python3
"""
Arc Raiders Radar — lecture mémoire via /proc/PID/mem (Linux/Proton uniquement).
EAC ne tourne pas sous Proton, donc /proc/PID/mem est lisible en root.

Usage:
  1. Lance Arc Raiders via Steam/Proton sous Linux
  2. sudo python3 radar.py            (mode web, ouvrir http://localhost:8888)
  3. sudo python3 radar.py --ascii     (mode terminal)
  4. sudo python3 radar.py --port 9000 (port custom)

Basé sur les offsets de la communauté (UC threads 590414, 732490).
"""

import os
import sys
import struct
import time
import signal
import json
import math
import threading
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler

# === OFFSETS ===
# Mis à jour pour pioneer_1.20.x-CL-1112387
# Ces offsets changent à chaque patch — vérifier sur UC/dumpspace

OFFSETS = {
    # Adresses statiques (offset depuis base module)
    'GWorld': 0x80E9950,
    'GNames': 0x7E97580,
    'GEngine': 0x808DE80,

    # UWorld
    'PersistentLevel': 0x38,
    'OwningGameInstance': 0x1A0,
    'GameState': 0x158,

    # ULevel
    'AActors': 0xA0,
    'ActorCount': 0xA8,

    # AActor
    'RootComponent': 0x1A0,
    'PlayerState': 0x2B0,
    'bHidden': 0x60,  # bit flag

    # USceneComponent
    'RelativeLocation': 0x128,
    'ComponentToWorld': 0x1C0,
    'ComponentVelocity': 0x168,

    # APlayerState
    'PlayerName': 0x340,
    'Pawn': 0x310,

    # APawn / ACharacter
    'PlayerController': 0x2C0,
    'Mesh': 0x310,
    'Health': 0x800,  # À vérifier

    # APlayerController
    'AcknowledgedPawn': 0x330,
    'CameraManager': 0x348,
    'PlayerCameraManager': 0x348,
    'ControlRotation': 0x2A8,

    # APlayerCameraManager
    'CameraCache': 0x2270,
    # CameraCacheEntry
    'POV': 0x10,
    'POV_Location': 0x10,     # FVector (X, Y, Z)
    'POV_Rotation': 0x28,     # FRotator (Pitch, Yaw, Roll)
    'POV_FOV': 0x40,          # float
}

# GWorld est obfusqué — nécessite déchiffrement
# XOR key pour le pointeur GWorld (peut changer par build)
GWORLD_XOR_KEY = 0x1B7112D299F8028D
GWORLD_XOR_KEY_ALT = 0xD8AABB54B36CB2F


def rol32(value, bits):
    """Rotate left 32-bit"""
    value &= 0xFFFFFFFF
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def decrypt_gworld_ptr(gworld_key_addr, raw_data):
    """Déchiffre le pointeur GWorld obfusqué.
    Basé sur le code reverse-engineered des threads UC.
    """
    # Lire le tableau de 8 pointeurs à gworld_key_addr + 8*idx
    addr_low = gworld_key_addr & 0xFFFFFFFF
    addr_high = (gworld_key_addr >> 32) & 0xFFFFFFFF

    v23 = (addr_low ^ rol32(addr_low, 12)) + 304
    v23 &= 0xFFFFFFFF
    v24 = (v23 ^ rol32(v23, 12)) + 304
    v24 &= 0xFFFFFFFF
    v25 = (addr_high + (v24 ^ rol32(v24, 12))) & 0xFFFFFFFF
    v26 = (v25 ^ rol32(v25, 12)) + 304
    v26 &= 0xFFFFFFFF
    v27 = (v26 ^ rol32(v26, 12)) + 304
    v27 &= 0xFFFFFFFF
    v28 = rol32(v27, 12) ^ v27
    v28 &= 0xFFFFFFFF

    idx = 7 * (((v28 & 0xFF) ^ ((v28 >> 16) & 0xFF)) & 7) + 6

    # raw_data contient les 128 bytes à partir de gworld_key_addr
    # Lire le pointeur à l'index calculé
    if idx * 8 + 8 > len(raw_data):
        return None

    ptr = struct.unpack_from('<Q', raw_data, idx * 8)[0]

    # Essayer les deux clés XOR
    result = ptr ^ GWORLD_XOR_KEY
    if 0x10000 < result < 0x7FFFFFFFFFFF:
        return result

    result = ptr ^ GWORLD_XOR_KEY_ALT
    if 0x10000 < result < 0x7FFFFFFFFFFF:
        return result

    return ptr  # Retourner tel quel si aucune clé ne marche


class ProcessMemoryReader:
    """Lit la mémoire d'un processus via /proc/PID/mem"""

    def __init__(self, pid):
        self.pid = pid
        self.mem_fd = None
        self.maps = []

    def open(self):
        mem_path = f'/proc/{self.pid}/mem'
        if not os.path.exists(mem_path):
            raise FileNotFoundError(f"Process {self.pid} not found")
        self.mem_fd = os.open(mem_path, os.O_RDONLY)
        self._parse_maps()

    def close(self):
        if self.mem_fd is not None:
            os.close(self.mem_fd)
            self.mem_fd = None

    def _parse_maps(self):
        """Parse /proc/PID/maps pour trouver les régions mémoire"""
        self.maps = []
        with open(f'/proc/{self.pid}/maps', 'r') as f:
            for line in f:
                parts = line.split()
                addr_range = parts[0].split('-')
                start = int(addr_range[0], 16)
                end = int(addr_range[1], 16)
                perms = parts[1]
                name = parts[-1] if len(parts) > 5 else ''
                self.maps.append({
                    'start': start,
                    'end': end,
                    'perms': perms,
                    'name': name,
                })

    def get_base_address(self):
        """Trouve l'adresse de base de PioneerGame.exe"""
        for m in self.maps:
            if 'PioneerGame' in m['name'] and 'r' in m['perms']:
                return m['start']
        # Fallback: premier mapping exécutable
        for m in self.maps:
            if 'r-x' in m['perms'] and m['name'] and '.exe' in m['name']:
                return m['start']
        return None

    def read(self, address, size):
        """Lit `size` bytes à `address`"""
        try:
            os.lseek(self.mem_fd, address, os.SEEK_SET)
            return os.read(self.mem_fd, size)
        except (OSError, OverflowError):
            return b'\x00' * size

    def read_u64(self, address):
        data = self.read(address, 8)
        return struct.unpack('<Q', data)[0]

    def read_u32(self, address):
        data = self.read(address, 4)
        return struct.unpack('<I', data)[0]

    def read_i32(self, address):
        data = self.read(address, 4)
        return struct.unpack('<i', data)[0]

    def read_float(self, address):
        data = self.read(address, 4)
        return struct.unpack('<f', data)[0]

    def read_vec3(self, address):
        """Lit un FVector (X, Y, Z) — 3 floats"""
        data = self.read(address, 12)
        return struct.unpack('<fff', data)

    def read_rotator(self, address):
        """Lit un FRotator (Pitch, Yaw, Roll) — 3 floats"""
        data = self.read(address, 12)
        return struct.unpack('<fff', data)

    def read_fstring(self, address, max_len=64):
        """Lit un FString UE5 (TArray<TCHAR>)"""
        # FString = { TCHAR* Data; int32 Num; int32 Max; }
        data_ptr = self.read_u64(address)
        num = self.read_i32(address + 8)
        if num <= 0 or num > max_len or data_ptr == 0:
            return ''
        raw = self.read(data_ptr, num * 2)  # UTF-16
        try:
            return raw.decode('utf-16-le').rstrip('\x00')
        except:
            return ''


def find_game_pid():
    """Trouve le PID de PioneerGame (natif ou via Proton/Wine)"""
    candidates = []
    for pid_str in os.listdir('/proc'):
        if not pid_str.isdigit():
            continue
        try:
            cmdline_path = f'/proc/{pid_str}/cmdline'
            with open(cmdline_path, 'r') as f:
                cmdline = f.read()
            if 'PioneerGame' in cmdline or 'pioneerGame' in cmdline:
                # Proton lance le .exe via wine — on veut le process wine
                candidates.append((int(pid_str), cmdline))
        except (PermissionError, FileNotFoundError):
            continue

    if not candidates:
        return None

    # Préférer le process avec le plus grand PID (le vrai jeu, pas le launcher)
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][0]


class Radar:
    """Radar principal — lit les positions des joueurs"""

    def __init__(self, reader, base_addr):
        self.reader = reader
        self.base = base_addr
        self.gworld = None
        self.local_pos = (0, 0, 0)
        self.local_yaw = 0
        self.players = []

    def update_gworld(self):
        """Déchiffre et lit GWorld"""
        gworld_key_addr = self.base + OFFSETS['GWorld']
        raw = self.reader.read(gworld_key_addr, 128)
        self.gworld = decrypt_gworld_ptr(gworld_key_addr, raw)

        if self.gworld is None or self.gworld < 0x10000:
            # Essayer lecture directe (si pas obfusqué dans cette version)
            self.gworld = self.reader.read_u64(self.base + OFFSETS['GWorld'])

        return self.gworld is not None and self.gworld > 0x10000

    def get_persistent_level(self):
        if not self.gworld:
            return None
        return self.reader.read_u64(self.gworld + OFFSETS['PersistentLevel'])

    def get_actors(self):
        """Lit la liste des acteurs du niveau"""
        level = self.get_persistent_level()
        if not level or level < 0x10000:
            return [], 0

        actors_ptr = self.reader.read_u64(level + OFFSETS['AActors'])
        actor_count = self.reader.read_i32(level + OFFSETS['ActorCount'])

        if actors_ptr < 0x10000 or actor_count <= 0 or actor_count > 10000:
            return [], 0

        # Lire le tableau de pointeurs d'acteurs
        raw = self.reader.read(actors_ptr, actor_count * 8)
        actors = []
        for i in range(actor_count):
            ptr = struct.unpack_from('<Q', raw, i * 8)[0]
            if ptr > 0x10000:
                actors.append(ptr)

        return actors, actor_count

    def get_actor_location(self, actor):
        """Lit la position d'un acteur"""
        root = self.reader.read_u64(actor + OFFSETS['RootComponent'])
        if root < 0x10000:
            return None
        return self.reader.read_vec3(root + OFFSETS['RelativeLocation'])

    def get_local_camera(self):
        """Lit la position et rotation de la caméra locale"""
        if not self.gworld:
            return None, None, None

        # GWorld -> OwningGameInstance -> LocalPlayers[0] -> PlayerController -> CameraManager
        game_instance = self.reader.read_u64(self.gworld + OFFSETS['OwningGameInstance'])
        if game_instance < 0x10000:
            return None, None, None

        # LocalPlayers array
        local_players_ptr = self.reader.read_u64(game_instance + 0x38)
        if local_players_ptr < 0x10000:
            return None, None, None

        local_player = self.reader.read_u64(local_players_ptr)
        if local_player < 0x10000:
            return None, None, None

        player_controller = self.reader.read_u64(local_player + 0x30)
        if player_controller < 0x10000:
            return None, None, None

        camera_manager = self.reader.read_u64(player_controller + OFFSETS['CameraManager'])
        if camera_manager < 0x10000:
            return None, None, None

        # CameraCache -> POV
        cache = camera_manager + OFFSETS['CameraCache']
        location = self.reader.read_vec3(cache + OFFSETS['POV_Location'])
        rotation = self.reader.read_rotator(cache + OFFSETS['POV_Rotation'])
        fov = self.reader.read_float(cache + OFFSETS['POV_FOV'])

        return location, rotation, fov

    def is_player_actor(self, actor):
        """Vérifie si un acteur est un joueur (a un PlayerState)"""
        player_state = self.reader.read_u64(actor + OFFSETS['PlayerState'])
        return player_state > 0x10000

    def get_player_name(self, actor):
        """Lit le nom du joueur"""
        player_state = self.reader.read_u64(actor + OFFSETS['PlayerState'])
        if player_state < 0x10000:
            return '?'
        return self.reader.read_fstring(player_state + OFFSETS['PlayerName'])

    def update(self):
        """Met à jour toutes les positions"""
        if not self.update_gworld():
            return False

        # Caméra locale
        cam_loc, cam_rot, cam_fov = self.get_local_camera()
        if cam_loc:
            self.local_pos = cam_loc
        if cam_rot:
            self.local_yaw = cam_rot[1]  # Yaw

        # Acteurs
        actors, count = self.get_actors()
        self.players = []

        for actor in actors:
            if not self.is_player_actor(actor):
                continue

            loc = self.get_actor_location(actor)
            if loc is None:
                continue

            name = self.get_player_name(actor)
            dx = loc[0] - self.local_pos[0]
            dy = loc[1] - self.local_pos[1]
            dz = loc[2] - self.local_pos[2]
            dist = math.sqrt(dx*dx + dy*dy + dz*dz) / 100  # UE units to meters

            self.players.append({
                'name': name,
                'pos': loc,
                'dist': dist,
                'dx': dx,
                'dy': dy,
                'dz': dz,
            })

        return True


def render_ascii_radar(radar, radius=100):
    """Affiche un radar ASCII dans le terminal"""
    WIDTH = 41
    HEIGHT = 21
    CENTER_X = WIDTH // 2
    CENTER_Y = HEIGHT // 2
    SCALE = radius * 100  # UE units

    # Grille vide
    grid = [[' ' for _ in range(WIDTH)] for _ in range(HEIGHT)]

    # Bordure
    for x in range(WIDTH):
        grid[0][x] = '-'
        grid[HEIGHT-1][x] = '-'
    for y in range(HEIGHT):
        grid[y][0] = '|'
        grid[y][WIDTH-1] = '|'

    # Joueur local au centre
    grid[CENTER_Y][CENTER_X] = '@'

    # Rotation locale (yaw en degrés)
    yaw_rad = math.radians(-radar.local_yaw)
    cos_yaw = math.cos(yaw_rad)
    sin_yaw = math.sin(yaw_rad)

    # Autres joueurs
    markers = []
    for i, player in enumerate(radar.players):
        if player['dist'] < 1:  # C'est nous
            continue

        # Rotation relative au yaw du joueur
        rx = player['dx'] * cos_yaw - player['dy'] * sin_yaw
        ry = player['dx'] * sin_yaw + player['dy'] * cos_yaw

        # Normaliser sur la grille
        px = int(CENTER_X + (rx / SCALE) * (WIDTH // 2))
        py = int(CENTER_Y - (ry / SCALE) * (HEIGHT // 2))

        if 1 <= px < WIDTH-1 and 1 <= py < HEIGHT-1:
            marker = str(i % 10)
            grid[py][px] = marker
            markers.append(f"  {marker}: {player['name'][:20]:20s} {player['dist']:.0f}m")

    # Affichage
    os.system('clear' if os.name != 'nt' else 'cls')
    print(f"  ARC RAIDERS RADAR  |  Players: {len(radar.players)}  |  Radius: {radius}m")
    print(f"  Pos: ({radar.local_pos[0]:.0f}, {radar.local_pos[1]:.0f}, {radar.local_pos[2]:.0f})  Yaw: {radar.local_yaw:.0f}")
    print()

    for row in grid:
        print(''.join(row))

    print()
    if markers:
        for m in markers:
            print(m)
    else:
        print("  Aucun joueur détecté")

    print(f"\n  [Ctrl+C pour quitter]")


# === WEB RADAR ===

RADAR_HTML = '''<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Arc Raiders Radar</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a0a; color: #0f0; font-family: 'Consolas', monospace; overflow: hidden; }
canvas { display: block; margin: 20px auto; }
#hud { text-align: center; padding: 10px; font-size: 14px; }
#players { position: fixed; right: 10px; top: 10px; width: 280px; background: rgba(0,20,0,0.8);
  border: 1px solid #0f0; padding: 10px; font-size: 12px; max-height: 90vh; overflow-y: auto; }
.player-entry { padding: 3px 0; border-bottom: 1px solid #030; }
.dist { color: #ff0; float: right; }
#status { position: fixed; left: 10px; top: 10px; font-size: 12px; color: #0a0; }
</style></head><body>
<div id="status">Connecting...</div>
<div id="hud">ARC RAIDERS RADAR</div>
<canvas id="radar" width="600" height="600"></canvas>
<div id="players"></div>
<script>
const canvas = document.getElementById('radar');
const ctx = canvas.getContext('2d');
const W = canvas.width, H = canvas.height;
const CX = W/2, CY = H/2;
let radarRadius = 150; // meters
let data = { players: [], local_pos: [0,0,0], local_yaw: 0 };

function drawRadar() {
  ctx.fillStyle = '#0a0a0a';
  ctx.fillRect(0, 0, W, H);

  // Grid circles
  ctx.strokeStyle = '#0a2a0a';
  ctx.lineWidth = 1;
  for (let r = 1; r <= 4; r++) {
    ctx.beginPath();
    ctx.arc(CX, CY, (r/4) * (W/2 - 20), 0, Math.PI * 2);
    ctx.stroke();
    ctx.fillStyle = '#0a3a0a';
    ctx.font = '10px Consolas';
    ctx.fillText(Math.round(radarRadius * r / 4) + 'm', CX + 4, CY - (r/4) * (W/2 - 20) + 12);
  }

  // Crosshairs
  ctx.strokeStyle = '#0a2a0a';
  ctx.beginPath();
  ctx.moveTo(CX, 20); ctx.lineTo(CX, H-20);
  ctx.moveTo(20, CY); ctx.lineTo(W-20, CY);
  ctx.stroke();

  // North indicator
  ctx.fillStyle = '#f00';
  ctx.font = 'bold 14px Consolas';
  ctx.textAlign = 'center';
  let yawRad = -data.local_yaw * Math.PI / 180;
  let nx = CX + Math.sin(yawRad) * (W/2 - 10);
  let ny = CY - Math.cos(yawRad) * (H/2 - 10);
  ctx.fillText('N', nx, ny);

  // Local player
  ctx.fillStyle = '#0f0';
  ctx.beginPath();
  ctx.arc(CX, CY, 5, 0, Math.PI * 2);
  ctx.fill();
  // Direction triangle
  ctx.beginPath();
  ctx.moveTo(CX, CY - 12);
  ctx.lineTo(CX - 5, CY - 2);
  ctx.lineTo(CX + 5, CY - 2);
  ctx.closePath();
  ctx.fill();

  // Other players
  let scale = (W/2 - 20) / (radarRadius * 100); // UE units to pixels
  let cos_y = Math.cos(yawRad);
  let sin_y = Math.sin(yawRad);
  let playerList = '';

  data.players.forEach((p, i) => {
    if (p.dist < 1) return; // skip self

    let rx = p.dx * cos_y - p.dy * sin_y;
    let ry = p.dx * sin_y + p.dy * cos_y;
    let px = CX + rx * scale;
    let py = CY - ry * scale;

    // Clamp to radar edge
    let fromCenter = Math.sqrt((px-CX)**2 + (py-CY)**2);
    let maxR = W/2 - 25;
    let onEdge = false;
    if (fromCenter > maxR) {
      px = CX + (px-CX) * maxR / fromCenter;
      py = CY + (py-CY) * maxR / fromCenter;
      onEdge = true;
    }

    // Color based on distance
    let color = p.dist < 30 ? '#f00' : p.dist < 80 ? '#ff0' : '#0f0';
    if (onEdge) color = '#666';

    // Draw dot
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(px, py, onEdge ? 3 : 5, 0, Math.PI * 2);
    ctx.fill();

    // Label
    ctx.fillStyle = color;
    ctx.font = '10px Consolas';
    ctx.textAlign = 'center';
    let label = p.name || ('P' + i);
    if (label.length > 12) label = label.substring(0, 12);
    ctx.fillText(label, px, py - 8);

    // Height indicator
    let dz = p.dz / 100;
    if (Math.abs(dz) > 2) {
      ctx.fillText(dz > 0 ? '▲' : '▼', px + 15, py + 4);
    }

    playerList += '<div class="player-entry">' + (p.name||'?') +
      '<span class="dist">' + Math.round(p.dist) + 'm</span></div>';
  });

  document.getElementById('players').innerHTML =
    '<b>Players (' + data.players.filter(p => p.dist >= 1).length + ')</b><br>' + playerList;

  ctx.textAlign = 'left';
  document.getElementById('hud').textContent =
    'ARC RAIDERS RADAR | Radius: ' + radarRadius + 'm | ' +
    'Pos: (' + data.local_pos.map(v => Math.round(v)).join(', ') + ')';
}

// SSE connection
function connect() {
  const es = new EventSource('/stream');
  es.onmessage = function(e) {
    data = JSON.parse(e.data);
    drawRadar();
    document.getElementById('status').textContent =
      'Connected | ' + new Date().toLocaleTimeString();
  };
  es.onerror = function() {
    document.getElementById('status').textContent = 'Disconnected - reconnecting...';
    es.close();
    setTimeout(connect, 2000);
  };
}

// Scroll to zoom
canvas.addEventListener('wheel', function(e) {
  e.preventDefault();
  radarRadius = Math.max(20, Math.min(500, radarRadius + (e.deltaY > 0 ? 10 : -10)));
});

connect();
drawRadar();
</script></body></html>'''


class RadarHTTPHandler(SimpleHTTPRequestHandler):
    """Handler HTTP pour le radar web"""
    radar_data = {'players': [], 'local_pos': [0, 0, 0], 'local_yaw': 0}
    clients = []

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(RADAR_HTML.encode())
        elif self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            RadarHTTPHandler.clients.append(self.wfile)
            try:
                while True:
                    time.sleep(60)
            except:
                pass
            finally:
                if self.wfile in RadarHTTPHandler.clients:
                    RadarHTTPHandler.clients.remove(self.wfile)
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass  # Silence les logs HTTP

    @classmethod
    def broadcast(cls, data):
        msg = f"data: {json.dumps(data)}\n\n"
        dead = []
        for client in cls.clients:
            try:
                client.write(msg.encode())
                client.flush()
            except:
                dead.append(client)
        for d in dead:
            cls.clients.remove(d)


def start_web_server(port=8888):
    """Lance le serveur web en arrière-plan"""
    server = HTTPServer(('0.0.0.0', port), RadarHTTPHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    print("=" * 50)
    print("  ARC RAIDERS RADAR v1.1")
    print("  Linux/Proton — lecture /proc/PID/mem")
    print("=" * 50)
    print()

    if os.name == 'nt':
        print("[!] Ce script ne fonctionne que sous Linux!")
        print("    Le jeu doit tourner via Steam/Proton.")
        print("    EAC ne tourne pas sous Proton,")
        print("    donc /proc/PID/mem est lisible.")
        sys.exit(1)

    if os.geteuid() != 0:
        print("[!] Root requis pour lire /proc/PID/mem")
        print("    Relance avec: sudo python3 radar.py")
        sys.exit(1)

    # Trouver le processus
    print("[*] Recherche de PioneerGame...")
    pid = find_game_pid()
    if pid is None:
        print("[!] Jeu non trouvé. Lance Arc Raiders d'abord!")
        sys.exit(1)
    print(f"[+] PID: {pid}")

    # Ouvrir la mémoire
    reader = ProcessMemoryReader(pid)
    reader.open()

    base = reader.get_base_address()
    if base is None:
        print("[!] Impossible de trouver l'adresse de base!")
        sys.exit(1)
    print(f"[+] Base: 0x{base:x}")

    # Créer le radar
    radar = Radar(reader, base)

    # Vérifier GWorld
    if not radar.update_gworld():
        print("[!] GWorld non trouvé — les offsets sont peut-être obsolètes")
        print(f"    GWorld addr: 0x{base + OFFSETS['GWorld']:x}")
        print("    Vérifier les offsets sur UC/dumpspace")
    else:
        print(f"[+] GWorld: 0x{radar.gworld:x}")

    # Choix du mode d'affichage
    web_mode = '--ascii' not in sys.argv
    if web_mode:
        port = 8888
        for i, arg in enumerate(sys.argv):
            if arg == '--port' and i + 1 < len(sys.argv):
                port = int(sys.argv[i + 1])
        start_web_server(port)
        print(f"[+] Radar web: http://localhost:{port}")
        print(f"    (ouvrir dans un navigateur)")
    else:
        print("[*] Mode ASCII (ajouter rien ou --port PORT pour le mode web)")

    print()
    print("[*] Démarrage du radar... (Ctrl+C pour arrêter)")
    time.sleep(1)

    # Boucle principale
    radius = 150  # mètres
    try:
        while True:
            if radar.update():
                if web_mode:
                    RadarHTTPHandler.broadcast({
                        'players': radar.players,
                        'local_pos': list(radar.local_pos),
                        'local_yaw': radar.local_yaw,
                    })
                else:
                    render_ascii_radar(radar, radius)
            else:
                if not web_mode:
                    print("[!] Erreur de lecture — le jeu tourne encore?")
            time.sleep(0.1)  # ~10 FPS
    except KeyboardInterrupt:
        print("\n[*] Arrêt du radar")
    finally:
        reader.close()


if __name__ == '__main__':
    main()
