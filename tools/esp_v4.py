#!/usr/bin/env python3
"""
ESP v4 — Arc Raiders (SDK offsets from FrostDumper + UC thread pages 144-150)
Uses CommDriver shared memory for kernel-level reads.

Offsets verified against:
  - DUMP_Offsets.txt (FrostDumper SDK dump, current patch)
  - UC thread pages 144-150 (confirmed working by ModrokiXyz, mrcarpetabr, Masberp, etc.)
"""
import ctypes
import ctypes.wintypes as wt
import struct
import time
import sys
import math
import threading

try:
    import glfw
    import OpenGL.GL as gl
    from imgui_bundle import imgui, imgui_ctx
    from imgui_bundle.python_backends.glfw_backend import GlfwRenderer
except ImportError:
    print("[!] imgui-bundle ou glfw manquant.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# CommDriver shared memory
# ---------------------------------------------------------------------------
kernel32 = ctypes.windll.kernel32
kernel32.OpenFileMappingW.restype = ctypes.c_void_p
kernel32.MapViewOfFile.restype = ctypes.c_void_p


class COMM_SHARED(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ready", ctypes.c_int32), ("command", ctypes.c_int32), ("status", ctypes.c_int32),
        ("process_name", ctypes.c_char * 260), ("pid", ctypes.c_uint64), ("cr3", ctypes.c_uint64),
        ("address", ctypes.c_uint64), ("size", ctypes.c_uint64), ("peb_address", ctypes.c_uint64),
        ("image_base", ctypes.c_uint64), ("data", ctypes.c_ubyte * 0x10000),
    ]


class Mem:
    def __init__(self):
        self.shared = None
        self.pid = 0
        self.cr3 = 0
        self.base = 0
        # Single shared-mem channel: only one thread may hold the driver at a time.
        self._drv_lock = threading.Lock()

    def connect(self):
        h = kernel32.OpenFileMappingW(0xF001F, False, "Global\\ArcComm")
        if not h:
            return False
        v = kernel32.MapViewOfFile(h, 0xF001F, 0, 0, ctypes.sizeof(COMM_SHARED))
        self.shared = COMM_SHARED.from_address(v)
        return self.shared.ready == 1

    def _wait(self, ms=500):
        deadline = time.perf_counter() + ms / 1000
        while time.perf_counter() < deadline:
            if self.shared.command == 0:
                return True
            time.sleep(0.0001)
        return False

    def attach(self, name="PioneerGame.exe"):
        for n in [name, name.replace(".exe", ".ex")]:
            self.shared.pid = 0
            self.shared.cr3 = 0
            self.shared.status = -1
            self.shared.process_name = n.encode()[:259]
            self.shared.command = 1
            if self._wait() and self.shared.status == 0 and self.shared.pid:
                self.pid, self.cr3 = self.shared.pid, self.shared.cr3
                return True
        return False

    def find_base(self):
        try:
            ntdll = ctypes.windll.ntdll

            class PBI(ctypes.Structure):
                _fields_ = [
                    ("R1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                    ("R2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                    ("R3", ctypes.c_void_p),
                ]

            h = kernel32.OpenProcess(0x1000, False, self.pid)
            pbi = PBI()
            ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
            kernel32.CloseHandle(h)
            base = self.u64(pbi.PebBaseAddress + 0x10)
            if base > 0x10000:
                self.base = base
        except Exception:
            pass
        return self.base

    def read(self, addr, size):
        if addr < 0x10000 or addr > 0x7FFFFFFFFFFF:
            return b'\x00' * size
        with self._drv_lock:
            self.shared.cr3 = self.cr3
            self.shared.address = addr
            self.shared.size = size
            self.shared.command = 2
            if not self._wait():
                return b'\x00' * size
            if self.shared.status != 0:
                return b'\x00' * size
            return bytes(self.shared.data[:size])

    def u64(self, a):
        return struct.unpack('<Q', self.read(a, 8))[0]

    def batch_u64(self, addrs):
        """Read N u64 values in a single IOCTL (CMD_BATCH_READ_U64=5)."""
        n = len(addrs)
        if n == 0:
            return []
        if n > 8000:
            # split
            out = []
            for i in range(0, n, 8000):
                out.extend(self.batch_u64(addrs[i:i+8000]))
            return out
        with self._drv_lock:
            ctypes.memmove(self.shared.data, struct.pack(f'<{n}Q', *addrs), n * 8)
            self.shared.cr3 = self.cr3
            self.shared.size = n
            self.shared.command = 5
            if not self._wait(2000) or self.shared.status != 0:
                return [0] * n
            return list(struct.unpack(f'<{n}Q', bytes(self.shared.data[:n * 8])))

    def i32(self, a):
        return struct.unpack('<i', self.read(a, 4))[0]

    def u32(self, a):
        return struct.unpack('<I', self.read(a, 4))[0]

    def f32(self, a):
        return struct.unpack('<f', self.read(a, 4))[0]

    def f64(self, a):
        return struct.unpack('<d', self.read(a, 8))[0]

    def vec3d(self, a):
        """FVector (3 doubles, UE5 LWC, 24 bytes)"""
        d = self.read(a, 24)
        return struct.unpack('<ddd', d) if len(d) == 24 else (0.0, 0.0, 0.0)

    def vec3f(self, a):
        """3 floats (12 bytes)"""
        d = self.read(a, 12)
        return struct.unpack('<fff', d) if len(d) == 12 else (0.0, 0.0, 0.0)

    def read_rotator(self, a):
        """FRotator — UE5 LWC uses doubles (pitch, yaw, roll)"""
        d = self.read(a, 24)
        return struct.unpack('<ddd', d) if len(d) == 24 else (0.0, 0.0, 0.0)


# ---------------------------------------------------------------------------
# SDK Offsets (FrostDumper dump + Arc Raiders C++ source + UC thread)
# ---------------------------------------------------------------------------
class OFF:
    # === RVA — 4.9.26 (Xinan8694 / UC thread) ===
    GWORLD = 0xE011D18

    # === UWorld (dump 2026-04-14) ===
    PersistentLevel = 0xF0

    # === ULevel → Actors TArray (UC confirmed 4.9.26) ===
    AActors = 0x108           # ptr
    # ActorCount = AActors + 8 (= 0x110)

    # === AActor (dump) ===
    RootComponent = 0x230
    ActorID = 0x18

    # === USceneComponent (dump) ===
    RelativeLocation = 0x218  # FVector (3 doubles)
    ComponentToWorld = 0x330  # FTransform — UC confirmed 4.9.26
    ComponentVelocity = 0x260

    # === ACharacter ===
    SkeletalMeshComponent = 0x430

    # === APawn (dump) ===
    PlayerState = 0x3D0       # APawn.PlayerState
    PawnController = 0x3E8    # APawn.Controller (backref, used to validate)

    # === AController (dump) ===
    ControllerPawn = 0x3F0    # AController.Pawn
    ControlRotation = 0x428

    # === APlayerController ===
    # AcknowledgedPawn n'est pas exposé par le dump et 0x3E8 = AController.StateName (FName).
    # On utilise AController.Pawn (0x3F0) à la place — côté client il n'y a qu'un seul
    # APlayerController (le local), les autres joueurs n'ont que Pawn+PlayerState répliqués.
    AcknowledgedPawn = 0x3F0

    # === APlayerCameraManager (dump) ===
    PCM_PCOwner = 0x430       # APlayerCameraManager.PCOwner (used to locate CamMgr)
    PCM_ViewTarget = 0xCA0    # FTViewTarget struct start
    # FTViewTarget: Target=+0x00, POV=+0x10 (FMinimalViewInfo), PlayerState=+0x820
    # FMinimalViewInfo: Location=+0x10 (3 doubles), Rotation=+0x30 (3 doubles), FOV=+0x50 (float)
    PCM_POV = 0xCA0 + 0x10    # = 0xCB0, start of FMinimalViewInfo

    # === APlayerState (dump) ===
    PawnPrivate = 0x428       # APlayerState.PawnPrivate
    PlayerNamePrivate = 0x448 # FString

    # === EmbarkPawn ===
    TeamID = 0x4D9           # uint8 (C++ source)

    # === Health (C++ source — reads as double!) ===
    HealthComponent = 0xD20   # actor → HealthComponent ptr
    Health = 0x688            # HealthComponent → CachedHealth (double)
    MaxHealth = 0x328         # HealthComponent → MaxHealth (double)
    HealthInfo = 0x530        # PlayerState → PlayerHealthInfo struct
    Shield = 0x1A0            # HealthComponent → Shield (double)

    # === Inventory / Items (C++ source) ===
    InventoryComponent = 0xC58  # actor → InventoryComponent ptr
    LocalCurrentItemActors = 0x540  # InventoryComponent → TArray of weapon actors
    WeaponQuality = 0x540     # weapon actor → quality uint8

    # === Visibility (C++ source) ===
    LastSubmitTime = 0x49C              # PrimitiveComponent
    LastRenderTimeOnScreen = 0x4A4      # PrimitiveComponent


# NPC class → display name (UC page 144, YumikoImagwa)
NPC_NAMES = {
    "C_BullCrab_01_C":              "Leaper",
    "C_ChonkPlatform_Mortar_C":     "Bombardier",
    "C_Chonk_C":                    "Bastian",
    "C_EliteDrone_Flamethrower_C":  "Firefly",
    "C_HeavyDrone_Missile_C":       "Rocketeer",
    "C_LightDrone_02_C":            "Wasp",
    "C_LightDrone_Elite_C":         "Hornet",
    "C_Pinger_C":                   "Spotter",
    "C_RollBot_01_Blockout_Normal_C": "Surveyor",
    "C_RollBot_Flamethrower_C":     "Fireball",
    "C_RollBot_Pop_C":              "Pop",
    "C_Rollbot_Boom_C":             "Comet",
    "C_Runner_C":                   "Surveyor",
    "C_Sniper_C":                   "Sentinel",
    "C_SnitchBot_01_C":             "Snitch",
    "C_Spearmint_C":                "Shredder",
    "C_TickBot_C":                  "Tick",
    "C_TurretEnemy_C":              "Turret",
}

# Weapon internal name → display name (UC page 150, ModrokiXyz)
WEAPON_NAMES = {
    "AssaultRifle_Bullpup_01":     "Tempest",
    "AssaultRifle_Burst_01":       "Arpeggio",
    "AssaultRifle_LowTier_01":     "Rattler",
    "AssaultRifle_Pneumatic_01":   "Kettle",
    "AssaultRifle_Heavy_01":       "Bettina",
    "BattleRifle_BreachAction_01": "Ferro",
    "BattleRifle_EnergyBurst_01": "Pulse",
    "DMR_Bolt_01":                 "Longbow",
    "SMG_LowTier_01":             "Buzzer",
    "SMG_Burst_01":                "Raptor",
    "Shotgun_LowTier_01":         "Scrap",
    "Shotgun_Slug_01":             "Boomstick",
    "LMG_Heavy_01":                "Hog",
    "Sniper_Bolt_01":              "Viper",
    "Sniper_Semi_01":              "Marksman",
    "Pistol_LowTier_01":          "Peashooter",
}


# ---------------------------------------------------------------------------
# Game state
# ---------------------------------------------------------------------------
class Game:
    def __init__(self, mem):
        self.m = mem
        self.gworld = 0
        self.last_world = 0
        self.persistent_level = 0
        self.player_controller = 0
        self.acknowledged_pawn = 0
        self.root_component = 0
        self.pcm = 0
        self.pcm_scan_idx = 0
        self.actors_ptr = 0
        self.cam_loc = (0.0, 0.0, 0.0)
        self.cam_rot = (0.0, 0.0, 0.0)
        self.cam_fov = 90.0
        self.players = []
        # Double-buffered snapshots for smooth interpolated rendering.
        # Worker thread fills these; render thread reads them under lock.
        self._lock = threading.Lock()
        self._snap_prev = None     # (ts, players, cam_loc, cam_rot, cam_fov)
        self._snap_cur = None
        self._stop = False
        self._thread = None
        self.tick_dt_ms = 0.0      # last worker tick time (for HUD)

    # ------------------------------------------------------------------
    def _valid(self, ptr):
        return 0x10000 < ptr < 0x7FFFFFFFFFFF

    def _bulk_read_ptrs(self, arr_ptr, count):
        batch = min(count, 8000)
        data = self.m.read(arr_ptr, batch * 8)
        actors = []
        for i in range(batch):
            a = struct.unpack_from('<Q', data, i * 8)[0]
            if self._valid(a):
                actors.append(a)
        return actors

    # ------------------------------------------------------------------
    def _read_health(self, actor):
        """Read health as double (matching C++ source)"""
        m = self.m
        hc = m.u64(actor + OFF.HealthComponent)
        if not self._valid(hc):
            return -1, -1
        hp = m.f64(hc + OFF.Health)       # double!
        max_hp = m.f64(hc + OFF.MaxHealth) # double!
        if 0 < hp < 100000 and 0 < max_hp < 100000:
            return hp, max_hp
        return -1, -1

    # ------------------------------------------------------------------
    def _update_camera(self):
        """FMinimalViewInfo at PCM + 0xCA0 (FTViewTarget) + 0x10 (POV).
        Reads loc(3d) + rot(3d) + fov(f32 packed in u64) in 1 batch IOCTL."""
        if not self.pcm:
            return
        m = self.m
        pov = self.pcm + OFF.PCM_POV
        # 6 u64 for loc/rot doubles + 1 u64 covering fov f32
        words = m.batch_u64([
            pov + 0x10, pov + 0x18, pov + 0x20,   # Location.X/Y/Z
            pov + 0x30, pov + 0x38, pov + 0x40,   # Rotation.P/Y/R
            pov + 0x50,                            # FOV (low 32 bits)
        ])
        loc = struct.unpack('<ddd', struct.pack('<QQQ', *words[0:3]))
        rot = struct.unpack('<ddd', struct.pack('<QQQ', *words[3:6]))
        fov = struct.unpack('<f', struct.pack('<I', words[6] & 0xFFFFFFFF))[0]
        if any(abs(v) > 100 for v in loc) and 10 < fov < 170 and all(abs(v) < 360 for v in rot):
            self.cam_loc = loc
            self.cam_rot = rot
            self.cam_fov = fov

    # ------------------------------------------------------------------
    def _find_player_controller(self, actors):
        """
        Batch scan: read AcknowledgedPawn for all actors in 1 IOCTL,
        then validate each candidate pawn via Pawn.Controller backref.
        """
        m = self.m
        pawns = m.batch_u64([a + OFF.AcknowledgedPawn for a in actors])
        cand_idx = [i for i, p in enumerate(pawns) if self._valid(p)]
        if not cand_idx:
            return False
        # Validate backref: pawn.Controller == actor
        ctrls = m.batch_u64([pawns[i] + OFF.PawnController for i in cand_idx])
        for k, i in enumerate(cand_idx):
            if ctrls[k] == actors[i]:
                pawn = pawns[i]
                pawn_root = m.u64(pawn + OFF.RootComponent)
                if not self._valid(pawn_root):
                    continue
                self.player_controller = actors[i]
                self.acknowledged_pawn = pawn
                self.root_component = pawn_root
                print(f"[+] PlayerController: 0x{actors[i]:X}")
                print(f"    LocalPawn:        0x{pawn:X}")
                return True
        return False

    # ------------------------------------------------------------------
    def _try_pcm_direct(self):
        """
        Fast path: read entire PC blob in 1 IOCTL, extract all valid pointers,
        validate each by checking ptr.PCOwner == PC.
        APlayerController size is ~0xE00, scan 0x300..0xE00.
        """
        m = self.m
        pc = self.player_controller
        # Single bulk read of PC structure
        blob = m.read(pc, 0xE00)
        if len(blob) < 0xE00:
            return False
        # Collect unique valid pointer candidates from PC blob
        seen = set()
        candidates = []
        for off in range(0x300, 0xDF8, 8):
            cand = struct.unpack_from('<Q', blob, off)[0]
            if not self._valid(cand) or cand in seen:
                continue
            seen.add(cand)
            candidates.append((off, cand))
        print(f"[*] PCM scan: {len(candidates)} pointer candidates in PC")
        for off, cand in candidates[:128]:
            if m.u64(cand + OFF.PCM_PCOwner) == pc:
                self.pcm = cand
                print(f"[+] CameraManager: 0x{cand:X} (PC+0x{off:X})")
                return True
        return False

    def _find_camera_manager(self, actors):
        """
        Batch scan: read PCOwner for all actors in 1 IOCTL via CMD_BATCH_READ_U64.
        APlayerCameraManager is the only actor with PCOwner == localPC.
        """
        m = self.m
        pc = self.player_controller
        addrs = [a + OFF.PCM_PCOwner for a in actors]
        owners = m.batch_u64(addrs)
        for a, owner in zip(actors, owners):
            if owner == pc and a != pc and a != self.acknowledged_pawn:
                self.pcm = a
                print(f"[+] CameraManager: 0x{a:X}")
                return True
        return False

    # ------------------------------------------------------------------
    def update(self):
        m = self.m

        # === GWorld: double dereference (matching C++ source) ===
        gworld_ptr = m.u64(m.base + OFF.GWORLD)
        if not self._valid(gworld_ptr):
            return False
        gw = m.u64(gworld_ptr)
        if not self._valid(gw):
            return False

        # Detect world change
        if gw != self.last_world:
            self.last_world = gw
            self.gworld = gw
            self.player_controller = 0
            self.acknowledged_pawn = 0
            self.root_component = 0
            self.pcm = 0
            self.actors_ptr = 0
            self.persistent_level = 0
            print(f"[+] UWorld: 0x{gw:X}")

        # === PersistentLevel + actors_ptr (cached: stable while UWorld unchanged) ===
        if not self.persistent_level:
            pl = m.u64(gw + OFF.PersistentLevel)
            if not self._valid(pl):
                return False
            self.persistent_level = pl
        if not self.actors_ptr:
            ap = m.u64(self.persistent_level + OFF.AActors)
            if not self._valid(ap):
                return False
            self.actors_ptr = ap
        actors_ptr = self.actors_ptr
        actor_count = m.i32(self.persistent_level + OFF.AActors + 8)
        if actor_count <= 0 or actor_count > 10000:
            return False

        all_actors = self._bulk_read_ptrs(actors_ptr, actor_count)
        if not all_actors:
            return False

        # === Find PlayerController (scan for AcknowledgedPawn) ===
        if not self.player_controller:
            self._find_player_controller(all_actors)

        # === Find CameraManager: incremental scan (PCM is not pointed by PC, must scan actors) ===
        if self.player_controller and not self.pcm:
            self._find_camera_manager(all_actors)

        # Camera is refreshed by the dedicated camera thread (~500 Hz),
        # so don't waste a batch IOCTL here on the slow actor tick.

        # === Build entity list (batched) ===
        # Backref check: actor.PlayerState.PawnPrivate == actor → real Pawn
        cand = [a for a in all_actors if a and a != self.acknowledged_pawn]
        if not cand:
            self.players = []
            return True

        # Step 1: batch read PlayerState for all candidates
        ps_list = m.batch_u64([a + OFF.PlayerState for a in cand])
        valid_idx = [i for i, ps in enumerate(ps_list) if self._valid(ps_list[i])]
        if not valid_idx:
            self.players = []
            return True

        # Step 2: batch read PlayerState.PawnPrivate (backref)
        pawn_priv = m.batch_u64([ps_list[i] + OFF.PawnPrivate for i in valid_idx])
        survivors = [valid_idx[k] for k, pp in enumerate(pawn_priv) if pp == cand[valid_idx[k]]]
        if not survivors:
            self.players = []
            return True

        # Step 3: batch read RootComponent
        roots = m.batch_u64([cand[i] + OFF.RootComponent for i in survivors])

        # Step 4: batch read positions (3 u64 = vec3d) for all valid roots in 1 IOCTL
        valid_roots = [r for r in roots if self._valid(r)]
        if not valid_roots:
            self.players = []
            return True
        pos_base = OFF.ComponentToWorld + 0x20
        pos_addrs = []
        for r in valid_roots:
            pos_addrs.extend([r + pos_base, r + pos_base + 8, r + pos_base + 16])
        pos_words = m.batch_u64(pos_addrs)

        targets = []
        vi = 0  # index into valid_roots/pos_words
        for k, idx in enumerate(survivors):
            if not self._valid(roots[k]):
                continue
            w = pos_words[vi*3:vi*3+3]
            vi += 1
            if w == [0, 0, 0]:
                continue
            pos = struct.unpack('<ddd', struct.pack('<QQQ', *w))
            actor_addr = cand[idx]
            try:
                dx = pos[0] - self.cam_loc[0]
                dy = pos[1] - self.cam_loc[1]
                dz = pos[2] - self.cam_loc[2]
                dist = math.sqrt(dx * dx + dy * dy + dz * dz) / 100.0
            except (ValueError, OverflowError):
                continue
            if dist < 0.5 or dist > 3000:
                continue
            targets.append({
                'actor': actor_addr,
                'pos': pos, 'dist': dist,
                'hp': -1, 'max_hp': -1,
                'visible': False,
                'type': 'player',
            })

        self.players = targets
        return True

    # ------------------------------------------------------------------
    # Async snapshot / interpolation pipeline
    # ------------------------------------------------------------------
    def _take_snapshot(self):
        snap = (
            time.perf_counter(),
            self.players,
            self.cam_loc, self.cam_rot, self.cam_fov,
        )
        with self._lock:
            self._snap_prev = self._snap_cur
            self._snap_cur = snap

    def _worker_loop(self):
        while not self._stop:
            t0 = time.perf_counter()
            try:
                if self.update():
                    self._take_snapshot()
            except Exception as e:
                print(f"[!] worker err: {e}", flush=True)
                time.sleep(0.05)
            self.tick_dt_ms = (time.perf_counter() - t0) * 1000.0

    def _camera_loop(self):
        """High-frequency camera reader. Camera changes every game frame (60+ Hz),
        so we read it on its own thread instead of waiting for the slow actor tick.
        Reads 7 u64 in one batch IOCTL (~1-2 ms) — driver mutex serialises with worker."""
        while not self._stop:
            if self.pcm:
                try:
                    self._update_camera()
                except Exception:
                    pass
            time.sleep(0.002)  # ~500 Hz cap

    def start_worker(self):
        self._thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._thread.start()
        self._cam_thread = threading.Thread(target=self._camera_loop, daemon=True)
        self._cam_thread.start()

    def stop_worker(self):
        self._stop = True

    def interpolated(self):
        """Return (players, cam_loc, cam_rot, cam_fov). Camera is read live by
        the dedicated cam thread (~500 Hz), positions are extrapolated from the
        last two actor snapshots."""
        # Always use freshest camera (updated by _camera_loop, not the snapshot).
        cam_loc = self.cam_loc
        cam_rot = self.cam_rot
        cam_fov = self.cam_fov

        with self._lock:
            prev = self._snap_prev
            cur = self._snap_cur
        if cur is None:
            return [], cam_loc, cam_rot, cam_fov
        if prev is None:
            return cur[1], cam_loc, cam_rot, cam_fov

        dt_snap = cur[0] - prev[0]
        if dt_snap <= 1e-4:
            return cur[1], cam_loc, cam_rot, cam_fov

        # How far past the last snapshot are we? Cap to 1.5x interval to bound drift.
        ahead = max(0.0, min(time.perf_counter() - cur[0], dt_snap * 1.5))
        f = ahead / dt_snap  # extrapolation factor: 0=last snap, 1=one tick ahead

        def extrap(p, c):
            return (
                c[0] + (c[0] - p[0]) * f,
                c[1] + (c[1] - p[1]) * f,
                c[2] + (c[2] - p[2]) * f,
            )

        prev_by_addr = {p.get('actor', 0): p for p in prev[1]}
        out = []
        for p in cur[1]:
            prev_p = prev_by_addr.get(p.get('actor', 0))
            if not prev_p:
                out.append(p)
                continue
            pos = extrap(prev_p['pos'], p['pos'])
            dx = pos[0] - cam_loc[0]
            dy = pos[1] - cam_loc[1]
            dz = pos[2] - cam_loc[2]
            dist = math.sqrt(dx*dx + dy*dy + dz*dz) / 100.0
            np = dict(p)
            np['pos'] = pos
            np['dist'] = dist
            out.append(np)
        return out, cam_loc, cam_rot, cam_fov


# ---------------------------------------------------------------------------
# World-to-screen
# ---------------------------------------------------------------------------
def w2s(pos, cam_loc, cam_rot, fov, sw, sh):
    pitch = math.radians(cam_rot[0])
    yaw = math.radians(cam_rot[1])

    dx = pos[0] - cam_loc[0]
    dy = pos[1] - cam_loc[1]
    dz = pos[2] - cam_loc[2]

    cp, sp = math.cos(pitch), math.sin(pitch)
    cy, sy = math.cos(yaw), math.sin(yaw)

    fwd = (cp * cy, cp * sy, sp)
    rgt = (-sy, cy, 0.0)
    up = (-sp * cy, -sp * sy, cp)

    cX = dx * rgt[0] + dy * rgt[1] + dz * rgt[2]
    cY = dx * up[0] + dy * up[1] + dz * up[2]
    cZ = dx * fwd[0] + dy * fwd[1] + dz * fwd[2]

    if cZ < 1.0:
        return None

    tanF = math.tan(math.radians(max(fov, 1.0)) / 2.0)
    aspect = sw / sh
    sX = (sw / 2.0) + (cX / (cZ * tanF * aspect)) * (sw / 2.0)
    sY = (sh / 2.0) - (cY / (cZ * tanF)) * (sh / 2.0)
    return int(sX), int(sY)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main():
    m = Mem()
    if not m.connect():
        print("[!] Driver non connecté (Global\\ArcComm)")
        return
    if not m.attach():
        print("[!] Process non trouvé")
        return
    m.find_base()
    print(f"[+] Base: 0x{m.base:X}  PID: {m.pid}")

    g = Game(m)

    if not glfw.init():
        return
    glfw.window_hint(glfw.DECORATED, 0)
    glfw.window_hint(glfw.TRANSPARENT_FRAMEBUFFER, 1)
    glfw.window_hint(glfw.FLOATING, 1)

    SW, SH = 1920, 1080
    win = glfw.create_window(SW, SH, "ESP", None, None)
    glfw.make_context_current(win)
    imgui.create_context()
    impl = GlfwRenderer(win)

    print("[+] ESP v4 prêt")
    g.start_worker()
    frame = 0
    last_diag = time.perf_counter()
    fps_acc = 0
    fps_disp = 0.0

    while not glfw.window_should_close(win):
        glfw.poll_events()
        impl.process_inputs()

        players, cam_loc, cam_rot, cam_fov = g.interpolated()

        frame += 1
        fps_acc += 1
        now = time.perf_counter()
        if now - last_diag >= 1.0:
            fps_disp = fps_acc / (now - last_diag)
            fps_acc = 0
            last_diag = now
            vis = sum(1 for p in players if p.get('visible'))
            print(f"[DIAG] render={fps_disp:.0f}fps tick={g.tick_dt_ms:.0f}ms "
                  f"pl={getattr(g,'persistent_level',0):X} pc={g.player_controller:X} pcm={g.pcm:X} "
                  f"targets={len(players)} vis={vis}",
                  flush=True)

        # --- Render ---
        gl.glClear(gl.GL_COLOR_BUFFER_BIT)
        imgui.new_frame()
        imgui.set_next_window_pos((0, 0))
        imgui.set_next_window_size((SW, SH))
        imgui.push_style_color(imgui.Col_.window_bg, (0, 0, 0, 0))

        # Colors: AABBGGRR (ImGui packed)
        COL_VISIBLE  = 0xFF3232FF   # Red — visible enemy
        COL_HIDDEN   = 0xFF32FFFF   # Yellow — behind wall
        COL_HP_BG    = 0x80000000   # Semi-transparent black
        COL_HP_FG    = 0xFF32FF32   # Green
        COL_HP_LOW   = 0xFF3232FF   # Red
        COL_WHITE    = 0xFFFFFFFF

        with imgui_ctx.begin("##esp", None, 0x7F):
            dl = imgui.get_window_draw_list()

            n_vis = 0
            for p in players:
                scr = w2s(p['pos'], cam_loc, cam_rot, cam_fov, SW, SH)
                if not scr:
                    continue

                sx, sy = scr
                vis = p.get('visible', False)
                if vis:
                    n_vis += 1

                col = COL_VISIBLE if vis else COL_HIDDEN

                # Box size scales with distance
                dist = p['dist']
                box_h = max(8, min(80, int(2000 / max(dist, 1))))
                box_w = box_h // 2

                # Draw box
                dl.add_rect((sx - box_w, sy - box_h), (sx + box_w, sy + box_h // 4), col, 0, 0, 2)

                # Distance text
                dl.add_text((sx + box_w + 4, sy - box_h), COL_WHITE, f"{dist:.0f}m")

                # Health bar
                hp, max_hp = p.get('hp', -1), p.get('max_hp', -1)
                if hp > 0 and max_hp > 0:
                    bar_w = box_w * 2
                    bar_h = 4
                    bar_x = sx - box_w
                    bar_y = sy + box_h // 4 + 3
                    ratio = min(hp / max_hp, 1.0)
                    hp_col = COL_HP_FG if ratio > 0.3 else COL_HP_LOW
                    dl.add_rect_filled((bar_x, bar_y), (bar_x + bar_w, bar_y + bar_h), COL_HP_BG)
                    dl.add_rect_filled((bar_x, bar_y), (bar_x + int(bar_w * ratio), bar_y + bar_h), hp_col)

            # HUD
            dl.add_text((10, 10), 0xFF32FF32,
                        f"ESP v4 | Targets: {len(players)} ({n_vis} visible) | "
                        f"FOV: {cam_fov:.0f} | render {fps_disp:.0f}fps tick {g.tick_dt_ms:.0f}ms")

        imgui.pop_style_color()
        imgui.render()
        impl.render(imgui.get_draw_data())
        glfw.swap_buffers(win)

    glfw.terminate()


if __name__ == "__main__":
    main()
