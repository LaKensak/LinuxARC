"""
Lance Frida + mitmproxy pour intercepter l'API Arc Raiders
1. Vérifie les droits admin (nécessaire pour Frida)
2. Mode attach (jeu déjà lancé) ou spawn (lance le jeu via Frida)
3. Injecte le script de bypass SSL
4. Lance mitmproxy en mode local/transparent
"""

import subprocess
import sys
import os
import time
import ctypes
import json
import datetime as _dt
import frida

PROXY_PORT = 8080
GAME_PROCESS_NAMES = [
    "PioneerGame",
    "PioneerGame.exe",
    "PioneerGame-Win64-Shipping",
    "PioneerGame-Win64-Shipping.exe",
    "ArcRaiders",
    "ArcRaiders-Win64-Shipping",
    "ArcRaiders.exe",
    "ArcRaiders-Win64-Shipping.exe",
]

# Chemins possibles du jeu (Steam/Epic)
GAME_EXE_PATHS = [
    # Nom réel de l'exe: PioneerGame
    r"C:\Program Files (x86)\Steam\steamapps\common\Arc Raiders\PioneerGame\Binaries\Win64\PioneerGame-Win64-Shipping.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\Arc Raiders\PioneerGame.exe",
    r"F:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame\Binaries\Win64\PioneerGame.exe",
    r"D:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame\Binaries\Win64\PioneerGame-Win64-Shipping.exe",
    r"D:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame.exe",
    r"E:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame\Binaries\Win64\PioneerGame-Win64-Shipping.exe",
    r"E:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame.exe",
    r"F:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame\Binaries\Win64\PioneerGame-Win64-Shipping.exe",
    r"F:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame.exe",
    # Anciens noms au cas où
    r"C:\Program Files (x86)\Steam\steamapps\common\Arc Raiders\ArcRaiders\Binaries\Win64\ArcRaiders-Win64-Shipping.exe",
    r"C:\Program Files\Epic Games\ArcRaiders\ArcRaiders\Binaries\Win64\ArcRaiders-Win64-Shipping.exe",
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FRIDA_SCRIPT_SSL_BYPASS = os.path.join(SCRIPT_DIR, "tools", "frida_bypass_ssl.js")
FRIDA_SCRIPT_SSL_DUMP = os.path.join(SCRIPT_DIR, "tools", "frida_hook_ssl_rw.js")
FRIDA_SCRIPT = FRIDA_SCRIPT_SSL_BYPASS  # Default
MITM_SCRIPT = os.path.join(SCRIPT_DIR, "tools", "mitm_arc.py")


def is_admin():
    """Vérifie si on tourne en administrateur"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def elevate_to_admin():
    """Relance le script en administrateur via UAC"""
    print("[*] Élévation des privilèges via UAC...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        f'"{os.path.abspath(__file__)}" ' + ' '.join(sys.argv[1:]),
        None, 1
    )
    sys.exit(0)


def find_game_pid():
    """Trouve le PID du processus Arc Raiders"""
    print("[*] Recherche du processus Arc Raiders...")

    # Méthode 1: via Frida
    try:
        device = frida.get_local_device()
        processes = device.enumerate_processes()
        for proc in processes:
            name_lower = proc.name.lower()
            if ("arc" in name_lower and "raid" in name_lower) or "pioneergame" in name_lower:
                print(f"[+] Trouvé: {proc.name} (PID: {proc.pid})")
                return proc.pid, proc.name
            for game_name in GAME_PROCESS_NAMES:
                if proc.name.lower() == game_name.lower().replace(".exe", ""):
                    print(f"[+] Trouvé: {proc.name} (PID: {proc.pid})")
                    return proc.pid, proc.name
    except Exception as e:
        print(f"[!] Erreur Frida enumerate: {e}")

    # Méthode 2: via tasklist
    try:
        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                name = parts[0]
                if ("arc" in name.lower() and "raid" in name.lower()) or "pioneergame" in name.lower():
                    pid = int(parts[1])
                    print(f"[+] Trouvé via tasklist: {name} (PID: {pid})")
                    return pid, name
    except Exception as e:
        print(f"[!] Erreur tasklist: {e}")

    return None, None


def find_game_exe():
    """Trouve l'exécutable du jeu pour le mode spawn"""
    for path in GAME_EXE_PATHS:
        if os.path.exists(path):
            return path

    # Chercher via le registre Steam
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Valve\Steam"
        )
        steam_path = winreg.QueryValueEx(key, "InstallPath")[0]
        winreg.CloseKey(key)

        # Lire libraryfolders.vdf pour trouver toutes les bibliothèques
        vdf_path = os.path.join(steam_path, "steamapps", "libraryfolders.vdf")
        if os.path.exists(vdf_path):
            with open(vdf_path, 'r') as f:
                content = f.read()
            import re
            paths = re.findall(r'"path"\s+"([^"]+)"', content)
            for lib_path in paths:
                # Chercher PioneerGame d'abord
                for exe_name in [
                    os.path.join("PioneerGame", "Binaries", "Win64", "PioneerGame-Win64-Shipping.exe"),
                    "PioneerGame.exe",
                    os.path.join("ArcRaiders", "Binaries", "Win64", "ArcRaiders-Win64-Shipping.exe"),
                ]:
                    exe = os.path.join(lib_path, "steamapps", "common", "Arc Raiders", exe_name)
                    if os.path.exists(exe):
                        return exe
    except Exception as e:
        print(f"[!] Erreur recherche Steam: {e}")

    return None


_CAPTURE_LOG = os.path.join(SCRIPT_DIR, "data", "logs", f"ssl_dump_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
os.makedirs(os.path.dirname(_CAPTURE_LOG), exist_ok=True)


def on_frida_message(message, data):
    """Callback pour les messages Frida - sauvegarde automatique"""
    if message["type"] == "send":
        payload = message['payload']
        print(f"[FRIDA] {payload}")

        # Sauvegarder les données SSL dans un fichier JSONL
        if isinstance(payload, dict) and payload.get('type') == 'ssl_traffic':
            entry = {
                "ts": _dt.datetime.now().isoformat(),
                **payload,
            }
            with open(_CAPTURE_LOG, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            print(f"[+] Sauvegardé -> {_CAPTURE_LOG}")

            # Détection automatique des infos critiques
            text = payload.get('data', '')
            for key in ['manifestId', 'matchId', 'ticketId', 'secretKey', 'serverAddress']:
                if key in text:
                    print(f"\n{'!'*60}")
                    print(f"  JACKPOT! '{key}' trouvé dans le trafic SSL!")
                    print(f"  Direction: {payload.get('direction', '?')}")
                    print(f"  Taille: {payload.get('length', '?')} bytes")
                    print(f"{'!'*60}\n")

    elif message["type"] == "error":
        print(f"[FRIDA ERROR] {message['description']}")
    else:
        print(f"[FRIDA] {message}")


def inject_frida_attach(pid):
    """Mode ATTACH: injecte dans un processus existant"""
    print(f"\n[*] Mode ATTACH - Injection Frida dans PID {pid}...")

    with open(FRIDA_SCRIPT, "r", encoding="utf-8") as f:
        script_code = f.read()

    session = frida.attach(pid)
    script = session.create_script(script_code)
    script.on("message", on_frida_message)
    script.load()

    print("[+] Script Frida injecté avec succès!")
    return session, script


def inject_frida_spawn(exe_path):
    """Mode SPAWN: lance le jeu avec Frida déjà attaché (bypass anti-cheat)"""
    print(f"\n[*] Mode SPAWN - Lancement du jeu via Frida...")
    print(f"[*] Exe: {exe_path}")

    with open(FRIDA_SCRIPT, "r", encoding="utf-8") as f:
        script_code = f.read()

    device = frida.get_local_device()

    # Spawn le processus (suspendu)
    pid = device.spawn([exe_path])
    print(f"[+] Processus créé (PID: {pid}) - en pause")

    # Attacher et injecter AVANT que le processus ne démarre
    session = device.attach(pid)
    script = session.create_script(script_code)
    script.on("message", on_frida_message)
    script.load()
    print("[+] Script SSL bypass injecté AVANT démarrage du jeu")

    # Attendre que les hooks soient en place
    time.sleep(1)

    # Reprendre l'exécution du processus
    device.resume(pid)
    print(f"[+] Processus repris (PID: {pid}) - le jeu démarre avec les hooks SSL actifs")

    return session, script, pid


def start_mitmproxy():
    """Lance mitmproxy en mode local"""
    print(f"\n[*] Lancement de mitmdump sur le port {PROXY_PORT}...")

    venv_dir = os.path.dirname(sys.executable)
    mitmdump_exe = os.path.join(venv_dir, "mitmdump.exe")
    if not os.path.exists(mitmdump_exe):
        mitmdump_exe = "mitmdump"

    cmd = [
        mitmdump_exe,
        "--mode", "local",
        "-s", MITM_SCRIPT,
        "--set", "connection_strategy=lazy",
        "--ssl-insecure",
    ]

    print(f"[*] Commande: {' '.join(cmd)}")
    return subprocess.Popen(cmd)


def main():
    global FRIDA_SCRIPT
    print("""
╔═══════════════════════════════════════════════════════════════╗
║     ARC RAIDERS API INTERCEPTOR (Frida + mitmproxy)         ║
║                                                               ║
║     Bypass Certificate Pinning + Interception HTTPS          ║
║     Capture: secretKey, squad layout, match info             ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    # 0. Vérifier les droits admin
    if not is_admin():
        print("[!] Ce script nécessite les droits administrateur pour Frida")
        print("[*] Relancement en tant qu'administrateur...")
        elevate_to_admin()
        return

    print("[+] Droits administrateur: OK")

    # 1. Choisir le mode
    print("\n[?] Choisis le mode d'injection:")
    print("    1. ATTACH - Le jeu est déjà lancé (bypass SSL)")
    print("    2. SPAWN  - Lance le jeu via Frida (bypass SSL)")
    print("    3. MITM   - Mitmproxy seul (sans Frida)")
    print("    4. DUMP   - SSL traffic dump ATTACH (hooker SSL_write/SSL_read)")
    print("    5. SPAWN+DUMP - Lance le jeu + dump SSL (contourne EAC)")
    print()

    choice = input("[?] Choix (1/2/3/4/5) [défaut: 5]: ").strip() or "5"

    session = None
    script = None

    if choice == "2":
        # === MODE SPAWN ===
        exe_path = find_game_exe()
        if not exe_path:
            print("[!] Exécutable Arc Raiders non trouvé automatiquement")
            exe_path = input("[?] Chemin complet vers l'exe du jeu: ").strip().strip('"')
            if not os.path.exists(exe_path):
                print("[!] Fichier introuvable")
                return

        try:
            session, script, pid = inject_frida_spawn(exe_path)
            print(f"[+] Jeu lancé avec bypass SSL (PID: {pid})")
        except Exception as e:
            print(f"[!] Erreur spawn: {e}")
            print("[*] Essaie le mode ATTACH ou vérifie le chemin du jeu")
            return

    elif choice == "1":
        # === MODE ATTACH ===
        pid, name = find_game_pid()
        if not pid:
            print("[!] Arc Raiders non trouvé!")
            print("[!] Lance le jeu d'abord, puis relance ce script.")

            print("\n[*] Processus actifs contenant 'arc' ou 'raid' ou 'embark':")
            try:
                device = frida.get_local_device()
                for proc in device.enumerate_processes():
                    n = proc.name.lower()
                    if "arc" in n or "raid" in n or "embark" in n or "pio" in n or "pioneer" in n:
                        print(f"    {proc.name} (PID: {proc.pid})")
            except:
                pass

            print("\n[?] Entre le PID manuellement (ou 'q' pour quitter): ", end="")
            user_input = input().strip()
            if user_input.lower() == 'q':
                return
            try:
                pid = int(user_input)
                name = "manual"
            except ValueError:
                print("[!] PID invalide")
                return

        try:
            session, script = inject_frida_attach(pid)
        except frida.ProcessNotFoundError:
            print(f"[!] Processus PID {pid} non trouvé")
            return
        except frida.PermissionDeniedError:
            print("[!] Permission refusée même en admin!")
            print("[*] L'anti-cheat bloque probablement l'injection")
            print("[*] Essaie le mode SPAWN (option 2) pour injecter AVANT l'anti-cheat")
            return
        except Exception as e:
            if "VirtualAllocEx" in str(e) or "0x00000005" in str(e):
                print(f"[!] ACCESS_DENIED: L'anti-cheat protège le processus")
                print("[*] Solutions:")
                print("    1. Utilise le mode SPAWN (option 2) pour injecter avant l'anti-cheat")
                print("    2. Désactive temporairement l'anti-cheat (EAC/BattlEye)")
                print("[*] Continuation avec mitmproxy seul...")
            else:
                print(f"[!] Erreur injection Frida: {e}")
                print("[*] Continuation sans Frida (mitmproxy seul)...")

    elif choice == "3":
        print("[*] Mode mitmproxy seul (pas de bypass SSL)")
    elif choice == "4":
        # === MODE DUMP SSL ===
        FRIDA_SCRIPT = FRIDA_SCRIPT_SSL_DUMP
        print("[*] Mode SSL DUMP - capture du trafic déchiffré via Frida hooks")
        print("[*] PAS BESOIN de mitmproxy - Frida lit directement le plaintext")

        pid, name = find_game_pid()
        if not pid:
            print("[!] Arc Raiders non trouvé! Lance le jeu d'abord.")
            print("[?] Entre le PID manuellement (ou 'q' pour quitter): ", end="")
            user_input = input().strip()
            if user_input.lower() == 'q':
                return
            try:
                pid = int(user_input)
            except ValueError:
                print("[!] PID invalide")
                return

        try:
            session, script = inject_frida_attach(pid)
            print(f"[+] SSL dump hooks injectés dans PID {pid}")
            print("[*] Queue pour un match - le trafic sera capturé ici")
            print("[*] Ctrl+C pour arrêter\n")

            # Boucle d'attente simple
            import signal
            signal.signal(signal.SIGINT, lambda s, f: None)
            try:
                while True:
                    time.sleep(1)
            except (KeyboardInterrupt, EOFError):
                pass
        except Exception as e:
            print(f"[!] Erreur: {e}")
        finally:
            if session:
                try:
                    session.detach()
                except:
                    pass
            print("[*] Terminé.")
        return
    elif choice == "5":
        # === MODE SPAWN + DUMP SSL ===
        FRIDA_SCRIPT = FRIDA_SCRIPT_SSL_DUMP
        print("[*] Mode SPAWN+DUMP - Lance le jeu via Frida + hooks SSL_write/SSL_read")
        print("[*] Contourne EAC en injectant AVANT le lancement")
        print("[*] PAS BESOIN de mitmproxy - Frida lit directement le plaintext\n")

        exe_path = find_game_exe()
        if not exe_path:
            print("[!] Exécutable Arc Raiders non trouvé automatiquement")
            exe_path = input("[?] Chemin complet vers l'exe du jeu: ").strip().strip('"')
            if not os.path.exists(exe_path):
                print("[!] Fichier introuvable")
                return

        try:
            session, script, pid = inject_frida_spawn(exe_path)
            print(f"[+] Jeu lancé avec hooks SSL dump (PID: {pid})")
            print("[*] Attends le chargement du jeu (~30s)...")
            print("[*] Queue pour un match - le trafic sera capturé ici")
            print("[*] Cherche: manifestId, matchId, ticketId, secretKey")
            print("[*] Ctrl+C pour arrêter\n")

            # Boucle d'attente simple
            import signal
            signal.signal(signal.SIGINT, lambda s, f: None)
            try:
                while True:
                    time.sleep(1)
            except (KeyboardInterrupt, EOFError):
                pass
        except Exception as e:
            print(f"[!] Erreur spawn: {e}")
            print("[*] Essaie le mode ATTACH (option 4) ou vérifie le chemin du jeu")
        finally:
            if session:
                try:
                    session.detach()
                except:
                    pass
            print("[*] Terminé.")
        return
    else:
        print("[!] Choix invalide")
        return

    # Attendre que les hooks s'installent
    if session:
        time.sleep(2)

    # Lancer mitmproxy
    mitm_proc = None
    try:
        mitm_proc = start_mitmproxy()
        print("\n[+] Tout est en place!")
        if session:
            print("[*] Le jeu devrait maintenant accepter le certificat mitmproxy")
        else:
            print("[!] Sans Frida, le cert pinning bloquera probablement les connexions")
        print("[*] Ctrl+C pour arrêter\n")

        mitm_proc.wait()

    except KeyboardInterrupt:
        print("\n[*] Arrêt...")
    finally:
        if mitm_proc:
            mitm_proc.terminate()
        if session:
            try:
                session.detach()
            except:
                pass
        print("[*] Terminé.")


if __name__ == "__main__":
    main()
