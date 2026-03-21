"""
Lance mitmproxy pour intercepter l'API Arc Raiders
Configure automatiquement le proxy Windows
"""

import subprocess
import sys
import os
import ctypes
import winreg

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def set_windows_proxy(enable, host="127.0.0.1", port=8080):
    """Active/désactive le proxy Windows"""
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_SET_VALUE
    )
    if enable:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
        # Bypass pour le trafic local
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.0.0.1;<local>")
        print(f"[+] Proxy Windows activé: {host}:{port}")
    else:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        print("[+] Proxy Windows désactivé")
    winreg.CloseKey(key)


def main():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║     ARC RAIDERS API INTERCEPTOR (mitmproxy)                  ║
║                                                               ║
║     Intercepte les appels HTTPS vers l'API Embark            ║
║     pour capturer: secretKey, squad layout, match info       ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    # 1. Activer le proxy Windows
    print("[*] Configuration du proxy Windows...")
    try:
        set_windows_proxy(True, PROXY_HOST, PROXY_PORT)
    except Exception as e:
        print(f"[!] Erreur proxy: {e}")
        print("    Configure manuellement: Paramètres > Réseau > Proxy")
        print(f"    Adresse: {PROXY_HOST}, Port: {PROXY_PORT}")

    # 2. Installer le certificat mitmproxy (première fois)
    cert_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")
    if not os.path.exists(cert_path):
        print("[*] Premier lancement - le certificat sera généré automatiquement")
        print("    Tu devras l'installer: double-clic sur le .cer -> Installer")

    # 3. Lancer mitmdump avec le script
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools', 'mitm_arc.py')

    print(f"\n[*] Lancement de mitmdump sur le port {PROXY_PORT}...")
    print("[*] Lance Arc Raiders maintenant!")
    print("[*] Ctrl+C pour arrêter\n")

    try:
        # Utiliser l'exécutable mitmdump directement
        venv_dir = os.path.dirname(sys.executable)
        mitmdump_exe = os.path.join(venv_dir, "mitmdump.exe")
        if not os.path.exists(mitmdump_exe):
            mitmdump_exe = "mitmdump"

        # Mode local (transparent) redirige tout le trafic de la machine
        subprocess.run([
            mitmdump_exe,
            "--mode", "local",
            "-s", script,
            "--set", "connection_strategy=lazy",
        ])
    except KeyboardInterrupt:
        print("\n[*] Arrêt...")
    finally:
        # Désactiver le proxy
        try:
            set_windows_proxy(False)
        except:
            print("[!] N'oublie pas de désactiver le proxy Windows!")

        print("[*] Terminé. Vérifie data/logs/ pour les captures.")


if __name__ == "__main__":
    main()
