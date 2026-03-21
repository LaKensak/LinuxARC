#!/usr/bin/env python3
"""
Script d'installation automatique
"""

import subprocess
import sys
import os
import platform

# Fix encoding pour Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')


def install_npcap():
    """Installe Npcap si nécessaire"""
    system = platform.system()
    if system == "Windows":
        print("[*] Vérification de Npcap...")
        try:
            import pcap
            print("[✓] Npcap déjà installé")
        except ImportError:
            print("[!] Npcap requis. Téléchargement...")
            # Télécharger et installer Npcap
            print("    Télécharge depuis: https://npcap.com")
            print("    Coche 'Install Npcap in WinPcap API-compatible Mode'")
            input("    Appuie sur Entrée après installation...")


def install_python_deps():
    """Installe les dépendances Python"""
    print("[*] Installation des dépendances Python...")

    deps = [
        'scapy',
        'numpy',
        'pygame',
        'psutil',
        'pymem',
        'cryptography',
        'colorama',
        'keyboard',
        'Pillow'
    ]

    for dep in deps:
        print(f"  - {dep}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", dep])


def create_directories():
    """Crée les dossiers nécessaires"""
    dirs = [
        'data/config',
        'data/signatures',
        'data/logs',
        'tests/mock_data',
        'tools',
        'overlay/fonts'
    ]

    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"[✓] Dossier créé: {d}")


def create_default_configs():
    """Crée les fichiers de configuration par défaut"""

    # settings.json
    settings = {
        "network": {"ports": [5055, 5056, 4535], "buffer_size": 65536},
        "overlay": {"width": 1024, "height": 768, "zoom": 1.0},
        "threat": {"danger_distance": 40, "critical_health": 30}
    }

    with open('data/config/settings.json', 'w') as f:
        import json
        json.dump(settings, f, indent=2)

    # packet_signatures.json (vide pour commencer)
    with open('data/signatures/packet_signatures.json', 'w') as f:
        json.dump({}, f, indent=2)

    print("[✓] Fichiers de configuration créés")


def main():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║     ARC RAIDERS NETWORK SNIFFER - INSTALLATION               ║
║                                                               ║
║     Ce script va installer toutes les dépendances            ║
║     nécessaires pour faire fonctionner le sniffer.           ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    # 1. Npcap
    install_npcap()

    # 2. Dépendances Python
    install_python_deps()

    # 3. Dossiers
    create_directories()

    # 4. Configurations
    create_default_configs()

    print("""
╔═══════════════════════════════════════════════════════════════╗
║     INSTALLATION TERMINÉE                                    ║
║                                                               ║
║     Pour lancer le sniffer:                                  ║
║     python main.py                                           ║
║                                                               ║
║     IMPORTANT: Lance en administrateur !                     ║
╚═══════════════════════════════════════════════════════════════╝
    """)


if __name__ == "__main__":
    main()