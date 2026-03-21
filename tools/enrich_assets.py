"""
Enrichit le mapping asset_ids.json en croisant l'inventaire API avec les IDs connus.
Extrait les gameAssetIds inconnus et tente de les identifier via le binaire du jeu.
"""

import json
import os
import struct
import re

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
ASSET_FILE = os.path.join(DATA_DIR, 'signatures', 'asset_ids.json')
INVENTORY_FILE = os.path.join(DATA_DIR, 'api_dump', 'v1_pioneer_inventory.json')
GAME_EXE = r"F:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame.exe"
GAME_DIR = r"F:\SteamLibrary\steamapps\common\Arc Raiders"


def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def analyze_inventory():
    """Analyse l'inventaire et identifie les IDs inconnus"""
    assets = load_json(ASSET_FILE)
    inventory = load_json(INVENTORY_FILE)

    known_ids = {int(k) for k in assets['by_id'].keys()}
    items = inventory['items']

    # Compter les gameAssetIds
    id_counts = {}
    for item in items:
        gid = item['gameAssetId']
        id_counts[gid] = id_counts.get(gid, 0) + 1

    # Séparer connus / inconnus
    known = {}
    unknown = {}
    for gid, count in sorted(id_counts.items(), key=lambda x: -x[1]):
        if gid in known_ids:
            name = assets['by_id'][str(gid)]
            known[gid] = {'name': name, 'count': count}
        else:
            unknown[gid] = count

    print(f"[*] Inventaire: {len(items)} items, {len(id_counts)} IDs uniques")
    print(f"[+] IDs connus: {len(known)} ({sum(v['count'] for v in known.values())} items)")
    print(f"[!] IDs inconnus: {len(unknown)} ({sum(unknown.values())} items)")

    # Afficher les IDs inconnus les plus fréquents
    print(f"\n--- Top 30 IDs inconnus ---")
    for gid, count in sorted(unknown.items(), key=lambda x: -x[1])[:30]:
        # Convertir en unsigned pour chercher dans le binaire
        uid = gid if gid >= 0 else gid + 2**32
        print(f"  {gid:>12d}  (0x{uid:08X})  x{count}")

    # Analyser les patterns dans les items inconnus
    print(f"\n--- Analyse des items inconnus ---")
    # Les items avec slots sont probablement des armes/équipements
    items_with_slots = [i for i in items if i.get('slots') and i['gameAssetId'] in unknown]
    items_damageable = [i for i in items if i.get('durability', 1) < 1 and i['gameAssetId'] in unknown]
    items_stackable = [i for i in items if i.get('amount', 1) > 1 and i['gameAssetId'] in unknown]

    print(f"  Items inconnus avec slots (armes/équipement): {len(items_with_slots)}")
    print(f"  Items inconnus endommagés (durability<1): {len(items_damageable)}")
    print(f"  Items inconnus stackables (amount>1): {len(items_stackable)}")

    # Top IDs inconnus avec beaucoup de slots = probablement des armes
    slot_counts = {}
    for item in items:
        gid = item['gameAssetId']
        if gid in unknown and item.get('slots'):
            slot_counts.setdefault(gid, set()).add(len(item['slots']))

    if slot_counts:
        print(f"\n--- IDs inconnus avec slots (armes probables) ---")
        for gid, slots in sorted(slot_counts.items(), key=lambda x: -max(x[1])):
            uid = gid if gid >= 0 else gid + 2**32
            print(f"  {gid:>12d}  slots: {sorted(slots)}  x{unknown[gid]}")

    return known, unknown


def scan_binary_for_names(unknown_ids):
    """Scanne le binaire du jeu pour trouver des strings proches des IDs"""
    if not os.path.exists(GAME_EXE):
        print(f"\n[!] Binaire non trouvé: {GAME_EXE}")
        return {}

    print(f"\n[*] Scan du binaire {GAME_EXE} pour les strings DA_Item_*...")

    found = {}
    try:
        with open(GAME_EXE, 'rb') as f:
            data = f.read()

        # Chercher toutes les strings "DA_Item_" dans le binaire
        pattern = b'DA_Item_'
        pos = 0
        da_items = []
        while True:
            idx = data.find(pattern, pos)
            if idx == -1:
                break
            # Extraire la string complète (jusqu'au null byte ou char non-ASCII)
            end = idx
            while end < len(data) and data[end] >= 0x20 and data[end] < 0x7F:
                end += 1
            name = data[idx:end].decode('ascii', errors='ignore')
            if len(name) > 8 and len(name) < 200:
                da_items.append(name)
            pos = idx + 1

        # Deduplicate
        da_items = sorted(set(da_items))

        print(f"[+] Trouvé {len(da_items)} strings DA_Item_* dans le binaire")

        # Afficher les nouvelles strings pas dans asset_ids.json
        existing_names = set()
        asset_data = load_json(ASSET_FILE)
        existing_names = set(asset_data['by_name'].keys())

        new_names = [n for n in da_items if n not in existing_names]
        print(f"[+] {len(new_names)} nouvelles strings DA_Item_* non mappées:")
        for name in new_names[:50]:
            print(f"    {name}")
        if len(new_names) > 50:
            print(f"    ... et {len(new_names) - 50} de plus")

        # Sauvegarder toutes les strings trouvées
        strings_file = os.path.join(DATA_DIR, 'signatures', 'binary_strings.json')
        save_json(strings_file, {
            'da_items_all': da_items,
            'da_items_new': new_names,
            'count_total': len(da_items),
            'count_new': len(new_names),
        })
        print(f"[+] Strings sauvegardées -> {strings_file}")

        return {n: None for n in new_names}

    except Exception as e:
        print(f"[!] Erreur scan binaire: {e}")
        return {}


def scan_pak_strings():
    """Cherche des strings dans les fichiers .utoc (table of contents)"""
    paks_dir = os.path.join(GAME_DIR, "PioneerGame", "Content", "Paks")
    if not os.path.exists(paks_dir):
        print(f"[!] Pas de dossier Paks: {paks_dir}")
        return []

    print(f"\n[*] Scan des fichiers .utoc pour les strings DA_Item_*...")
    all_names = set()

    for fname in os.listdir(paks_dir):
        if not fname.endswith('.utoc'):
            continue

        fpath = os.path.join(paks_dir, fname)
        fsize = os.path.getsize(fpath)
        if fsize < 1000:
            continue

        try:
            with open(fpath, 'rb') as f:
                data = f.read()

            # Chercher DA_Item_
            pos = 0
            while True:
                idx = data.find(b'DA_Item_', pos)
                if idx == -1:
                    break
                end = idx
                while end < len(data) and data[end] >= 0x20 and data[end] < 0x7F:
                    end += 1
                name = data[idx:end].decode('ascii', errors='ignore')
                if 8 < len(name) < 200:
                    all_names.add(name)
                pos = idx + 1

            # Aussi chercher les paths avec Item
            pos = 0
            while True:
                idx = data.find(b'/Game/', pos)
                if idx == -1:
                    break
                end = idx
                while end < len(data) and data[end] >= 0x20 and data[end] < 0x7F:
                    end += 1
                path = data[idx:end].decode('ascii', errors='ignore')
                if 'Item' in path and len(path) < 300:
                    all_names.add(path)
                pos = idx + 1
        except:
            continue

    names = sorted(all_names)
    print(f"[+] Trouvé {len(names)} strings DA_Item_* / Item paths dans .utoc")
    for n in names[:30]:
        print(f"    {n}")
    if len(names) > 30:
        print(f"    ... et {len(names) - 30} de plus")

    return names


def main():
    print("=" * 60)
    print("  ARC RAIDERS ASSET ID ENRICHMENT")
    print("=" * 60 + "\n")

    # 1. Analyser l'inventaire
    known, unknown = analyze_inventory()

    # 2. Scanner le binaire pour les strings
    new_from_binary = scan_binary_for_names(unknown)

    # 3. Scanner les .utoc
    pak_names = scan_pak_strings()

    # 4. Résumé
    print(f"\n{'='*60}")
    print(f"  RÉSUMÉ")
    print(f"{'='*60}")
    print(f"  IDs connus dans l'inventaire: {len(known)}")
    print(f"  IDs inconnus dans l'inventaire: {len(unknown)}")
    print(f"  Nouvelles strings DA_Item_ trouvées: {len(new_from_binary)}")
    print(f"  Strings dans .utoc: {len(pak_names)}")
    print(f"\n  Pour mapper les IDs inconnus aux noms, il faudrait:")
    print(f"  1. Extraire les .pak/.ucas avec FModel ou UEAssetToolkit")
    print(f"  2. Ou capturer le jeu chargeant les assets (noms dans les logs UE)")
    print(f"  3. Ou utiliser un SDK dumper en jeu (Unreal Header Tool)")


if __name__ == "__main__":
    main()
