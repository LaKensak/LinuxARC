"""
Diagnostic CommDriver — vérifie si le shared memory existe
et si le driver est actif.
"""
import ctypes
import ctypes.wintypes as wt
import time

kernel32 = ctypes.windll.kernel32
kernel32.OpenFileMappingW.restype = ctypes.c_void_p
kernel32.OpenFileMappingW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

FILE_MAP_READ = 0x0004

print("=" * 50)
print("  DIAGNOSTIC COMMDRIVER")
print("=" * 50)
print()

# Test 1: shared memory names to try
names = [
    "Global\\ArcComm",
    "Local\\ArcComm",
    "ArcComm",
]

for name in names:
    h = kernel32.OpenFileMappingW(FILE_MAP_READ, False, name)
    err = kernel32.GetLastError() if not h else 0
    if h:
        print(f"[+] '{name}' => TROUVE (handle={h:#x})")
        kernel32.CloseHandle(h)
    else:
        print(f"[-] '{name}' => introuvable (erreur {err})")

print()

# Test 2: check if we can see kernel debug output via OutputDebugString
# (won't work without DebugView, but shows intent)
print("[*] Vérification des drivers chargés...")
try:
    import subprocess
    # Check if acpiex.sys is loaded (it should be)
    result = subprocess.run(
        ["driverquery", "/v", "/fo", "csv"],
        capture_output=True, text=True, timeout=10
    )
    drivers = result.stdout.lower()

    if "acpiex" in drivers:
        print("[+] acpiex.sys est chargé (normal)")
    else:
        print("[!] acpiex.sys non trouvé dans la liste des drivers")

    # Count boot-start drivers
    lines = result.stdout.strip().split('\n')
    print(f"[*] {len(lines)-1} drivers chargés au total")
except Exception as e:
    print(f"[!] driverquery erreur: {e}")

print()

# Test 3: wait and retry (in case the driver is still initializing)
print("[*] Tentative de connexion avec retry (30 sec max)...")
for i in range(30):
    h = kernel32.OpenFileMappingW(FILE_MAP_READ, False, "Global\\ArcComm")
    if h:
        print(f"[+] Shared memory trouvé après {i+1} secondes!")
        kernel32.CloseHandle(h)
        break
    time.sleep(1)
    if i % 5 == 4:
        print(f"    ...{i+1}s écoulées, toujours rien")
else:
    err = kernel32.GetLastError()
    print(f"[-] Shared memory introuvable après 30 secondes (erreur {err})")
    print()
    print("DIAGNOSTIC:")
    print("  Le driver CommDriver n'est probablement pas chargé en mémoire.")
    print("  Causes possibles:")
    print("  1. L'EFI loader n'a pas trouvé les signatures (version Windows non supportée)")
    print("  2. Le mapping du driver a échoué (taille CommDriver > taille acpiex.sys)")
    print("  3. La résolution des imports a échoué")
    print("  4. Le driver a crashé au démarrage (BSOD évité car boot-start)")
    print()
    print("  => Regarde les messages sur l'écran UEFI au boot")
    print("  => Ou lance DebugView (Sysinternals) en admin avec 'Capture Kernel' activé")

print()
print("Done.")
