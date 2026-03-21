#!/bin/bash
# ============================================
#  Arc Raiders Radar — Setup Linux (Ubuntu/Nobara)
#  Lance ce script après avoir installé Linux en dual-boot
#  Usage: sudo bash setup_linux.sh
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

# Vérifications
if [ "$EUID" -ne 0 ]; then
    err "Lance avec sudo: sudo bash setup_linux.sh"
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

echo -e "${CYAN}"
echo "============================================"
echo "  ARC RAIDERS RADAR — SETUP LINUX"
echo "============================================"
echo -e "${NC}"

# Détecter la distro
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    log "Distro détectée: $NAME"
else
    DISTRO="unknown"
    warn "Distro inconnue, on essaie quand même..."
fi

# ============================================
# ÉTAPE 1: Mise à jour système
# ============================================
info "Étape 1/6: Mise à jour système..."

case "$DISTRO" in
    ubuntu|debian|linuxmint|pop)
        dpkg --add-architecture i386
        apt update -y
        apt upgrade -y
        ;;
    fedora|nobara)
        dnf update -y
        ;;
    arch|manjaro|endeavouros)
        pacman -Syu --noconfirm
        ;;
    *)
        warn "Distro non reconnue — installe manuellement les paquets"
        ;;
esac

log "Système à jour"

# ============================================
# ÉTAPE 2: Drivers GPU
# ============================================
info "Étape 2/6: Drivers GPU..."

# Détecter le GPU
GPU_VENDOR="unknown"
if lspci | grep -qi nvidia; then
    GPU_VENDOR="nvidia"
elif lspci | grep -qi "amd\|radeon"; then
    GPU_VENDOR="amd"
elif lspci | grep -qi intel; then
    GPU_VENDOR="intel"
fi

log "GPU détecté: $GPU_VENDOR"

case "$DISTRO" in
    ubuntu|debian|pop)
        if [ "$GPU_VENDOR" = "nvidia" ]; then
            info "Installation drivers NVIDIA..."
            apt install -y nvidia-driver-550 nvidia-utils-550 2>/dev/null || \
            apt install -y nvidia-driver nvidia-utils 2>/dev/null || \
            warn "Installe les drivers NVIDIA manuellement via 'sudo ubuntu-drivers autoinstall'"
        elif [ "$GPU_VENDOR" = "amd" ]; then
            apt install -y mesa-vulkan-drivers mesa-vulkan-drivers:i386 libvulkan1 libvulkan1:i386
        fi
        # Vulkan + libs 32-bit dans tous les cas
        apt install -y libvulkan1 libvulkan1:i386 vulkan-tools mesa-vulkan-drivers 2>/dev/null || true
        ;;
    fedora|nobara)
        if [ "$GPU_VENDOR" = "nvidia" ]; then
            # Nobara a déjà les drivers NVIDIA en général
            dnf install -y akmod-nvidia xorg-x11-drv-nvidia-cuda 2>/dev/null || \
            warn "Installe les drivers NVIDIA via RPM Fusion"
        fi
        dnf install -y vulkan-loader vulkan-loader.i686 mesa-vulkan-drivers mesa-vulkan-drivers.i686 2>/dev/null || true
        ;;
    arch|manjaro)
        if [ "$GPU_VENDOR" = "nvidia" ]; then
            pacman -S --noconfirm nvidia nvidia-utils lib32-nvidia-utils
        elif [ "$GPU_VENDOR" = "amd" ]; then
            pacman -S --noconfirm mesa lib32-mesa vulkan-radeon lib32-vulkan-radeon
        fi
        pacman -S --noconfirm vulkan-icd-loader lib32-vulkan-icd-loader
        ;;
esac

log "Drivers GPU configurés"

# ============================================
# ÉTAPE 3: Steam + Proton
# ============================================
info "Étape 3/6: Installation Steam..."

case "$DISTRO" in
    ubuntu|debian|pop|linuxmint)
        # Dépendances Steam
        apt install -y wget gdebi-core
        if ! command -v steam &>/dev/null; then
            wget -O /tmp/steam.deb https://cdn.akamai.steamstatic.com/client/installer/steam.deb
            dpkg -i /tmp/steam.deb 2>/dev/null || apt install -f -y
            rm /tmp/steam.deb
        fi
        ;;
    fedora|nobara)
        dnf install -y steam 2>/dev/null || warn "Active RPM Fusion pour Steam"
        ;;
    arch|manjaro)
        # Activer multilib
        if ! grep -q "^\[multilib\]" /etc/pacman.conf; then
            echo -e "\n[multilib]\nInclude = /etc/pacman.d/mirrorlist" >> /etc/pacman.conf
            pacman -Sy
        fi
        pacman -S --noconfirm steam
        ;;
esac

log "Steam installé"

# ============================================
# ÉTAPE 4: Python + dépendances radar
# ============================================
info "Étape 4/6: Python + dépendances..."

case "$DISTRO" in
    ubuntu|debian|pop|linuxmint)
        apt install -y python3 python3-pip python3-venv
        ;;
    fedora|nobara)
        dnf install -y python3 python3-pip
        ;;
    arch|manjaro)
        pacman -S --noconfirm python python-pip
        ;;
esac

log "Python installé"

# ============================================
# ÉTAPE 5: Copier le radar
# ============================================
info "Étape 5/6: Configuration du radar..."

RADAR_DIR="$REAL_HOME/arc-radar"
mkdir -p "$RADAR_DIR"

# Si on est lancé depuis le dossier du projet, copier radar.py
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/radar.py" ]; then
    cp "$SCRIPT_DIR/radar.py" "$RADAR_DIR/radar.py"
    log "radar.py copié dans $RADAR_DIR"
else
    warn "radar.py non trouvé à côté de ce script"
    warn "Copie-le manuellement dans $RADAR_DIR"
fi

# Créer un lanceur rapide
cat > "$RADAR_DIR/run_radar.sh" << 'LAUNCHER'
#!/bin/bash
# Lanceur rapide pour le radar
cd "$(dirname "$0")"

if [ "$EUID" -ne 0 ]; then
    echo "[!] Root requis. Relance avec: sudo ./run_radar.sh"
    exit 1
fi

# Vérifier que le jeu tourne
if ! pgrep -f PioneerGame > /dev/null; then
    echo "[!] Arc Raiders n'est pas lancé!"
    echo "    Lance le jeu via Steam/Proton d'abord."
    exit 1
fi

echo "[+] Lancement du radar..."
echo "    Ouvre http://localhost:8888 dans ton navigateur"
echo ""
python3 radar.py "$@"
LAUNCHER
chmod +x "$RADAR_DIR/run_radar.sh"

chown -R "$REAL_USER:$REAL_USER" "$RADAR_DIR"

log "Radar configuré dans $RADAR_DIR"

# ============================================
# ÉTAPE 6: Config Proton
# ============================================
info "Étape 6/6: Notes de configuration Proton..."

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  INSTALLATION TERMINÉE${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "${GREEN}Étapes suivantes (manuellement):${NC}"
echo ""
echo "  1. Lance Steam en tant que $REAL_USER (pas root)"
echo "     $ steam"
echo ""
echo "  2. Dans Steam > Settings > Compatibility :"
echo "     - Coche 'Enable Steam Play for all other titles'"
echo "     - Choisis 'Proton Experimental' ou 'GE-Proton'"
echo ""
echo "  3. Installe Arc Raiders depuis ta bibliothèque Steam"
echo ""
echo "  4. Lance Arc Raiders, entre en match"
echo ""
echo "  5. Dans un autre terminal :"
echo "     $ cd $RADAR_DIR"
echo "     $ sudo ./run_radar.sh"
echo ""
echo "  6. Ouvre http://localhost:8888 dans ton navigateur"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  - EAC ne se lance PAS sous Proton = mémoire lisible"
echo "  - Le jeu peut avoir des problèmes anti-cheat côté serveur"
echo "    (kick si EAC heartbeat manque) — à tester"
echo "  - Les offsets datent du playtest 2 (v1.20.x)"
echo "    Si le jeu a été mis à jour, il faudra les mettre à jour"
echo ""
echo -e "${GREEN}GPU: $GPU_VENDOR | Distro: $DISTRO${NC}"
echo ""
