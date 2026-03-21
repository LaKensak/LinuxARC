"""
Système de logging avancé pour le sniffer ARC Raiders
- Rotation automatique des fichiers
- Buffer en mémoire pour réduire l'écriture disque
- Mode silencieux optionnel
- Niveaux de log configurables
- Compression des logs anciens
"""

import os
import sys
import time
import json
import threading
import queue
import gzip
import shutil
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum
import traceback

# Tentative d'import des couleurs (optionnel)
try:
    from colorama import init, Fore, Back, Style

    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False


    # Définir des valeurs factices
    class Fore:
        RED = '';
        GREEN = '';
        YELLOW = '';
        BLUE = ''
        MAGENTA = '';
        CYAN = '';
        WHITE = ''


    class Back:
        RED = '';
        GREEN = '';
        YELLOW = ''


    class Style:
        RESET_ALL = '';
        BRIGHT = ''


class LogLevel(Enum):
    """Niveaux de log"""
    DEBUG = 0
    INFO = 1
    SUCCESS = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5

    def get_color(self) -> str:
        """Retourne la couleur associée au niveau"""
        colors = {
            LogLevel.DEBUG: Fore.CYAN,
            LogLevel.INFO: Fore.BLUE,
            LogLevel.SUCCESS: Fore.GREEN,
            LogLevel.WARNING: Fore.YELLOW,
            LogLevel.ERROR: Fore.RED,
            LogLevel.CRITICAL: Fore.RED + Back.RED
        }
        return colors.get(self, Fore.WHITE)

    def get_name(self) -> str:
        """Retourne le nom formaté"""
        names = {
            LogLevel.DEBUG: "[DEBUG]",
            LogLevel.INFO: "[INFO]",
            LogLevel.SUCCESS: "[SUCCESS]",
            LogLevel.WARNING: "[WARNING]",
            LogLevel.ERROR: "[ERROR]",
            LogLevel.CRITICAL: "[CRITICAL]"
        }
        return names.get(self, "[UNKNOWN]")


class MemoryBuffer:
    """Buffer mémoire pour logs (réduit l'écriture disque)"""

    def __init__(self, max_size: int = 1000):
        self.buffer = []
        self.max_size = max_size
        self.lock = threading.Lock()

    def add(self, entry: Dict):
        """Ajoute une entrée au buffer"""
        with self.lock:
            self.buffer.append(entry)
            if len(self.buffer) > self.max_size:
                self.buffer.pop(0)

    def get_all(self) -> list:
        """Récupère toutes les entrées"""
        with self.lock:
            return self.buffer.copy()

    def get_last(self, n: int = 10) -> list:
        """Récupère les n dernières entrées"""
        with self.lock:
            return self.buffer[-n:]

    def clear(self):
        """Vide le buffer"""
        with self.lock:
            self.buffer.clear()

    def size(self) -> int:
        """Taille du buffer"""
        with self.lock:
            return len(self.buffer)


class Logger:
    """
    Logger avancé avec support:
    - Fichiers de log rotatifs
    - Compression automatique
    - Buffer mémoire
    - Couleurs console
    - Thread-safe
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern pour éviter les logs dupliqués"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance

    def __init__(self,
                 name: str = "ARC_Sniffer",
                 log_dir: str = "data/logs",
                 level: LogLevel = LogLevel.INFO,
                 max_file_size_mb: int = 10,
                 max_files: int = 10,
                 console_output: bool = True,
                 file_output: bool = True,
                 memory_buffer_size: int = 500,
                 use_colors: bool = True,
                 quiet: bool = False):
        """
        Initialise le logger

        Args:
            name: Nom du logger
            log_dir: Dossier des logs
            level: Niveau de log minimum
            max_file_size_mb: Taille max d'un fichier (Mo)
            max_files: Nombre max de fichiers de log
            console_output: Afficher dans la console
            file_output: Écrire dans un fichier
            memory_buffer_size: Taille du buffer mémoire
            use_colors: Utiliser les couleurs dans la console
            quiet: Mode silencieux (pas de sortie console)
        """
        # Éviter la réinitialisation multiple
        if hasattr(self, '_initialized') and self._initialized:
            return

        self.name = name
        self.log_dir = Path(log_dir)
        self.level = level
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.max_files = max_files
        self.console_output = console_output and not quiet
        self.file_output = file_output
        self.use_colors = use_colors and COLORS_AVAILABLE
        self.quiet = quiet

        # Buffer mémoire
        self.memory_buffer = MemoryBuffer(memory_buffer_size)

        # Queue pour l'écriture asynchrone
        self.log_queue = queue.Queue(maxsize=1000)
        self.writer_thread = None
        self.running = True

        # Statistiques
        self.stats = {
            'total_logs': 0,
            'by_level': {lvl.value: 0 for lvl in LogLevel},
            'file_writes': 0,
            'errors': 0,
            'start_time': datetime.now()
        }

        # Créer le dossier des logs
        if self.file_output:
            self.log_dir.mkdir(parents=True, exist_ok=True)

        # Démarrer le thread d'écriture
        if self.file_output:
            self._start_writer_thread()

        self._initialized = True

        # Log de démarrage
        self.info(f"Logger initialisé - Dossier: {self.log_dir}")

    def _start_writer_thread(self):
        """Démarre le thread d'écriture asynchrone"""
        self.writer_thread = threading.Thread(
            target=self._writer_loop,
            name=f"LoggerWriter-{self.name}",
            daemon=True
        )
        self.writer_thread.start()

    def _writer_loop(self):
        """Boucle d'écriture asynchrone"""
        while self.running:
            try:
                # Attendre un log avec timeout pour pouvoir vérifier running
                entry = self.log_queue.get(timeout=1)

                if entry is None:  # Signal d'arrêt
                    break

                self._write_to_file(entry)
                self.log_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.stats['errors'] += 1
                # Éviter une boucle infinie en cas d'erreur
                time.sleep(0.1)

    def _get_log_file(self) -> Path:
        """Retourne le nom du fichier de log actuel"""
        date = datetime.now().strftime("%Y%m%d")
        return self.log_dir / f"{self.name}_{date}.log"

    def _rotate_file_if_needed(self, filepath: Path):
        """Vérifie si le fichier doit être rotaté"""
        if not filepath.exists():
            return

        if filepath.stat().st_size >= self.max_file_size:
            self._rotate_file(filepath)

    def _rotate_file(self, filepath: Path):
        """Fait tourner le fichier de log"""
        # Compresser l'ancien fichier
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        compressed_path = self.log_dir / f"{filepath.stem}_{timestamp}.log.gz"

        try:
            with open(filepath, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Supprimer le fichier original
            filepath.unlink()

            # Nettoyer les anciens fichiers
            self._cleanup_old_logs()

        except Exception as e:
            print(f"[!] Erreur rotation logs: {e}")

    def _cleanup_old_logs(self):
        """Supprime les anciens fichiers de log"""
        try:
            # Récupérer tous les fichiers de log
            log_files = list(self.log_dir.glob(f"{self.name}_*.log*"))

            # Trier par date de modification
            log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

            # Supprimer les fichiers excédentaires
            for old_file in log_files[self.max_files:]:
                old_file.unlink()

        except Exception as e:
            pass  # Ignorer les erreurs de nettoyage

    def _write_to_file(self, entry: Dict):
        """Écrit une entrée dans le fichier"""
        if not self.file_output:
            return

        try:
            filepath = self._get_log_file()
            self._rotate_file_if_needed(filepath)

            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(entry['formatted'] + '\n')

            self.stats['file_writes'] += 1

        except Exception as e:
            self.stats['errors'] += 1

    def _format_message(self, level: LogLevel, message: str,
                        source: str = None) -> str:
        """Formate un message de log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_str = f"[{source}] " if source else ""

        # Format console (avec couleurs)
        if self.console_output and self.use_colors:
            level_color = level.get_color()
            reset = Style.RESET_ALL
            console_msg = (f"{timestamp} {level_color}{level.get_name()}{reset} "
                           f"{source_str}{message}")
        else:
            console_msg = f"{timestamp} {level.get_name()} {source_str}{message}"

        # Format fichier (sans couleurs)
        file_msg = f"{timestamp} {level.get_name()} {source_str}{message}"

        return console_msg, file_msg

    def _log(self, level: LogLevel, message: str, source: str = None,
             extra: Dict = None):
        """Méthode interne de logging"""
        if level.value < self.level.value:
            return

        console_msg, file_msg = self._format_message(level, message, source)

        # Ajouter aux stats
        self.stats['total_logs'] += 1
        self.stats['by_level'][level.value] += 1

        # Ajouter au buffer mémoire
        entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level.value,
            'level_name': level.name,
            'message': message,
            'source': source,
            'extra': extra,
            'formatted': file_msg
        }
        self.memory_buffer.add(entry)

        # Afficher dans la console
        if self.console_output and not self.quiet:
            print(console_msg)
            sys.stdout.flush()

        # Envoyer à l'écriture asynchrone
        if self.file_output and self.running:
            try:
                self.log_queue.put_nowait(entry)
            except queue.Full:
                pass  # File pleine, on ignore

    # Méthodes publiques
    def debug(self, message: str, source: str = None, extra: Dict = None):
        """Log DEBUG"""
        self._log(LogLevel.DEBUG, message, source, extra)

    def info(self, message: str, source: str = None, extra: Dict = None):
        """Log INFO"""
        self._log(LogLevel.INFO, message, source, extra)

    def success(self, message: str, source: str = None, extra: Dict = None):
        """Log SUCCESS"""
        self._log(LogLevel.SUCCESS, message, source, extra)

    def warning(self, message: str, source: str = None, extra: Dict = None):
        """Log WARNING"""
        self._log(LogLevel.WARNING, message, source, extra)

    def error(self, message: str, source: str = None, extra: Dict = None):
        """Log ERROR"""
        self._log(LogLevel.ERROR, message, source, extra)

    def critical(self, message: str, source: str = None, extra: Dict = None):
        """Log CRITICAL"""
        self._log(LogLevel.CRITICAL, message, source, extra)

    def exception(self, message: str, source: str = None):
        """Log une exception avec traceback"""
        tb = traceback.format_exc()
        self.error(f"{message}\n{tb}", source)

    # Méthodes utilitaires
    def set_level(self, level: LogLevel):
        """Change le niveau de log"""
        self.level = level
        self.info(f"Niveau de log changé: {level.name}")

    def get_stats(self) -> Dict:
        """Retourne les statistiques du logger"""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()

        return {
            'total_logs': self.stats['total_logs'],
            'by_level': {
                LogLevel(lvl).name: count
                for lvl, count in self.stats['by_level'].items()
            },
            'file_writes': self.stats['file_writes'],
            'errors': self.stats['errors'],
            'buffer_size': self.memory_buffer.size(),
            'uptime_seconds': uptime,
            'queue_size': self.log_queue.qsize()
        }

    def get_recent_logs(self, n: int = 10) -> list:
        """Récupère les n derniers logs"""
        return self.memory_buffer.get_last(n)

    def export_logs(self, output_file: str = None):
        """Exporte les logs en JSON"""
        if not output_file:
            output_file = self.log_dir / f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        logs = self.memory_buffer.get_all()

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'export_time': datetime.now().isoformat(),
                'logger_name': self.name,
                'total_logs': len(logs),
                'logs': logs
            }, f, indent=2, ensure_ascii=False)

        self.info(f"Logs exportés vers {output_file}")
        return output_file

    def flush(self):
        """Attend que tous les logs soient écrits"""
        if self.file_output and self.running:
            self.log_queue.join()

    def close(self):
        """Ferme le logger"""
        self.running = False
        if self.file_output and self.writer_thread:
            self.log_queue.put(None)  # Signal d'arrêt
            self.writer_thread.join(timeout=5)

        self.info("Logger fermé")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# ============================================================
# Fonctions utilitaires pour une utilisation simple
# ============================================================

# Logger par défaut
_default_logger: Optional[Logger] = None


def get_logger(name: str = "ARC_Sniffer",
               level: LogLevel = LogLevel.INFO,
               quiet: bool = False) -> Logger:
    """
    Récupère ou crée un logger

    Args:
        name: Nom du logger
        level: Niveau de log
        quiet: Mode silencieux

    Returns:
        Instance du logger
    """
    global _default_logger
    if _default_logger is None or _default_logger.name != name:
        _default_logger = Logger(name=name, level=level, quiet=quiet)
    return _default_logger


# ============================================================
# Exemple d'utilisation
# ============================================================

if __name__ == "__main__":
    # Exemple d'utilisation
    logger = get_logger("TestLogger", level=LogLevel.DEBUG)

    print("\n=== Test du Logger ===\n")

    logger.debug("Message de debug")
    logger.info("Message d'information")
    logger.success("Action réussie")
    logger.warning("Attention! Quelque chose d'inhabituel")
    logger.error("Erreur rencontrée")

    try:
        raise ValueError("Exemple d'erreur")
    except Exception as e:
        logger.exception("Exception capturée")

    # Afficher les stats
    print("\n=== Statistiques ===")
    stats = logger.get_stats()
    print(f"Total logs: {stats['total_logs']}")
    print(f"Par niveau: {stats['by_level']}")

    # Récupérer les derniers logs
    print("\n=== Derniers logs ===")
    for log in logger.get_recent_logs(3):
        print(f"  {log['timestamp']} [{log['level_name']}] {log['message']}")

    # Fermer le logger
    logger.close()