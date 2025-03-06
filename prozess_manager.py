import psutil
# Importiere die globale Protokollierungsfunktion aus logging_utils.py
from logging_utils import protokolliere_ereignis_global

class ProzessManager:
    """
    Verwaltet Prozess-bezogene Operationen.
    Modul für Prozess-Beendigung.
    """
    def beende_prozess(self, pid):
        """Beendet einen Prozess anhand seiner Prozess-ID (PID)."""
        try:
            prozess = psutil.Process(pid)
            prozess_name = prozess.name()
            prozess.terminate()
            self.protokolliere_ereignis("aktion", f"Prozess '{prozess_name}' (PID: {pid}) beendet.")
            return True
        except psutil.NoSuchProcess:
            self.protokolliere_ereignis("warnung", f"Prozess mit PID {pid} nicht gefunden. Möglicherweise bereits beendet.", {"pid": pid})
            return False
        except psutil.AccessDenied:
            self.protokolliere_ereignis("warnung", f"Zugriff verweigert beim Beenden von Prozess mit PID {pid}. Virenschutz benötigt möglicherweise höhere Berechtigungen.", {"pid": pid})
            return False
        except Exception as e:
            self.protokolliere_ereignis("fehler", f"Fehler beim Beenden von Prozess mit PID {pid}: {e}", {"fehler": str(e), "pid": pid})
            return False

    def protokolliere_ereignis(self, typ, meldung, daten=None):
        """Protokolliert ein Ereignis über das Logging-Modul."""
        protokolliere_ereignis_global(typ, meldung, daten)
