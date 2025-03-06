import psutil
from logging_utils import protokolliere_ereignis_global

class NetzwerkManager:
    """
    Verwaltet Netzwerk-bezogene Operationen.
    Modul für Netzwerküberwachung (erweitert).
    """
    def __init__(self):
        pass  # Keine Initialisierung aktuell

    def überwache_netzwerk_verbindungen(self):
        """Überwacht aktive Netzwerkverbindungen (rudimentär)."""
        protokolliere_ereignis_global("info", "Überprüfe Netzwerkverbindungen...")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                prozess_obj = psutil.Process(proc.info['pid'])  # Prozess Objekt holen um net_connections() aufzurufen
                prozess_name = proc.info['name'].lower()
                for verbindung in prozess_obj.net_connections():  # Korrekte Verwendung von net_connections()
                    if verbindung.status in ["ESTABLISHED", "LISTEN"]:
                        remote_port = verbindung.raddr.port if verbindung.raddr else 'N/A'
                        protokolliere_ereignis_global("debug",
                                                      f"Aktive Netzwerkverbindung: Prozess: {prozess_name} (PID: {proc.info['pid']}), "
                                                      f"Lokaler Port: {verbindung.laddr.port}, Remote Port: {remote_port}, Status: {verbindung.status}")
                        # TODO: Zukünftig: Hier detailliertere Analyse und KI-Anbindung
                        # Beispiel: Analyse von verbindung.raddr (Remote-Adresse) auf verdächtige IPs/Domains
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                protokolliere_ereignis_global("warnung",
                                              f"Fehler beim Zugriff auf Prozess-Netzwerkinformationen (NetzwerkManager): {e}",
                                              {"prozess_pid": proc.info.get('pid', 'Unbekannt'), "fehler": str(e)})
            except Exception as e:
                protokolliere_ereignis_global("fehler",
                                              f"Unerwarteter Fehler bei der Netzwerküberwachung (NetzwerkManager): {e}",
                                              {"fehler": str(e)})

    def protokolliere_ereignis(self, typ, meldung, daten=None):
        """Protokolliert ein Ereignis über das Logging-Modul."""
        protokolliere_ereignis_global(typ, meldung, daten)
