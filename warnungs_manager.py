# --- Inhalt von: warnungs_manager.py ---
import tkinter as tk
from tkinter import messagebox

# Importiere die globale Protokollierungsfunktion aus logging_utils.py
from logging_utils import protokolliere_ereignis_global

class WarnungsManager:
    """
    Verwaltet Warnmeldungen und Benutzerinteraktion.
    Modul für Anzeige von Warnungen und Auslösen von Aktionen.
    """
    def zeige_warnung(self, meldung, aktion=None, **aktions_parameter):
        """Zeigt eine Warnmeldung an und führt optional eine automatisierte Aktion aus."""
        protokolliere_ereignis_global("warnung", meldung)
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning("Virenschutz Warnung", meldung)
        root.destroy()

        if aktion == "prozess_beenden":
            pid = aktions_parameter.get("pid")
            if pid:
                # Annahme: prozess_manager ist im globalen Scope oder wird übergeben
                from main import prozess_manager # Import hier, um zirkuläre Abhängigkeit zu vermeiden
                if globals().get('prozess_manager') and globals()['prozess_manager'].beende_prozess(pid): # Zugriff über globals()
                    protokolliere_ereignis_global("aktion", f"Prozess mit PID {pid} beendet aufgrund Warnung: {meldung}")
                else:
                    protokolliere_ereignis_global("fehler", f"Fehler beim Beenden von Prozess mit PID {pid} trotz Warnung: {meldung}")
        elif aktion == "datei_quarantaene":
            datei_pfad = aktions_parameter.get("datei_pfad")
            if datei_pfad:
                 # Annahme: quarantäne_manager ist im globalen Scope oder wird übergeben
                from main import quarantaene_manager # Import hier, um zirkuläre Abhängigkeit zu vermeiden
                if globals().get('quarantaene_manager') and globals()['quarantaene_manager'].quarantäne_datei(datei_pfad): # Zugriff über globals()
                    protokolliere_ereignis_global("aktion", f"Datei '{datei_pfad}' in Quarantäne verschoben aufgrund Warnung: {meldung}")
                else:
                    protokolliere_ereignis_global("fehler", f"Fehler beim Verschieben der Datei '{datei_pfad}' in Quarantäne trotz Warnung: {meldung}")
        elif aktion == "blockchain_reputation_prüfen": # Beispiel für Blockchain Aktion
            datei_hash = aktions_parameter.get("datei_hash")
            if datei_hash:
                from main import blockchain_manager # Import um Zirkelbezug zu vermeiden
                blockchain_manager_instance = globals().get('blockchain_manager') # Zugriff auf globale Instanz
                if blockchain_manager_instance:
                    reputation = blockchain_manager_instance.pruefe_datei_reputation_blockchain(datei_hash) # Zugriff auf globale Instanz
                    protokolliere_ereignis_global("info", f"Blockchain Reputation für Hash '{datei_hash}': {reputation}")
                    messagebox.showinfo("Blockchain Reputation", f"Datei Reputation (Blockchain): {reputation}")
                else:
                    protokolliere_ereignis_global("warnung", "Blockchain Manager Instanz nicht gefunden für Reputationsprüfung.")

        # TODO: Erweiterung für weitere Aktionen (zukünftig)
        else:
            protokolliere_ereignis_global("warnung", f"Warnung angezeigt: {meldung}. Keine automatisierte Aktion konfiguriert.")
