# --- Inhalt von: system_pruefung_manager.py ---
import psutil
import time
import os
import hashlib
import threading
from datetime import datetime
from typing import Union
from logging_utils import protokolliere_ereignis_global
from config_rules_quarantine import QuarantäneManager, RegelManager, KonfigurationManager # Importe, WarnungsManager entfernt
from warnungs_manager import WarnungsManager # Import WarnungsManager aus warnungs_manager.py
from prozess_manager import ProzessManager # Import ProzessManager
from netzwerk_manager import NetzwerkManager # Import NetzwerkManager
from ki_analyse_manager import KIAnalyseManager # Import KIAnalyseManager
from quanten_analyse_manager import QuantenAnalyseManager # Import QuantenAnalyseManager
from blockchain_manager import BlockchainManager # Import BlockchainManager
import stat # Für Dateiattribute

class SystemÜberprüfungsManager:
    """Verwaltet die Systemüberprüfung."""
    def __init__(self, konfig_manager, regel_manager, quarantaene_manager, prozess_manager, netzwerk_manager, warnungs_manager, ki_analyse_manager, quanten_analyse_manager, blockchain_manager):
        self.konfig_manager = konfig_manager
        self.regel_manager = regel_manager
        self.quarantaene_manager = quarantaene_manager # Korrekter Variablenname
        self.prozess_manager = prozess_manager
        self.netzwerk_manager = netzwerk_manager
        self.warnungs_manager = warnungs_manager
        self.ki_analyse_manager = ki_analyse_manager
        self.quanten_analyse_manager = quanten_analyse_manager
        self.blockchain_manager = blockchain_manager

        self.scan_verzeichnis = self.konfig_manager.get_konfiguration().get("systempruefung").get("scan_verzeichnis")
        self.dateiendungen_ignoriert = self.konfig_manager.get_konfiguration().get("systempruefung").get("dateiendungen_ignoriert")
        self.system_verzeichnisse_ignoriert = self.konfig_manager.get_konfiguration().get("systempruefung").get("system_verzeichnisse_ignoriert") # Hinzugefügt
        self.echtzeit_schutz_aktiv = self.konfig_manager.get_konfiguration().get("systempruefung").get("echtzeit_schutz", True)
        self.pruefungs_intervall_sekunden = self.konfig_manager.get_konfiguration().get("systempruefung").get("pruefungs_intervall_sekunden", 600)
        self.geplante_pruefung_thread = None
        self.echtzeit_schutz_thread = None
        self.letzte_pruefung_zeit = "Nie" # Letzte Prüfungszeit als String

        if self.echtzeit_schutz_aktiv:
            self.starte_echtzeit_schutz()

        # Virenschutz Version in Blockchain registrieren (beim Start)
        if self.blockchain_manager.blockchain_aktiviert and self.konfig_manager.get_konfiguration().get("blockchain").get("update_verifizierung_aktiviert"):
            virenschutz_version_hash = hashlib.sha256(self.konfig_manager.get_konfiguration().get("virenschutz").get("version").encode('utf-8')).hexdigest()
            self.blockchain_manager.registriere_virenschutz_version_blockchain(virenschutz_version_hash)
            protokolliere_ereignis_global("info", f"Virenschutz-Version in Blockchain registriert. Version-Hash: {virenschutz_version_hash}")

    @property
    def letzte_pruefung_zeit_str(self):
        """Gibt die letzte Prüfungszeit als String zurück."""
        return self.letzte_pruefung_zeit

    def starte_systempruefung(self, verzeichnis=None):
        """Startet eine vollständige Systemprüfung (manuell oder geplant)."""
        start_zeit = datetime.now()
        protokolliere_ereignis_global("info", "Systemprüfung gestartet.")
        if verzeichnis:
            protokolliere_ereignis_global("info", f"Systemprüfung gestartet, manuelles Verzeichnis: '{verzeichnis}'")
            scan_verzeichnisse = [verzeichnis]
        else:
            scan_verzeichnisse = self.scan_verzeichnis
        protokolliere_ereignis_global("info", f"Scan-Verzeichnisse: {scan_verzeichnisse}") # Debugging Scan-Verzeichnisse
        anzahl_dateien_geprueft = 0
        anzahl_bedrohungen_gefunden = 0

        # Threat Intelligence von Blockchain abrufen (vor der Prüfung, falls aktiviert)
        if self.blockchain_manager.blockchain_aktiviert and self.konfig_manager.get_konfiguration().get("blockchain").get("threat_intelligence_aktiviert"):
            threat_intelligence_daten = self.blockchain_manager.hole_threat_intelligence_blockchain()
            if threat_intelligence_daten and threat_intelligence_daten.indikatoren:
                protokolliere_ereignis_global("info", f"Threat Intelligence von Blockchain abgerufen. Anzahl Indikatoren: {len(threat_intelligence_daten.indikatoren)}")
                # TODO: Threat Intelligence Indikatoren in Regeln integrieren (zukünftig)
            else:
                protokolliere_ereignis_global("warnung", "Keine oder leere Threat Intelligence Daten von Blockchain erhalten.")

        for basis_verzeichnis in scan_verzeichnisse:
            protokolliere_ereignis_global("info", f"Prüfe Verzeichnis: '{basis_verzeichnis}'")
            for wurzel, verzeichnisse, dateien in os.walk(basis_verzeichnis):
                # Systemverzeichnisse ignorieren
                ignorieren = False
                for sys_dir in self.system_verzeichnisse_ignoriert:
                    if wurzel.lower().startswith(sys_dir.lower()):  # Case-insensitive Vergleich
                        protokolliere_ereignis_global("debug", f"Verzeichnis '{wurzel}' ignoriert (Systemverzeichnis).")
                        ignorieren = True
                        break
                if ignorieren:
                    verzeichnisse[:] = []  # Verhindert weiteren Abstieg in Unterverzeichnisse
                    continue  # Springe zum nächsten Basisverzeichnis

                for datei_name in dateien:
                    datei_pfad = os.path.join(wurzel, datei_name)

                    # Systemdateien ebenfalls ignorieren, falls sie direkt im Scan-Verzeichnis liegen und nicht schon durch Verzeichnis ausgeschlossen wurden
                    ignorieren_datei = False
                    for sys_dir in self.system_verzeichnisse_ignoriert:
                        if datei_pfad.lower().startswith(sys_dir.lower()):  # Case-insensitive Vergleich
                            protokolliere_ereignis_global("debug", f"Datei '{datei_pfad}' ignoriert (Systemdatei).")
                            ignorieren_datei = True
                            break
                    if ignorieren_datei:
                        continue

                    # Systemdateien explizit ausschließen (über Dateiattribute)
                    if os.stat(datei_pfad).st_file_attributes & stat.FILE_ATTRIBUTE_SYSTEM:
                        protokolliere_ereignis_global("debug", f"Datei '{datei_pfad}' ignoriert (Systemdatei-Attribut).")
                        continue

                    if any(datei_name.lower().endswith(endung) for endung in self.dateiendungen_ignoriert):
                        protokolliere_ereignis_global("debug", f"Datei '{datei_name}' ignoriert (Dateiendung).")
                        continue

                    # .sys Dateien explizit ausschließen
                    if datei_name.lower().endswith(".sys"):
                        protokolliere_ereignis_global("debug", f"Datei '{datei_name}' ignoriert (Dateiendung: .sys).")
                        continue

                    anzahl_dateien_geprueft += 1
                    protokolliere_ereignis_global("debug", f"Prüfe Datei: '{datei_pfad}'")
                    datei_hash = self._berechne_datei_hash(datei_pfad)
                    if datei_hash:  # Nur analysieren, wenn Hash erfolgreich berechnet wurde
                        ergebnis, regel_name = self._analysiere_datei(datei_pfad, datei_hash)

                        if ergebnis != "normal": # Debugging erkannte Ergebnisse
                            protokolliere_ereignis_global("debug", f"Datei '{datei_pfad}' - Ergebnis: {ergebnis}, Regel: {regel_name}")

                        if ergebnis == "bedrohung":
                            anzahl_bedrohungen_gefunden += 1
                            protokolliere_ereignis_global("warnung", f"Bedrohung erkannt in Datei '{datei_pfad}' durch Regel '{regel_name}'. Aktion: Quarantäne.", {"datei_pfad": datei_pfad, "regel_name": regel_name})
                            self.quarantaene_manager.quarantäne_datei(datei_pfad)  # Korrekter Methodenaufruf

        end_zeit = datetime.now()
        dauer = end_zeit - start_zeit
        self.letzte_pruefung_zeit = end_zeit.strftime("%Y-%m-%d %H:%M:%S")  # Zeit als String speichern
        protokolliere_ereignis_global("info", f"Systemprüfung abgeschlossen. Geprüfte Dateien: {anzahl_dateien_geprueft}, Bedrohungen gefunden: {anzahl_bedrohungen_gefunden}, Dauer: {dauer}.")
        from main import web_ui_manager # Import hier, um Zirkelbezug zu vermeiden, Zugriff auf globale Instanz
        web_ui_manager.anzahl_bedrohungen_session = anzahl_bedrohungen_gefunden # Für Web-UI aktualisieren
        return anzahl_dateien_geprueft, anzahl_bedrohungen_gefunden, dauer

    def plane_systempruefung(self):
        """Plant regelmäßige Systemprüfungen."""
        if self.geplante_pruefung_thread is None or not self.geplante_pruefung_thread.is_alive():
            protokolliere_ereignis_global("info", f"Geplante Systemprüfung wird gestartet. Intervall: {self.pruefungs_intervall_sekunden} Sekunden.")
            self.geplante_pruefung_thread = threading.Thread(target=self._geplante_pruefung_schleife, daemon=True)
            self.geplante_pruefung_thread.start()
        else:
            protokolliere_ereignis_global("warnung", "Geplante Systemprüfung läuft bereits.")

    def stoppe_geplante_pruefung(self):
        """Stoppt die geplante Systemprüfung."""
        if self.geplante_pruefung_thread and self.geplante_pruefung_thread.is_alive():
            protokolliere_ereignis_global("info", "Geplante Systemprüfung wird gestoppt.")
            self.geplante_pruefung_thread = None
        else:
            protokolliere_ereignis_global("warnung", "Keine geplante Systemprüfung läuft oder Thread-Objekt nicht vorhanden.")

    def starte_echtzeit_schutz(self):
        """Startet den Echtzeitschutz."""
        if self.echtzeit_schutz_thread is None or not self.echtzeit_schutz_thread.is_alive():
            protokolliere_ereignis_global("info", "Echtzeitschutz wird gestartet.")
            self.echtzeit_schutz_aktiv = True
            self.echtzeit_schutz_thread = threading.Thread(target=self._echtzeit_schutz_schleife, daemon=True)
            self.echtzeit_schutz_thread.start()
        else:
            protokolliere_ereignis_global("warnung", "Echtzeitschutz läuft bereits.")

    def stoppe_echtzeit_schutz(self):
        """Stoppt den Echtzeitschutz."""
        if self.echtzeit_schutz_thread and self.echtzeit_schutz_thread.is_alive():
            protokolliere_ereignis_global("info", "Echtzeitschutz wird gestoppt.")
            self.echtzeit_schutz_aktiv = False
            self.echtzeit_schutz_thread = None
        else:
            protokolliere_ereignis_global("warnung", "Kein Echtzeitschutz läuft oder Thread-Objekt nicht vorhanden.")

    def _geplante_pruefung_schleife(self):
        """Schleife für die geplante Systemprüfung."""
        while True:
            protokolliere_ereignis_global("info", "Geplante Systemprüfung startet...")
            self.starte_systempruefung()
            protokolliere_ereignis_global("info", f"Geplante Systemprüfung abgeschlossen. Nächste Prüfung in {self.pruefungs_intervall_sekunden} Sekunden.")
            time.sleep(self.pruefungs_intervall_sekunden)

    def _echtzeit_schutz_schleife(self):
        """Echtzeitschutz-Schleife."""
        protokolliere_ereignis_global("info", "Echtzeitschutz-Schleife gestartet.")
        while self.echtzeit_schutz_aktiv:
            self._ueberpruefe_system_ereignisse_echtzeit()
            self._ueberpruefe_prozesse_echtzeit()
            self._ueberpruefe_netzwerk_aktivitaeten_echtzeit()
            time.sleep(5)
        protokolliere_ereignis_global("info", "Echtzeitschutz-Schleife beendet.")

    def _ueberpruefe_system_ereignisse_echtzeit(self):
        """Überprüft Systemereignisse im Echtzeit-Modus (aktuell Platzhalter)."""
        protokolliere_ereignis_global("debug", "Echtzeit-Systemereignisüberprüfung (Platzhalter).")
        # TODO: Implementierung für Echtzeit-Systemereignisüberwachung (z.B. Dateioperationen, Registry-Änderungen)
        # Für jetzt: Placeholder message reicht.
        pass # Zukünftige Implementierung für Systemereignisse

    def _ueberpruefe_prozesse_echtzeit(self):
        """Überprüft laufende Prozesse im Echtzeit-Modus."""
        protokolliere_ereignis_global("debug", "Echtzeit-Prozessüberprüfung gestartet.")
        for prozess in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']): # 'connections' entfernt
            try:
                prozess_info = prozess.info
                prozess_obj = psutil.Process(prozess_info['pid']) # Prozess Objekt holen
                verbindungen = prozess_obj.net_connections() # Verbindungen separat abrufen
                prozess_info['connections'] = verbindungen # Verbindungen zur Prozessinfo hinzufügen (optional, falls später benötigt)

                ergebnis, regel_name = self._analysiere_prozess(prozess_info)
                if ergebnis == "bedrohung":
                    protokolliere_ereignis_global("warnung", f"Verdächtiger Prozess erkannt: '{prozess_info.get('name', 'Unbekannt')}' (PID: {prozess_info.get('pid', 'Unbekannt')}) durch Regel '{regel_name}'. Aktion: Prozess beenden.",
                                                {"prozess_name": prozess_info.get('name', 'Unbekannt'), "pid": prozess_info.get('pid', 'Unbekannt'), "regel_name": regel_name})
                    self.warnungs_manager.zeige_warnung(f"Verdächtiger Prozess erkannt: '{prozess_info.get('name', 'Unbekannt')}' (PID: {prozess_info.get('pid', 'Unbekannt')}). Aktion: Prozess beendet.",
                                                      aktion="prozess_beenden", pid=prozess_info.get('pid'))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                protokolliere_ereignis_global("warnung", f"Fehler beim Zugriff auf Prozessinformationen (Echtzeit-Prozessüberprüfung): {e}", {"prozess_pid": prozess.pid, "fehler": str(e)})
            except Exception as e:
                protokolliere_ereignis_global("fehler", f"Unerwarteter Fehler bei der Echtzeit-Prozessüberprüfung: {e}", {"fehler": str(e)})

    def _ueberpruefe_netzwerk_aktivitaeten_echtzeit(self):
        """Überprüft Netzwerkaktivitäten im Echtzeit-Modus (zukünftig)."""
        protokolliere_ereignis_global("debug", "Echtzeit-Netzwerkaktivitätsüberprüfung (gestartet, rudimentär).")
        # TODO: Implementierung für detailliertere Echtzeit-Netzwerkaktivitätsüberwachung
        # Für jetzt: rudimentäre Überwachung der Verbindungen reicht.
        self.netzwerk_manager.überwache_netzwerk_verbindungen()
        pass # Zukünftige Implementierung für Netzwerkaktivitäten

    def manuelle_systempruefung_starten_gui(self):
        """Startet eine manuelle Systemprüfung über die GUI."""
        protokolliere_ereignis_global("info", "Manuelle Systemprüfung über GUI angefordert.")
        threading.Thread(target=self.starte_systempruefung).start()

    def zeige_letzte_pruefung_zeit_gui(self):
        """Zeigt die Zeit der letzten Systemprüfung in der GUI an."""
        from tkinter import messagebox # Lokaler Import, um Zirkelbezug zu vermeiden
        messagebox.showinfo("Letzte Systemprüfung", f"Letzte Systemprüfung: {self.letzte_pruefung_zeit}")

    def überprüfe_system_nach_regeln(self):
        """Überprüft das System anhand der geladenen Regeln (generische Funktion)."""
        regeln = self.regel_manager.get_regeln()
        return regeln

    def _analysiere_prozess(self, prozess_info):
        """Analysiert einen Prozess anhand der Regeln."""
        regeln = self.regel_manager.get_regeln()
        prozess_regeln = regeln.get("prozesse", {}).get("regeln", [])

        for regel in prozess_regeln:
            if regel.get("aktiviert"):
                muster_liste = regel.get("muster", [])
                aktion = regel.get("aktion")
                quanten_analyse_aktiviert = regel.get("quanten_analyse_aktiviert", False)

                prozess_name_lower = prozess_info.get('name', '').lower()

                if any(muster.lower() in prozess_name_lower for muster in muster_liste):
                    protokolliere_ereignis_global("debug", f"Prozess '{prozess_name_lower}' matched Regel '{regel.get('name')}' (Muster: {muster_liste}). Aktion: {aktion}")

                    if quanten_analyse_aktiviert:
                        protokolliere_ereignis_global("debug", f"Quantenanalyse für Prozess '{prozess_name_lower}' (Regel: '{regel.get('name')}') aktiviert.")
                        quanten_ergebnis = self.quanten_analyse_manager.quanten_anomalie_erkennung(prozess_info)
                        if quanten_ergebnis == "verdächtig":
                            protokolliere_ereignis_global("warnung", f"Quantenanalyse meldet verdächtiges Prozessverhalten für '{prozess_name_lower}' (Regel: '{regel.get('name')}').")
                            return "bedrohung", regel.get("name")

                    ki_ergebnis = self.ki_analyse_manager.analysiere_prozess_verhalten(prozess_info)
                    if ki_ergebnis == "verdächtig":
                        protokolliere_ereignis_global("warnung", f"KI-Analyse meldet verdächtiges Prozessverhalten für '{prozess_name_lower}' (Regel: '{regel.get('name')}'). KI-Antwort: {ki_ergebnis}")
                        return "bedrohung", regel.get("name")

                    if aktion == "prozess_beenden":
                        return "bedrohung", regel.get("name")
                    elif aktion == "warnung":
                        self.warnungs_manager.zeige_warnung(f"Verdächtiger Prozess '{prozess_name_lower}' gefunden (Regel: '{regel.get('name')}').")
                        return "verdacht", regel.get("name")
        return "normal", None

    def _analysiere_datei(self, datei_pfad, datei_hash):
        """Analysiert eine Datei anhand der Regeln."""
        regeln = self.regel_manager.get_regeln()
        datei_regeln = regeln.get("dateien", {}).get("regeln", [])

        for regel in datei_regeln:
            if regel.get("aktiviert"):
                muster_liste = regel.get("muster", [])
                pfad_liste = regel.get("pfade", [])
                aktion = regel.get("aktion")
                quanten_analyse_aktiviert = regel.get("quanten_analyse_aktiviert", False)
                blockchain_reputation_aktiviert = regel.get("blockchain_reputation_aktiviert", False)

                datei_name_lower = os.path.basename(datei_pfad).lower()
                datei_pfad_lower = datei_pfad.lower()

                if pfad_liste:
                    erfüllt_pfad_bedingung = False
                    for pfad_muster in pfad_liste:
                        erweiterter_pfad = os.path.expandvars(pfad_muster).lower()
                        if erweiterter_pfad in datei_pfad_lower:
                            erfüllt_pfad_bedingung = True
                            break
                    if not erfüllt_pfad_bedingung:
                        protokolliere_ereignis_global("debug", f"Datei '{datei_pfad}' ignoriert (Pfadbedingung der Regel '{regel.get('name')}' nicht erfüllt). Erwartete Pfade: {pfad_liste}")
                        continue

                if any(datei_name_lower.endswith(muster.lower()) for muster in muster_liste):
                    protokolliere_ereignis_global("debug", f"Datei '{datei_pfad}' matched Regel '{regel.get('name')}' (Muster: {muster_liste}, Pfade: {pfad_liste}). Aktion: {aktion}")

                    if blockchain_reputation_aktiviert:
                        protokolliere_ereignis_global("debug", f"Blockchain-Reputationsprüfung für Datei '{datei_pfad}' (Regel: '{regel.get('name')}') aktiviert.")
                        datei_reputation = self.blockchain_manager.pruefe_datei_reputation_blockchain(datei_hash)
                        if datei_reputation == "bösartig" or datei_reputation == "verdächtig":
                            protokolliere_ereignis_global("warnung", f"Blockchain-Reputationsprüfung meldet erhöhte Reputation für Datei '{datei_pfad}' (Regel: '{regel.get('name')}'). Reputation: {datei_reputation}")
                            return "bedrohung", regel.get("name")

                    if quanten_analyse_aktiviert:
                        protokolliere_ereignis_global("debug", f"Quantenanalyse für Datei '{datei_pfad}' (Regel '{regel.get('name')}') aktiviert.")
                        quanten_ergebnis = self.quanten_analyse_manager.quanten_malware_signatur_analyse(datei_pfad)
                        if quanten_ergebnis == "verdächtig":
                            protokolliere_ereignis_global("warnung", f"Quantenanalyse meldet verdächtige Datei-Signatur/Anomalie für '{datei_pfad}' (Regel: '{regel.get('name')}').")
                            return "bedrohung", regel.get("name")

                    if aktion == "datei_quarantaene":
                        return "bedrohung", regel.get("name")
                    elif aktion == "warnung":
                        self.warnungs_manager.zeige_warnung(f"Verdächtige Datei '{datei_pfad}' gefunden (Regel: '{regel.get('name')}').")
                        return "verdacht", regel.get("name")
        return "normal", None

    def _analysiere_netzwerk_verbindung(self, verbindung_info):
        """Analysiert eine Netzwerkverbindung anhand der Regeln (zukünftig)."""
        regeln = self.regel_manager.get_regeln()
        netzwerk_regeln = regeln.get("netzwerk", {}).get("regeln", [])

        for regel in netzwerk_regeln:
            if regel.get("aktiviert"):
                muster_ports = regel.get("muster", [])
                aktion = regel.get("aktion")
                quanten_analyse_aktiviert = regel.get("quanten_analyse_aktiviert", False)

                remote_port = verbindung_info.get("rport")

                if remote_port in muster_ports:
                    protokolliere_ereignis_global("debug", f"Netzwerkverbindung zu Remote-Port '{remote_port}' matched Regel '{regel.get('name')}' (Muster: {muster_ports}). Aktion: {aktion}")

                    if quanten_analyse_aktiviert:
                        protokolliere_ereignis_global("debug", f"Quantenanalyse für Netzwerkverbindung zu Port '{remote_port}' (Regel: '{regel.get('name')}') aktiviert.")
                        quanten_ergebnis = self.quanten_analyse_manager.quanten_anomalie_erkennung(verbindung_info)
                        if quanten_ergebnis == "verdächtig":
                            protokolliere_ereignis_global("warnung", f"Quantenanalyse meldet verdächtigen Netzwerkverkehr zu Port '{remote_port}' (Regel: '{regel.get('name')}').")
                            return "bedrohung", regel.get("name")

                    if aktion == "warnung":
                        self.warnungs_manager.zeige_warnung(f"Verdächtige Netzwerkverbindung zu Port '{remote_port}' (Regel: '{regel.get('name')}').")
                        return "verdacht", regel.get("name")
        return "normal", None

    def _berechne_datei_hash(self, datei_pfad, algorithmus="sha256") -> Union[str, None]:
        # Überspringe Systemdateien, die mit '.sys' enden
        if datei_pfad.lower().endswith(".sys"):
            protokolliere_ereignis_global("debug", f"Datei '{datei_pfad}' wird übersprungen, da es sich um eine Systemdatei handelt.")
            return None
        hasher = hashlib.new(algorithmus)
        try:
            with open(datei_pfad, 'rb') as datei:
                while block := datei.read(4096):
                    hasher.update(block)
            return hasher.hexdigest()
        except PermissionError as e:
            protokolliere_ereignis_global("warnung", f"Zugriff verweigert beim Berechnen des Datei-Hashes für '{datei_pfad}': {e}. Datei wird übersprungen.", {"datei_pfad": datei_pfad, "fehler": str(e)})
            return None
        except Exception as e:
            protokolliere_ereignis_global("fehler", f"Fehler beim Berechnen des Datei-Hashes für '{datei_pfad}': {e}", {"datei_pfad": datei_pfad, "fehler": str(e)})
            return None

    def protokolliere_ereignis(self, typ, meldung, daten=None):
        """Protokolliert ein Ereignis über das Logging-Modul."""
        protokolliere_ereignis_global(typ, meldung, daten=None)
