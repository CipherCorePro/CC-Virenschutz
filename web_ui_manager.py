from flask import Flask, render_template, jsonify
import psutil
import threading
import time
import os
from config_rules_quarantine import KonfigurationManager
from logging_utils import protokolliere_ereignis_global
from system_pruefung_manager import SystemÜberprüfungsManager # Import SystemÜberprüfungsManager
from prozess_manager import ProzessManager # Import ProzessManager
from warnungs_manager import WarnungsManager # Import WarnungsManager
from blockchain_manager import BlockchainManager # Import BlockchainManager
from ki_analyse_manager import KIAnalyseManager # Import KIAnalyseManager # Import KIAnalyseManager hinzugefügt

class WebUIManager:
    """Verwaltet die Web-UI für den Virenschutz."""
    def __init__(self, konfig_manager, system_ueberpruefungs_manager, prozess_manager, warnungs_manager, blockchain_manager, ki_analyse_manager): # ki_analyse_manager hinzugefügt
        """
        Initialisiert den WebUIManager.
        """
        self.konfig_manager = konfig_manager
        self.system_ueberpruefungs_manager = system_ueberpruefungs_manager
        self.prozess_manager = prozess_manager
        self.warnungs_manager = warnungs_manager
        self.blockchain_manager = blockchain_manager
        self.ki_analyse_manager = ki_analyse_manager # ki_analyse_manager hinzugefügt
        self.web_ui_aktiviert = self.konfig_manager.get_konfiguration().get("web_ui").get("aktiviert", True)
        self.web_ui_port = self.konfig_manager.get_konfiguration().get("web_ui").get("port", 5000)
        self.aktualisierungs_intervall = self.konfig_manager.get_konfiguration().get("web_ui").get("aktualisierungs_intervall", 5)
        self.app = Flask(__name__)
        self.letzte_log_eintraege = []
        self.log_aktualisierungs_intervall = 2
        self.letzte_log_aktualisierung_zeit = 0
        self.anzahl_bedrohungen_session = 0 # Anzahl Bedrohungen in der aktuellen Session

        # Flask Routen definieren
        self.app.add_url_rule('/', 'index', self.index)
        self.app.add_url_rule('/logs', 'logs', self.logs)
        self.app.add_url_rule('/config', 'config_anzeigen', self.config_anzeigen)
        self.app.add_url_rule('/api/dashboard_daten', 'api_dashboard_daten', self.api_dashboard_daten)
        self.app.add_url_rule('/api/log_daten', 'api_log_daten', self.api_log_daten)
        self.app.add_url_rule('/api/config_daten', 'api_config_daten', self.api_config_daten)

    def starte_web_ui(self):
        """Startet die Flask Web-UI in einem Thread."""
        if not self.web_ui_aktiviert:
            protokolliere_ereignis_global("info", "Web-UI ist deaktiviert in der Konfiguration. Web-UI wird NICHT gestartet.")
            return

        protokolliere_ereignis_global("info", f"Web-UI wird gestartet auf Port {self.web_ui_port}...")
        web_ui_thread = threading.Thread(target=self.run_flask_app)
        web_ui_thread.daemon = True
        web_ui_thread.start()

    def run_flask_app(self):
        """Startet die Flask-App (interne Methode für Thread)."""
        self.app.run(port=self.web_ui_port, debug=False)

    # --- Flask Routen und zugehörige Funktionen ---
    def index(self):
        """Route für das Haupt-Dashboard."""
        cpu_auslastung_virenschutz = psutil.cpu_percent(interval=1)
        speicher_auslastung_virenschutz = psutil.virtual_memory().percent

        # TODO: Hier oder im SystemÜberprüfungsManager echte Bedrohungszählung implementieren
        anzahl_bedrohungen = self.anzahl_bedrohungen_session # Platzhalter

        return render_template(
            'index.html', # **Template-Dateien (HTML) müssten noch erstellt werden!**
            cpu_auslastung=cpu_auslastung_virenschutz,
            speicher_auslastung=speicher_auslastung_virenschutz,
            echtzeit_schutz_aktiv=self.system_ueberpruefungs_manager.echtzeit_schutz_aktiv,
            letzte_pruefung_zeit=self.system_ueberpruefungs_manager.letzte_pruefung_zeit_str,
            anzahl_bedrohungen=anzahl_bedrohungen,
            blockchain_aktiviert=self.blockchain_manager.blockchain_aktiviert,
            ki_aktiviert=self.ki_analyse_manager.ki_aktiviert, # ki_aktiviert hinzugefügt
            virenschutz_version=self.konfig_manager.get_konfiguration().get("virenschutz").get("version"),
            aktualisierungs_intervall=self.aktualisierungs_intervall
        )

    def logs(self):
        """Route für die Anzeige der Log-Einträge."""
        self._aktualisiere_log_cache()
        return render_template(
            'logs.html', # **Template-Dateien (HTML) müssten noch erstellt werden!**
            log_eintraege=self.letzte_log_eintraege,
            aktualisierungs_intervall=self.aktualisierungs_intervall
        )

    def config_anzeigen(self):
        """Route für die Anzeige der Konfiguration."""
        konfiguration = self.konfig_manager.get_konfiguration()
        return render_template(
            'config.html', # **Template-Dateien (HTML) müssten noch erstellt werden!**
            konfiguration=konfiguration,
            aktualisierungs_intervall=self.aktualisierungs_intervall
        )

    # --- API Endpunkte (für JSON Daten) ---
    def api_dashboard_daten(self):
        """API-Endpunkt für Dashboard-Daten (JSON)."""
        cpu_auslastung_virenschutz = psutil.cpu_percent(interval=1)
        speicher_auslastung_virenschutz = psutil.virtual_memory().percent

        # TODO: Hier echte Bedrohungszählung implementieren
        anzahl_bedrohungen = self.anzahl_bedrohungen_session # Platzhalter

        daten = {
            "cpu_auslastung": cpu_auslastung_virenschutz,
            "speicher_auslastung": speicher_auslastung_virenschutz,
            "echtzeit_schutz_aktiv": self.system_ueberpruefungs_manager.echtzeit_schutz_aktiv,
            "letzte_pruefung_zeit": self.system_ueberpruefungs_manager.letzte_pruefung_zeit_str,
            "anzahl_bedrohungen": anzahl_bedrohungen,
            "blockchain_aktiviert": self.blockchain_manager.blockchain_aktiviert,
            "ki_aktiviert": self.ki_analyse_manager.ki_aktiviert, # ki_aktiviert hinzugefügt
            "virenschutz_version": self.konfig_manager.get_konfiguration().get("virenschutz").get("version"),
            "aktualisierungs_intervall": self.aktualisierungs_intervall
        }
        return jsonify(daten)

    def api_log_daten(self):
        """API-Endpunkt für Log-Daten (JSON)."""
        self._aktualisiere_log_cache()
        daten = {
            "log_eintraege": self.letzte_log_eintraege,
            "aktualisierungs_intervall": self.aktualisierungs_intervall
        }
        return jsonify(daten)

    def api_config_daten(self):
        """API-Endpunkt für Konfigurationsdaten (JSON)."""
        konfiguration = self.konfig_manager.get_konfiguration()
        daten = {
            "konfiguration": konfiguration,
            "aktualisierungs_intervall": self.aktualisierungs_intervall
        }
        return jsonify(daten)

    def _aktualisiere_log_cache(self):
        """Aktualisiert den Log-Cache in regelmäßigen Abständen."""
        jetzt = time.time()

        # Initialisieren, falls nicht vorhanden
        if not hasattr(self, 'letzte_log_aktualisierung_zeit'):
            self.letzte_log_aktualisierung_zeit = 0

        if jetzt - self.letzte_log_aktualisierung_zeit >= self.log_aktualisierungs_intervall:
            log_datei_pfad = self.konfig_manager.get_konfiguration().get("logging").get("log_datei")
            log_datei_pfad = os.path.abspath(log_datei_pfad)  # Sicherstellen, dass es ein absoluter Pfad ist

            try:
                if not os.path.exists(log_datei_pfad):  # Prüfen, ob Datei existiert
                    self.letzte_log_eintraege = ["Log-Datei nicht gefunden! Pfad: " + log_datei_pfad]
                    return

                with open(log_datei_pfad, 'r', encoding='utf-8', errors='ignore') as f:  # Fehlerfreies Encoding setzen
                    alle_log_eintraege = f.readlines()
                    self.letzte_log_eintraege = alle_log_eintraege[-100:]  # Letzte 100 Einträge speichern

            except FileNotFoundError:
                self.letzte_log_eintraege = ["Log-Datei nicht gefunden!"]
            except Exception as e:
                self.letzte_log_eintraege = [f"Fehler beim Lesen der Log-Datei: {e}"]

            self.letzte_log_aktualisierung_zeit = jetzt  # Zeitpunkt der letzten Aktualisierung setzen
