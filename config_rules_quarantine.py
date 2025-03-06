import json
import os
import shutil
import logging
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

# Importiere die globale Protokollierungsfunktion aus logging_utils.py
from logging_utils import protokolliere_ereignis_global

class KonfigurationManager:
    """
    Verwaltet die Konfiguration des Virenschutzes.
    Modul für Konfigurationsmanagement und Persistenz.
    """
    CONFIG_DATEI = "virenschutz_config.json"
    STANDARD_KONFIGURATION = {
        "virenschutz": {
            "name": "Visionärer Virenschutz",
            "version": "0.15",
            "entwickler": "KI-Agenten-Team"
        },
        "systempruefung": {
            "scan_verzeichnis": ["C:\\"],
            "dateiendungen_ignoriert": [".log", ".tmp", ".temp"],
            "system_verzeichnisse_ignoriert": ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\System Volume Information", "C:\\$Recycle.Bin", "C:\\ProgramData"],
            "echtzeit_schutz": True,
            "pruefungs_intervall_sekunden": 600
        },
        "regeln": {
            "regelsatz_datei": "virenschutz_regeln.json"
        },
        "quarantaene": {
            "quarantaene_verzeichnis": "quarantaene"
        },
        "logging": {
            "log_datei": "virenschutz.log",
            "log_level": "DEBUG"
        },
        "blockchain": {
            "aktiviert": False,
            "log_registrierung_aktiviert": False,
            "threat_intelligence_aktiviert": False,
            "update_verifizierung_aktiviert": False,
            "netzwerk_adresse": "http://localhost:8545", # Platzhalter für Netzwerkadresse (z.B. Ethereum)
            "api_schluessel": "rhAUQtxnceWojZHvhZ1EoG1CuYT7s7NyDWhKkBehOcI", # API Schlüssel falls benötigt
            "smart_contract_adresse": "" # Smart Contract Adresse falls verwendet
        },
        "web_ui": {
            "aktiviert": True,
            "port": 5000,
            "aktualisierungs_intervall": 5
        },
        "ki": {  # KI Konfiguration hinzugefügt
            "aktiviert": True,
            "gemini_api_key": "YOUR_GEMINI_API_KEY",  # **WICHTIG: API-Key hier eintragen!**
            "gemini_modell_name": "gemini-2.0-flash"
        }
    }

    def __init__(self):
        self.konfiguration = self.lade_konfiguration()

    def lade_konfiguration(self):
        """Lädt die Konfiguration aus der JSON-Datei."""
        try:
            with open(self.CONFIG_DATEI, 'r', encoding='utf-8') as f:
                konfiguration = json.load(f)
            protokolliere_ereignis_global("info", f"Konfiguration erfolgreich aus '{self.CONFIG_DATEI}' geladen.")
            return konfiguration
        except FileNotFoundError:
            protokolliere_ereignis_global("warnung", f"Konfigurationsdatei '{self.CONFIG_DATEI}' nicht gefunden. Verwende Standardkonfiguration.")
            return self.standard_konfiguration()
        except json.JSONDecodeError:
            protokolliere_ereignis_global("fehler", f"Fehler beim Lesen der Konfigurationsdatei '{self.CONFIG_DATEI}'. JSON-Format ungültig. Verwende Standardkonfiguration.", {"datei": self.CONFIG_DATEI})
            return self.standard_konfiguration()

    def standard_konfiguration(self):
        """Definiert die Standardkonfiguration."""
        return self.STANDARD_KONFIGURATION

    def get_konfiguration(self):
        """Gibt die aktuelle Konfiguration zurück."""
        return self.konfiguration

    def aktualisiere_konfiguration(self, neue_konfiguration):
        """Aktualisiert die Konfiguration und speichert sie in der Datei."""
        self.konfiguration = neue_konfiguration
        self.speichere_konfiguration()
        protokolliere_ereignis_global("info", "Konfiguration aktualisiert und gespeichert.")

    def speichere_konfiguration(self):
        """Speichert die aktuelle Konfiguration in der JSON-Datei."""
        try:
            with open(self.CONFIG_DATEI, 'w') as f:
                json.dump(self.konfiguration, f, indent=4)
            protokolliere_ereignis_global("info", f"Konfiguration erfolgreich in '{self.CONFIG_DATEI}' gespeichert.")
        except Exception as e:
            protokolliere_ereignis_global("fehler", f"Fehler beim Speichern der Konfiguration in '{self.CONFIG_DATEI}': {e}", {"datei": self.CONFIG_DATEI, "fehler": str(e)})

class RegelManager:
    """
    Verwaltet die Regeln des Virenschutzes.
    Modul für Regel-Laden, Speichern und Validierung.
    """
    REGELN_DATEI_DEFAULT = "virenschutz_regeln.json" # Standard, wird aber durch Konfig ersetzt

    def __init__(self, konfig_manager):
        self.konfig_manager = konfig_manager
        self.regeln_datei_pfad = self.konfig_manager.get_konfiguration().get("regeln").get("regelsatz_datei", self.REGELN_DATEI_DEFAULT) # Aus Konfig holen
        self.regeln = self.lade_regeln()

    def lade_regeln(self):
        """Lädt Regeln aus einer JSON-Datei und validiert die Struktur."""
        datei_pfad = self.regeln_datei_pfad
        try:
            if not os.path.exists(datei_pfad):
                self.protokolliere_ereignis("warnung", f"Regeldatei nicht gefunden: '{datei_pfad}'. Verwende leere Regeln.", {"datei": datei_pfad})
                return {"prozesse": {"regeln": []}, "dateien": {"regeln": []}, "netzwerk": {"regeln": []}, "ki_analyse": {"regeln": []}, "quanten_analyse": {"regeln": []}}
            with open(datei_pfad, 'r') as f:
                regeln = json.load(f)
                erwartete_kategorien = ["prozesse", "dateien", "netzwerk", "ki_analyse", "quanten_analyse"]
                for kategorie in erwartete_kategorien:
                    if kategorie not in regeln or not isinstance(regeln[kategorie], dict) or "regeln" not in regeln[kategorie] or not isinstance(regeln[kategorie]["regeln"], list):
                        raise ValueError(f"Ungültige Regelstruktur: Kategorie '{kategorie}' fehlt oder hat ungültige Struktur.")
                self.protokolliere_ereignis("info", f"Regeln erfolgreich aus '{datei_pfad}' geladen.")
                return regeln
        except FileNotFoundError as e:
            self.protokolliere_ereignis("warnung", f"Regeldatei nicht gefunden (FileNotFoundError). Verwende leere Regeln.", {"datei": datei_pfad, "fehler": str(e)})
            return {"prozesse": {"regeln": []}, "dateien": {"regeln": []}, "netzwerk": {"regeln": []}, "ki_analyse": {"regeln": []}, "quanten_analyse": {"regeln": []}}
        except json.JSONDecodeError as e:
            self.protokolliere_ereignis("fehler", f"Fehler beim Lesen der Regeldatei (Ungültiges JSON) '{datei_pfad}'. Verwende leere Regeln.", {"datei": datei_pfad, "fehler": str(e)})
            return {"prozesse": {"regeln": []}, "dateien": {"regeln": []}, "netzwerk": {"regeln": []}, "ki_analyse": {"regeln": []}, "quanten_analyse": {"regeln": []}}
        except ValueError as e:
            self.protokolliere_ereignis("fehler", f"Fehler in der Regelstruktur der Datei '{datei_pfad}': {e}. Verwende leere Regeln.", {"datei": datei_pfad, "fehler": str(e)})
            return {"prozesse": {"regeln": []}, "dateien": {"regeln": []}, "netzwerk": {"regeln": []}, "ki_analyse": {"regeln": []}, "quanten_analyse": {"regeln": []}}
        except Exception as e:
            self.protokolliere_ereignis("fehler", f"Unerwarteter Fehler beim Laden der Regeldatei '{datei_pfad}': {e}. Verwende leere Regeln.", {"datei": datei_pfad, "fehler": str(e)})
            return {"prozesse": {"regeln": []}, "dateien": {"regeln": []}, "netzwerk": {"regeln": []}, "ki_analyse": {"regeln": []}, "quanten_analyse": {"regeln": []}}

    def speichere_regeln(self, regeln):
        """Speichert Regeln in einer JSON-Datei."""
        datei_pfad = self.regeln_datei_pfad
        if not isinstance(regeln, dict):
            self.protokolliere_ereignis("fehler", "Fehler beim Speichern der Regeln: Regeln müssen ein Dictionary sein.", {"regeln_typ": type(regeln)})
            return False
        try:
            with open(datei_pfad, 'w') as f:
                json.dump(regeln, f, indent=4)
            self.protokolliere_ereignis("info", f"Regeln erfolgreich in '{datei_pfad}' gespeichert.")
            return True
        except Exception as e:
            self.protokolliere_ereignis("fehler", f"Fehler beim Speichern der Regeln in '{datei_pfad}': {e}", {"fehler": str(e), "datei_pfad": datei_pfad})
            return False

    def get_regeln(self):
        """Gibt die aktuellen Regeln zurück."""
        return self.regeln

    def protokolliere_ereignis(self, typ, meldung, daten=None):
        """Protokolliert ein Ereignis über das Logging-Modul."""
        protokolliere_ereignis_global(typ, meldung, daten)

class QuarantäneManager:
    """
    Verwaltet Quarantäne-Operationen.
    Modul für Initialisierung und Datei-Quarantäne.
    """
    QUARANTÄNE_PFAD_DEFAULT = "C:\\VirenschutzQuarantaene" # Standard, wird aber durch Konfig ersetzt

    def __init__(self, konfig_manager):
        self.konfig_manager = konfig_manager
        self.quarantaene_pfad = self.konfig_manager.get_konfiguration().get("quarantaene").get("quarantaene_verzeichnis", self.QUARANTÄNE_PFAD_DEFAULT) # Aus Konfig holen
        self.initialisiere_quarantaene()

    def initialisiere_quarantaene(self):
        """Stellt sicher, dass der Quarantäne-Ordner existiert."""
        if not os.path.exists(self.quarantaene_pfad):
            try:
                os.makedirs(self.quarantaene_pfad)
                self.protokolliere_ereignis("info", f"Quarantäne-Ordner '{self.quarantaene_pfad}' erstellt.")
            except OSError as e:
                self.protokolliere_ereignis("fehler", f"Fehler beim Erstellen des Quarantäne-Ordners '{self.quarantaene_pfad}': {e}", {"fehler": str(e)})
        else:
            self.protokolliere_ereignis("info", f"Quarantäne-Ordner '{self.quarantaene_pfad}' existiert bereits.")

    def quarantäne_datei(self, datei_pfad):
        """Verschiebt eine verdächtige Datei in den Quarantäne-Ordner."""
        datei_name = os.path.basename(datei_pfad)
        quarantaene_datei_pfad = os.path.join(self.quarantaene_pfad, datei_name + ".quarantäne")
        try:
            if not os.path.exists(datei_pfad):
                raise FileNotFoundError(f"Datei zum Quarantänisieren nicht gefunden: '{datei_pfad}'")
            shutil.move(datei_pfad, quarantaene_datei_pfad)
            self.protokolliere_ereignis("aktion", f"Datei '{datei_name}' nach Quarantäne verschoben.", {"ursprungs_pfad": datei_pfad, "quarantaene_pfad": quarantaene_datei_pfad})
            return True
        except FileNotFoundError as e:
            self.protokolliere_ereignis("warnung", f"Datei zum Quarantänisieren nicht gefunden: '{datei_pfad}'. Möglicherweise bereits gelöscht oder verschoben.", {"datei_pfad": datei_pfad, "fehler": str(e)})
            return False
        except Exception as e:
            self.protokolliere_ereignis("fehler", f"Fehler beim Verschieben der Datei '{datei_pfad}' in Quarantäne: {e}", {"fehler": str(e), "datei_pfad": datei_pfad})
            return False

    def protokolliere_ereignis(self, typ, meldung, daten=None):
        """Protokolliert ein Ereignis über das Logging-Modul."""
        protokolliere_ereignis_global(typ, meldung, daten)
