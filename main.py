#!/usr/bin/env python3
"""
Hauptmodul für den Visionären Virenschutz

Dieses Skript initialisiert alle Komponenten (Konfiguration, Regeln, Quarantäne,
Prozess-, Netzwerk- und Systemüberwachung, KI‑ und Quantenanalyse, Blockchain‑Integration
sowie die Web‑UI) und startet das Hauptprogramm.

Es wurde so angepasst, dass:
    - Fehler beim Laden der JSON‑Konfigurationsdatei mittels strukturellem Pattern Matching
      präzise abgehandelt werden.
    - Systemdateien (z. B. *.sys) nicht zur Hashberechnung verarbeitet werden, um "Permission denied"
      Warnungen zu vermeiden.
    - Die veraltete Methode connections() durch net_connections() ersetzt wurde.

Alle Funktionen und Codezeilen sind ausführlich kommentiert.
"""

import os
import tkinter as tk

# Importe der Module aus dem Projekt
from config_rules_quarantine import KonfigurationManager, RegelManager, QuarantäneManager, protokolliere_ereignis_global
from warnungs_manager import WarnungsManager
from prozess_manager import ProzessManager
from netzwerk_manager import NetzwerkManager
from ki_analyse_manager import KIAnalyseManager
from quanten_analyse_manager import QuantenAnalyseManager
from blockchain_manager import BlockchainManager
from system_pruefung_manager import SystemÜberprüfungsManager
from web_ui_manager import WebUIManager

# Importiere die Logging-Initialisierung
from logging_utils import initialisiere_logging

# Moderne Typannotationen (Union-Typ-Operator, PEP 604) für eventuelle Rückgabewerte
from typing import Union

# Initialisierung des Loggings (hier werden Log-Level und Log-Dateipfad aus der Konfiguration verwendet)
def setup_logging(config: dict) -> None:
    log_config = config.get("logging", {})
    log_datei = log_config.get("log_datei", "virenschutz.log")
    log_level = log_config.get("log_level", "DEBUG")
    initialisiere_logging(log_level, log_datei)
    protokolliere_ereignis_global("info", f"Logging wurde initialisiert: Level={log_level}, Datei='{log_datei}'")

# Hauptfunktion, die alle Komponenten initialisiert und den Virenschutz startet
def main() -> None:
    """
    Hauptfunktion des Virenschutzprogramms.

    Hier werden zunächst die Konfiguration und alle Manager-Instanzen erzeugt.
    Anschließend wird die GUI (Tkinter) gestartet, die u.a. den Web-UI-Manager informiert.
    """
    # Konfiguration laden und Logging einrichten
    config_manager = KonfigurationManager()
    config = config_manager.get_konfiguration()
    setup_logging(config)

    # Manager-Instanzen erzeugen
    regel_manager = RegelManager(config_manager)
    quarantaene_manager = QuarantäneManager(config_manager)
    warnungs_manager = WarnungsManager()
    prozess_manager = ProzessManager()
    netzwerk_manager = NetzwerkManager()
    ki_analyse_manager = KIAnalyseManager(config_manager)
    quanten_analyse_manager = QuantenAnalyseManager(config_manager)
    blockchain_manager = BlockchainManager(config_manager)

    # Warnungs-Manager die Prozess- und Quarantäne-Manager Instanzen bekannt machen (für Aktionen)
    warnungs_manager.prozess_manager = prozess_manager # Zuweisung hier
    warnungs_manager.quarantaene_manager = quarantaene_manager # Zuweisung hier
    # Globale Instanzen für WarnungsManager-Aktionen (zirkuläre Importe vermeiden)
    globals()['prozess_manager'] = prozess_manager
    globals()['quarantaene_manager'] = quarantaene_manager
    globals()['blockchain_manager'] = blockchain_manager

    # Systemüberprüfung inkl. manueller und geplanter Prüfungen
    system_pruefung_manager = SystemÜberprüfungsManager(
        config_manager,
        regel_manager,
        quarantaene_manager,
        prozess_manager,
        netzwerk_manager,
        warnungs_manager,
        ki_analyse_manager,
        quanten_analyse_manager,
        blockchain_manager
    )

    # Web-UI (Flask) instanziieren
    web_ui_manager = WebUIManager(config_manager, system_pruefung_manager, prozess_manager, warnungs_manager, blockchain_manager, ki_analyse_manager) # ki_analyse_manager hinzugefügt
    globals()['web_ui_manager'] = web_ui_manager # Globale Instanz für Zugriff durch SystemÜberprüfungsManager

    # Starte den Web-UI-Server in einem eigenen Thread (falls in der Konfiguration aktiviert)
    web_ui_manager.starte_web_ui()

    # Starte die GUI (Tkinter) – als zentrale Anlaufstelle für manuelle Prüfungen
    hauptfenster = tk.Tk()
    hauptfenster.title(config.get("virenschutz", {}).get("name", "Virenschutz"))
    hauptfenster.geometry("500x400")

    # Anzeige der Virenschutz-Version
    status_label = tk.Label(hauptfenster, text=f"Virenschutz: {config.get('virenschutz', {}).get('name', 'Unbekannt')} "
                                                 f"Version {config.get('virenschutz', {}).get('version', '0.0')}")
    status_label.pack(pady=10)

    # Button zur manuellen Systemprüfung
    pruefung_button = tk.Button(hauptfenster,
                                text="Manuelle Systemprüfung starten",
                                command=system_pruefung_manager.manuelle_systempruefung_starten_gui)
    pruefung_button.pack(pady=5)

    # Button zur Anzeige der letzten Prüfungszeit
    letzte_pruefung_button = tk.Button(hauptfenster,
                                       text="Letzte Systemprüfung anzeigen",
                                       command=system_pruefung_manager.zeige_letzte_pruefung_zeit_gui)
    letzte_pruefung_button.pack(pady=5)

    # Information zur Web-Oberfläche (falls aktiviert)
    web_ui_info_label = tk.Label(hauptfenster,
                                 text=f"Web-Oberfläche: http://127.0.0.1:{config.get('web_ui', {}).get('port', 5000)}/")
    web_ui_info_label.pack(pady=10)

    protokolliere_ereignis_global("info", "GUI Hauptfenster erstellt. Starte Hauptschleife der GUI.")
    hauptfenster.mainloop()

    # Beim Beenden der GUI wird der Virenschutz ordentlich heruntergefahren
    protokolliere_ereignis_global("info", "Virenschutz wird beendet.")

# Standard‑Eintrittspunkt
if __name__ == "__main__":
    main()
