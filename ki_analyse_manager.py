import google.generativeai as genai # Gemini API import
# Importiere die globale Protokollierungsfunktion aus logging_utils.py
from logging_utils import protokolliere_ereignis_global
import time # Für Simulationen
import os

class KIAnalyseManager:
    """
    Verwaltet KI-basierte Analysen und Erkennung.
    Modul für KI-Funktionalitäten, aktuell Gemini-basiert.
    """
    def __init__(self, konfig_manager):
        self.konfig_manager = konfig_manager
        self.ki_konfig = self.konfig_manager.get_konfiguration().get("ki")
        self.ki_aktiviert = self.ki_konfig.get("aktiviert", True)
        self.gemini_api_key = self.ki_konfig.get("gemini_api_key")
        self.gemini_modell_name = self.ki_konfig.get("gemini_modell_name")

        self.ki_modell_pfad = self.konfig_manager.get_konfiguration().get("ki_modell_pfad") # unused config key
        self.lade_ki_modelle()
        self.gemini_modell = None

        if self.ki_aktiviert and self.gemini_api_key and self.gemini_api_key != "YOUR_GEMINI_API_KEY": # API Key Check hinzugefügt
            self.initialisiere_gemini()
        elif self.ki_aktiviert and (not self.gemini_api_key or self.gemini_api_key == "YOUR_GEMINI_API_KEY"):
            protokolliere_ereignis_global("warnung", "KI-Analyse aktiviert, aber kein gültiger Gemini API-Schlüssel konfiguriert. KI-Funktionen mit Gemini werden deaktiviert.")
            self.ki_aktiviert = False
        else:
            protokolliere_ereignis_global("info", "KI-Analyse ist DEAKTIVIERT gemäß Konfiguration.")

    def initialisiere_gemini(self):
        """Initialisiert das Gemini KI-Modell."""
        try:
            genai.configure(api_key=self.gemini_api_key) # API Key Konfiguration HIER
            self.gemini_modell = genai.GenerativeModel(self.gemini_modell_name) # Kein API Key hier
            protokolliere_ereignis_global("info", f"Gemini KI-Modell '{self.gemini_modell_name}' erfolgreich initialisiert.")
        except Exception as e:
            protokolliere_ereignis_global("fehler", f"Fehler bei der Initialisierung des Gemini KI-Modells: {e}. KI-Funktionen mit Gemini werden deaktiviert.", {"fehler": str(e)})
            self.ki_aktiviert = False

    def lade_ki_modelle(self):
        """Lädt KI-Modelle (aktuell Platzhalter)."""
        protokolliere_ereignis_global("info", f"KIAnalyseManager initialisiert. Lade KI-Modelle aus (Pfad nicht konfiguriert, aktuell Platzhalter-Funktion).")
        # TODO: Logik zum Laden von KI-Modellen (z.B. TensorFlow, PyTorch Modelle)
        # Für jetzt: keine Modelle laden, placeholder message reicht.
        self.ki_modelle = {} # Placeholder: Dictionary für geladene KI-Modelle

    def _frage_gemini(self, prompt):
        """Interagiert mit dem Gemini KI-Modell."""
        if not self.ki_aktiviert or not self.gemini_modell:
            protokolliere_ereignis_global("warnung", "Gemini KI-Modell ist nicht initialisiert oder KI ist deaktiviert. Keine KI-Analyse möglich.")
            return "KI-Analyse nicht verfügbar."

        try:
            protokolliere_ereignis_global("debug", f"Sende Anfrage an Gemini: '{prompt}'")
            antwort = self.gemini_modell.generate_content(prompt)
            protokolliere_ereignis_global("debug", f"Antwort von Gemini erhalten.")
            return antwort.text
        except Exception as e:
            protokolliere_ereignis_global("fehler", f"Fehler bei der Anfrage an Gemini: {e}", {"fehler": str(e)})
            return f"Fehler bei KI-Analyse: {e}"

    def analysiere_prozess_verhalten(self, prozess_info):
        """Analysiert Prozessverhalten mit KI (nutzt Gemini)."""
        if not self.ki_aktiviert or not self.gemini_modell:
            protokolliere_ereignis_global("warnung", "KI-Analyse für Prozessverhalten ist deaktiviert oder nicht initialisiert. Verwende Standardanalyse.")
            return "normal"

        prozess_name = prozess_info.get('name', 'Unbekannt')
        pid = prozess_info.get('pid', 'Unbekannt')
        prompt = f"Analysiere das Verhalten des Prozesses '{prozess_name}' (PID: {pid}). Ist das Verhalten verdächtig im Kontext eines Virenschutzprogramms? Begründe deine Antwort kurz."

        ki_antwort = self._frage_gemini(prompt)
        protokolliere_ereignis_global("info", f"KI-Analyse (Gemini) für Prozess '{prozess_name}' (PID: {pid}): Antwort: {ki_antwort}")

        if "verdächtig" in ki_antwort.lower() or "ungewöhnlich" in ki_antwort.lower() or "potenziell gefährlich" in ki_antwort.lower():
            return "verdächtig"
        else:
            return "normal"

    def analysiere_datei_verhalten(self, datei_pfad):
        """Analysiert Dateiverhalten mit KI (aktuell Platzhalter)."""
        protokolliere_ereignis_global("debug", f"KIAnalyseManager: Analysiere Dateiverhalten für Datei '{datei_pfad}'. (Simuliere: Unauffällig)")
        # TODO: KI-Modell für Dateiverhaltensanalyse aufrufen und Ergebnis zurückgeben
        # Hier würde man z.B. ein vortrainiertes Modell laden und füttern mit Features der Datei (z.B. Inhaltsextrakt, Metadaten)
        time.sleep(0.2) # Simuliere Analysezeit
        return "normal" # Simuliere: Datei ist unauffällig

    def analysiere_netzwerk_verhalten(self, netzwerk_daten):
        """Analysiert Netzwerkverkehr mit KI (aktuell Platzhalter)."""
        protokolliere_ereignis_global("debug", f"KIAnalyseManager: Analysiere Netzwerkverkehr. (Simuliere: Unauffällig)")
        # TODO: KI-Modell für Netzwerkanalyse aufrufen und Ergebnis zurückgeben
        # Hier würde man z.B. Netzwerk-Features (Ports, Protokolle, Zieladressen) analysieren
        time.sleep(0.3) # Simuliere Analysezeit
        return "normal" # Simuliere: Netzwerkverhalten unauffällig

    def analysiere_system_verhalten(self):
        """Analysiert das gesamte Systemverhalten mit KI (aktuell Platzhalter)."""
        protokolliere_ereignis_global("debug", f"KIAnalyseManager: Analysiere gesamtes Systemverhalten mit KI. (Simuliere: Unauffällig)")
        # TODO: KI-Modell für umfassende Systemanalyse und Anomalieerkennung
        # Hier könnte man Metriken des gesamten Systems (CPU, Speicher, Netzwerk, Prozesse) analysieren
        time.sleep(0.5) # Simuliere Analysezeit
        return "normal" # Simuliere: Systemverhalten unauffällig

    def protokolliere_ereignis(self, typ, meldung, daten=None):
        """Protokolliert ein Ereignis über das Logging-Modul."""
        protokolliere_ereignis_global(typ, meldung, daten)
