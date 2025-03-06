# api_tests.py

import requests
import json

# Konfigurierbare Basis-URL für die Web-UI - kann in der Testumgebung angepasst werden
BASE_URL = "http://localhost:5000"

def teste_api_endpoint(endpoint, erwartete_keys=None):
    """
    Testet einen API-Endpunkt und validiert die JSON-Antwort.
    Args:
        endpoint (str): Der API-Endpunkt relativ zur BASE_URL (z.B. '/').
        erwartete_keys (list, optional): Eine Liste von erwarteten Schlüsseln im JSON-Objekt.
                                         Wenn angegeben, wird geprüft, ob diese Schlüssel vorhanden sind.
    """
    url = BASE_URL + endpoint
    print(f"Teste Endpoint: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()  # Fehlerhafte HTTP-Statuscodes erkennen (z.B. 404, 500)

        if response.headers['Content-Type'] != 'application/json':
            print(f"  FEHLER: Ungültiger Content-Type: {response.headers['Content-Type']}. Erwartet wurde 'application/json'.")
            print("  Antwort-Text (zur Fehlersuche):", response.text)
            return # Test für diesen Endpoint abbrechen

        daten = response.json() # JSON-Antwort parsen
        print("  Status Code OK:", response.status_code)
        print("  JSON Antwort:")
        print(json.dumps(daten, indent=4, ensure_ascii=False)) # JSON formatiert ausgeben (ensure_ascii=False für korrekte Darstellung von Umlauten etc.)

        if erwartete_keys:
            print("  Überprüfe erwartete Schlüssel:")
            for key in erwartete_keys:
                if key in daten:
                    print(f"    - Schlüssel '{key}' vorhanden: OK")
                else:
                    print(f"    - Schlüssel '{key}' FEHLT!")
                    raise AssertionError(f"Erwarteter Schlüssel '{key}' fehlt in der JSON-Antwort von {endpoint}")

        print("  Endpoint Test erfolgreich abgeschlossen.\n")

    except requests.exceptions.RequestException as e:
        print(f"  FEHLER beim Zugriff auf Endpoint {endpoint}: {e}")
        if hasattr(e.response, 'text'): # Antworttext ausgeben, falls vorhanden, zur Fehlersuche
            print("  Antwort-Text (zur Fehlersuche):", e.response.text)
    except json.JSONDecodeError as e:
        print(f"  FEHLER: Ungültige JSON-Antwort von {endpoint}: {e}")
        if hasattr(response, 'text'): # Antworttext ausgeben, falls response definiert und text vorhanden
            print("  Antwort-Text (zur Fehlersuche):", response.text)
    except AssertionError as e:
        print(f"  FEHLER: Assertion Fehler: {e}")

if __name__ == "__main__":
    print("Starte API Tests für Visionären Virenschutz Web-UI (JSON APIs)\n")
    print(f"Basis URL für Tests: {BASE_URL}\n")

    # --- Test für / (Dashboard) ---
    print("--- Testgruppe: Dashboard API ---")
    teste_api_endpoint(
        '/api/dashboard_daten', # Korrektur: Teste API Endpoint
        erwartete_keys=[
            "cpu_auslastung",
            "speicher_auslastung",
            "echtzeit_schutz_aktiv",
            "letzte_pruefung_zeit",
            "anzahl_bedrohungen",
            "blockchain_aktiviert",
            "ki_aktiviert", # ki_aktiviert hinzugefügt
            "virenschutz_version",
            "aktualisierungs_intervall"
        ]
    )

    # --- Test für /logs (Log-Einträge) ---
    print("--- Testgruppe: Log API ---")
    teste_api_endpoint(
        '/api/log_daten', # Korrektur: Teste API Endpoint
        erwartete_keys=[
            "log_eintraege",
            "aktualisierungs_intervall"
        ]
    )

    # --- Test für /config (Konfiguration) ---
    print("--- Testgruppe: Konfigurations API ---")
    teste_api_endpoint(
        '/api/config_daten', # Korrektur: Teste API Endpoint
        erwartete_keys=[
            "konfiguration",
            "aktualisierungs_intervall"
        ]
    )

    print("\nAlle API Tests abgeschlossen.")
    print("Bitte überprüfen Sie die Ausgaben auf 'FEHLER', um eventuelle Probleme zu identifizieren.")
