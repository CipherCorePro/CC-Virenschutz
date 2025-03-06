# --- Inhalt von: logging_utils.py ---
import logging

def initialisiere_logging(log_level_str, log_datei_pfad):
    """Initialisiert das Logging-System."""
    log_level_mapping = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    log_level = log_level_mapping.get(log_level_str.upper(), logging.INFO) # Standardmäßig INFO

    logging.basicConfig(
        filename=log_datei_pfad,
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s - %(daten)s', # Daten im Format einfügen
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    protokolliere_ereignis_global("info", f"Logging initialisiert. Log-Level: {logging.getLevelName(log_level)}, Log-Datei: '{log_datei_pfad}'")

def protokolliere_ereignis_global(typ, meldung, daten=None):
    """Globale Funktion zum Protokollieren von Ereignissen."""
    if typ == "info":
        logging.info(meldung, extra={'daten': daten} if daten else {})
    elif typ == "warnung":
        logging.warning(meldung, extra={'daten': daten} if daten else {})
    elif typ == "fehler":
        logging.error(meldung, extra={'daten': daten} if daten else {})
    elif typ == "debug":
        logging.debug(meldung, extra={'daten': daten} if daten else {})
    elif typ == "aktion":
        logging.info(f"AKTION: {meldung}", extra={'daten': daten} if daten else {}) # Kennzeichnung für Aktionen im Log
    else:
        logging.info(f"Unbekannter Ereignistyp '{typ}': {meldung}", extra={'daten': daten} if daten else {})
