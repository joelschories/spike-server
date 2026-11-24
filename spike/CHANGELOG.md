## 0.3.1
- Router-Abfragen gehen nacheinander statt gleichzeitig hinaus. Parallele Anmeldungen hat die FRITZ!Box
  abgelehnt, dadurch blieb die Übersicht leer.
- Klappt die Anmeldung am Router nicht, meldet Spike das jetzt klar, statt leere Daten zu liefern.
- Schutzfilter: Ist Port 53 auf einer internen Adresse belegt (z. B. unter Home Assistant OS), lauscht Spike
  direkt auf seiner Heimnetz-Adresse.
- Spike startet nach einem unerwarteten Fehler von selbst neu.
- Neu: Diagnose (Version, Schutzfilter, letzte Protokollzeilen) für die Fehlersuche in der App.

## 0.3.0
- Schutzfilter: eingebauter DNS-Server blockiert Werbung, Tracker, Betrug und Schadsoftware für das ganze
  Heimnetz. Optional Glücksspiel, Erwachseneninhalte und SafeSearch. Weiterleitung verschlüsselt (DNS over HTTPS).
- Änderungen, die die FRITZ!Box am Gerät bestätigt haben möchte (Zwei-Faktor), funktionieren jetzt:
  die App zeigt an, welche Taste du drücken musst.
- WPS lässt sich wirklich abschalten (vorher falscher Aufruf), UPnP behält den Mediaserver-Zustand.
- Verständliche Fehlermeldungen, z. B. wenn dem FRITZ!Box-Benutzer Rechte fehlen.
- Im Home-Assistant-Add-on liegen die Daten jetzt sicher im Add-on-Speicher (vorher im Container,
  dadurch gingen Kopplung und Router-Zugang bei einem Update verloren). Einmalig neu verbinden.
- Neu: Internetstatus, Portfreigaben im Detail, Gerät aufwecken (Wake-on-LAN), Router neu starten,
  mehrere Geräte auf einmal als vertraut markieren.

## 0.2.0
- Läuft unabhängig von Home Assistant (keine Seitenleiste, keine Einstellungen in Home Assistant).
- Verschlüsselte Verbindung (TLS) mit Zertifikats-Pinning in der App.
- Kopplung: erstes Gerät direkt, weitere Geräte nur nach Bestätigung.
- Router-Zugangsdaten werden in der App eingegeben.

## 0.1.0
- Erste Version.
