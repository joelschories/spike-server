## 0.7.0
- Update-Check: Spike schaut zweimal am Tag nach, ob es eine neuere Version gibt (es wird nur die öffentliche
  Versionsdatei aus dem GitHub-Projekt abgerufen). Die App zeigt dann einen Hinweis mit der passenden Anleitung
  für Home Assistant, Raspberry Pi OS oder Docker.
- Kompatibilität: Server und App melden sich gegenseitig, welche Version sie mindestens brauchen.

## 0.6.2
- „Zuletzt online“ stimmt jetzt: Spike merkt sich, wann ein Gerät zuletzt verbunden war, statt immer die
  aktuelle Uhrzeit zu melden.

## 0.6.1
- Der Spike-Wächter heißt jetzt Spike Guard.

## 0.6.0
- Strenger Modus (optional): Neue Geräte kommen erst ins Internet, wenn du sie in der App freigibst. Geräte mit
  der Spike-App sind automatisch freigegeben; beim Einschalten lassen sich alle vorhandenen Geräte übernehmen.
  Spike prüft dann alle 10 Sekunden auf neue Geräte.
- Geräte, die gerade offline sind, lassen sich jetzt sperren oder freigeben: Spike merkt sich den Wunsch und setzt
  ihn um, sobald sich das Gerät wieder verbindet (die FRITZ!Box kann nur verbundene Geräte sperren).
- Neuer Endpunkt POST /api/security {strictMode, trustExisting}; Geräte melden blockPending und autoBlocked.

## 0.5.2
- Jugendschutz deutlich stärker: zusätzlich zur HaGeZi-Liste die OISD-NSFW-Liste (zusammen rund 500.000 Seiten
  statt 81.000).
- Ist der Jugendschutz an, zeigen Google, Bing und DuckDuckGo automatisch nur jugendfreie Ergebnisse
  (SafeSearch). Sonst kam man über die Bildersuche an solche Inhalte, ohne eine Seite aufzurufen.

## 0.5.1
- Wichtig: „Gast-WLAN unsichtbar“ entfernt. Die FRITZ!Box kennt dafür nur einen gemeinsamen Schalter und hat
  dabei auch das Heimnetz versteckt. Spike macht nach dem Update einmalig alle WLAN-Namen wieder sichtbar.
- Schutzfilter zuverlässiger: Der DNS-Server startet vor allem anderen. Antwortet der DNS-Anbieter nicht sofort,
  fragt Spike nach 1,5 Sekunden mehrere Ausweichserver gleichzeitig (vorher bis zu 12 Sekunden Warten).
  Ist das Internet kurz weg, liefert Spike die letzte bekannte Antwort statt eines Fehlers.
- Antworten tragen immer exakt die Frage des Geräts (auch Groß-/Kleinschreibung) und richten sich nach der
  Paketgröße, die das Gerät annimmt.
- Zusätzlich blockiert: Werbe-Server großer deutscher Nachrichtenseiten (u. a. asadcdn.com, html-load.com).
- Wächter: Spike fragt den DHCP-Server der FRITZ!Box, welchen DNS-Server sie verteilt, und erkennt so sicher,
  ob die Sicht pro Gerät eingerichtet ist. Die Sicht pro Gerät ist ein optionales Extra.

## 0.5.0
- Schutzfilter deutlich stärker: HaGeZi Pro statt Multi (strenger Modus: Pro++, blockiert auch Google-Werbelinks)
  und Threat Intelligence Medium statt Mini. Zusammen rund 500.000 Einträge.
- Neu: „Umgehung verhindern“ (standardmäßig an). Sperrt fremde DNS-over-HTTPS-Dienste, Proxys und iCloud Privat-Relay
  im Heimnetz, damit Browser und Apps nicht am Filter vorbei surfen. Fernzugänge wie Tailscale bleiben erreichbar.
- Neu: Kategorien „Hersteller-Tracking“ (Smart-TVs, Handys, Windows, Alexa) und „Soziale Netzwerke“.
- Wächter arbeitet sofort: Auch wenn nur die FRITZ!Box bei Spike nachfragt, meldet er gefährliche Seiten und
  Schadsoftware-Muster für das ganze Netz. Für die Sicht pro Gerät erkennt Spike jetzt selbst, ob die FRITZ!Box
  Spike als „Lokalen DNS-Server“ verteilt.
- Mehrere unbekannte Geräte auf einmal sperren (eine Bestätigung an der FRITZ!Box für alle).

## 0.4.0
- Spike-Wächter: lernt aus den DNS-Anfragen das normale Verhalten jedes Geräts (lokal, ohne Cloud) und meldet
  Hinweise auf Schadsoftware (zufällig erzeugte Domains), wiederholte Aufrufe gefährlicher Seiten,
  ungewöhnlich viele Anfragen und neue Ziele bei Kameras, Steckdosen, Lampen und Saugrobotern.
- Hinweise lassen sich als „in Ordnung“ markieren (Spike lernt dazu), ausblenden oder das Gerät direkt sperren.
  Optional sperrt Spike bei Hinweisen auf Schadsoftware automatisch.
- Systemzustand: verschlüsselte Namensauflösung, Router-Verbindung und Blocklisten werden laufend geprüft.
- Empfehlungen lassen sich verwerfen und zählen dann nicht mehr in den Score, bis sich die Lage ändert.

## 0.3.2
- Eigenes Icon und Logo in Home Assistant.
- Gast-WLAN direkt aus der App einrichten (Name, sicheres Passwort) und unsichtbar schalten.
- Spike hält ein aktuelles Gesamtbild bereit und prüft auch ohne geöffnete App alle 30 Sekunden
  auf neue Geräte. Die App kann so alle paar Sekunden aktualisieren, ohne die FRITZ!Box zu belasten.

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
