# Spike

Spike überwacht dein Heimnetz und verbindet sich mit der Spike-App auf iPhone und Mac.

## Einrichtung

1. Lege in deiner FRITZ!Box einen eigenen Benutzer für Spike an
   (*System › FRITZ!Box-Benutzer › Benutzer hinzufügen*, Recht „FRITZ!Box Einstellungen“).
2. Trage Adresse, Benutzer und Passwort im Reiter **Konfiguration** dieses Add-ons ein.
   Ohne Zugangsdaten läuft Spike im Demo-Modus mit Beispieldaten.
3. Starte das Add-on und öffne **Spike** in der Seitenleiste. Dort steht dein Kopplungscode.
4. Gib den Code in der Spike-App ein.

## Sicherheit

- Spike öffnet keine Ports nach außen. Die App spricht nur im Heimnetz mit dem Server.
- Kopplungscodes gelten 10 Minuten und nur einmal; nach mehreren Fehlversuchen sperrt Spike kurz.
- Der Kopplungscode ist nur in Home Assistant sichtbar, nicht im restlichen Netz.
