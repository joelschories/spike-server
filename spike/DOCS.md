# Spike

Spike ist der Server für die Spike-App auf iPhone und Mac. Er läuft hier nur als Container
auf deinem Raspberry und hat nichts mit Home Assistant zu tun.

## Einrichtung

1. Add-on installieren und starten.
2. Spike-App öffnen und dem Einrichtungs-Guide folgen. Die App findet Spike automatisch.
3. In der App deinen Router verbinden.

## Schutzfilter (Werbeblocker)

Spike enthält einen DNS-Server, der Werbung, Tracker und gefährliche Seiten für alle Geräte blockiert.
Er nutzt Port 53 auf deinem Raspberry. Läuft dort schon AdGuard Home oder Pi-hole, meldet die App das.

Damit der Filter wirkt, trägst du Spike einmal als DNS-Server in der FRITZ!Box ein
(Internet › Zugangsdaten › DNS-Server). Die App zeigt dir die genauen Schritte und die Adresse.
Home Assistant läuft dabei unverändert weiter.

## Sicherheit

- Die Verbindung zwischen App und Spike ist verschlüsselt (TLS). Die App merkt sich das Zertifikat
  beim ersten Kontakt und lehnt danach jedes andere ab.
- Das erste Gerät verbindet sich direkt. Jedes weitere muss auf einem bereits verbundenen Gerät erlaubt werden.
- Die Router-Zugangsdaten liegen nur in diesem Add-on, nicht in Home Assistant.
- Spike öffnet keine Ports ins Internet.

## Notfall

Wenn kein verbundenes Gerät mehr vorhanden ist: Option **Kopplungen zurücksetzen** aktivieren,
Add-on neu starten, verbinden, Option wieder ausschalten.
