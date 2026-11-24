# Spike

Spike ist der Server für die Spike-App auf iPhone und Mac. Er läuft hier nur als Container
auf deinem Raspberry und hat nichts mit Home Assistant zu tun.

## Einrichtung

1. Add-on installieren und starten.
2. Spike-App öffnen und dem Einrichtungs-Guide folgen. Die App findet Spike automatisch.
3. In der App deinen Router verbinden.

## Sicherheit

- Die Verbindung zwischen App und Spike ist verschlüsselt (TLS). Die App merkt sich das Zertifikat
  beim ersten Kontakt und lehnt danach jedes andere ab.
- Das erste Gerät verbindet sich direkt. Jedes weitere muss auf einem bereits verbundenen Gerät erlaubt werden.
- Die Router-Zugangsdaten liegen nur in diesem Add-on, nicht in Home Assistant.
- Spike öffnet keine Ports ins Internet.

## Notfall

Wenn kein verbundenes Gerät mehr vorhanden ist: Option **Kopplungen zurücksetzen** aktivieren,
Add-on neu starten, verbinden, Option wieder ausschalten.
