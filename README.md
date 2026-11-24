# Spike-Server

Server für die Spike-App (Heimnetz-Sicherheit für iPhone und Mac). Open Source, MIT-Lizenz.

## Installation

**Raspberry mit Raspberry Pi OS** (eigenständiges Programm, startet automatisch):

```bash
curl -fsSL https://raw.githubusercontent.com/joelschories/spike-server/main/install.sh | sudo bash
```

**Raspberry mit Home Assistant OS:** Diese Adresse in Home Assistant als Add-on-Paketquelle hinzufügen
und das Add-on „Spike“ installieren. Spike läuft dort nur als Container und ist nicht in Home Assistant eingebunden.

**Docker:**

```bash
docker run -d --name spike --restart unless-stopped --network host -v spike-data:/data ghcr.io/joelschories/spike-server:latest
```

Danach die Spike-App öffnen: Sie findet den Server automatisch, verbindet sich und fragt nach den Router-Zugangsdaten.

## Sicherheit

- TLS mit eigenem Zertifikat; die App pinnt den Fingerabdruck beim ersten Kontakt.
- Erstes Gerät verbindet sich direkt, weitere nur nach Bestätigung auf einem verbundenen Gerät.
- Keine Ports ins Internet, Router-Zugangsdaten nur im Datenordner (Rechte 600).
- Notfall: `sudo spike-reset-pairing` (Raspberry Pi OS) bzw. Add-on-Option „Kopplungen zurücksetzen“.
