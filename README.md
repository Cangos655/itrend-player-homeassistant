# iTrend Player für Home Assistant / for Home Assistant

[Deutsch](#deutsch) | [English](#english)

> Status: **Stufe 1 (Version 0.1.0)**: Kopplung, Zustand empfangen, Entitäten. Steuerung (Play/Pause/…) folgt später (Stufe 3) und braucht eine eigene Sicherheitsprüfung.
> Status: **Stage 1 (version 0.1.0)**: pairing, receiving state, entities. Control (play/pause/…) comes later (stage 3) after a separate security review.

---

## Deutsch

Diese Integration zeigt in Home Assistant, was iTrend Player auf Ihrem Fernseher gerade tut (Android TV / Fire TV und Samsung/Tizen). Die App liefert keine Inhalte; die Integration empfängt nur den Zustand der App, lokal in Ihrem Netz. Es gibt keine Cloud und keine Weitergabe an iTrend24 oder Dritte.

### Installation über HACS (benutzerdefiniertes Repository)

1. HACS öffnen, Menü (drei Punkte) > **Benutzerdefinierte Repositories**.
2. Adresse `https://github.com/Cangos655/itrend-player-homeassistant` eintragen, Kategorie **Integration**, hinzufügen.
3. **iTrend Player** in HACS suchen, herunterladen, Home Assistant neu starten.

Ohne HACS: den Ordner `custom_components/itrend_player` in das Verzeichnis `config/custom_components/` Ihrer Home-Assistant-Installation kopieren und neu starten.

### Einrichtung

1. **Einstellungen > Geräte & Dienste > Integration hinzufügen > iTrend Player.**
2. Home Assistant zeigt einen **sechsstelligen Code** und die **Adresse** Ihrer Home-Assistant-Instanz an. Der Code gilt 5 Minuten, nur einmal und erlaubt höchstens 3 Fehlversuche.
3. In der App am Fernseher: **Einstellungen > Home Assistant**, Adresse und Code eingeben, die Hinweise zur Übertragung bestätigen. Sobald die App gekoppelt hat, legt Home Assistant das Gerät an (Name aus der App).
4. Mehrere Fernseher: Schritte wiederholen; jeder Fernseher hat ein eigenes Gerät und ein eigenes Geheimnis.

**Kopplung erneuern:** Hat die App die Kopplung beendet oder ist sie ungültig, bietet Home Assistant am Eintrag **Neu konfigurieren / Kopplung erneuern** an. Entitäten und Verlauf bleiben erhalten.

**Löschen:** Gerät oder Eintrag in Home Assistant löschen entfernt Webhook und Schlüssel. Die App meldet danach „Kopplung erneuern“ und kann getrennt werden.

**Netzwerkzugriff (Option):** Normalerweise nimmt die Integration nur Meldungen aus dem Heimnetz an. Erreicht der Fernseher Home Assistant über einen Domainnamen, Proxy oder Hairpin-NAT (Absender erscheint als öffentliche Adresse), beantwortet Home Assistant die Meldungen mit leerem Body; die App zeigt „nicht bestätigt (`empty_body`)“ und „App aktiv“ bleibt aus. Dann am Eintrag **Konfigurieren > Auch Anfragen von außerhalb des Heimnetzes erlauben** einschalten. Die Sicherheit ändert sich kaum, da jede Meldung signiert ist und Sequenznummern und Rate-Limits weiter gelten.

### Entitäten (je Fernseher)

| Entität | Inhalt |
|---|---|
| Media-Player | spielt, Pause, Puffern, Leerlauf, aus, nicht verfügbar; Titel, Sender, Typ, Serie/Staffel/Folge, Dauer, Position. Keine Steuerfunktionen in Stufe 1. |
| Sensor App-Version | Diagnose |
| Sensor Abo-Ablauf | Zeitstempel (Beginn des gemeldeten Tages), nur wenn die App ihn freigibt |
| Sensor Verbindungen | aktive Verbindungen, Attribut `connections_max` |
| Sensor Erlaubte Verbindungen | `connections_max` laut Anbieter (kommt auch ohne aktive Verbindungen) |
| Binär-Sensor App aktiv | an, solange die App sendet |

Ereignisse auf dem HA-Bus: `itrend_player_event` mit `type` = `playback_started`, `playback_stopped` (`reason`), `channel_changed`, `trailer_opened`, dazu `device_id`, `entry_id` und, falls freigegeben, `media`.

Nach etwa **90 Sekunden** ohne Lebenszeichen (drei verpasste Herzschläge) werden die Entitäten „nicht verfügbar“. Das ist von „Fernseher aus“ nicht zu unterscheiden. Beendet die App ordentlich, wechselt der Media-Player sofort auf „aus“.

### Datenschutz und Sicherheit

- Gesendet wird nur, was Sie in der App freigeben (nur Status, Titel und Sender, Abo-Ablauf). Standard ist: nichts. Zugangsdaten, Playlist- und Anbieteradressen werden nie gesendet.
- Die Übertragung erfolgt per **signiertem Webhook** (HMAC-SHA-256, Schlüssel wird nie übertragen). Bei `http` im Heimnetz ist der Inhalt **nicht verschlüsselt**: Titel sind im selben Netz mitlesbar. Wenn möglich `https` verwenden.
- Schlüssel liegen im Speicher der Konfigurationseinträge von Home Assistant. Titel und Sender werden nicht dauerhaft gespeichert; die Integration nimmt Titelattribute vom Recorder-Verlauf aus. Ereignisse (`itrend_player_event`) können Titel enthalten; Automationen, Logbuch und Protokolle sind Ihre Sache.
- Veröffentlichen Sie keine Home-Assistant-Logs: Home Assistant selbst schreibt Webhook-Adressen unregistrierter Webhooks in das Protokoll.
- Wird ein Kopplungscode gesperrt, ohne dass Sie ihn falsch eingegeben haben, versucht jemand im Netz zu stören. Erzeugen Sie einen neuen Code.

### Protokoll

Das Protokoll (Kopplung per SRP-6a, Signatur, Testvektoren) ist in [`docs/protocol/PROTOCOL.md`](docs/protocol/PROTOCOL.md) beschrieben; `vectors.json` und `reference.py` liegen daneben. Entscheidungen der Umsetzung: [`docs/DECISIONS.md`](docs/DECISIONS.md).

### Entwicklung

```bash
python3.13 -m venv .venv && . .venv/bin/activate
pip install -r requirements_test.txt
pytest
```

---

## English

This integration shows in Home Assistant what iTrend Player is doing on your TV (Android TV / Fire TV and Samsung/Tizen). The app provides no content; the integration only receives the app's state, locally on your network. There is no cloud and nothing is sent to iTrend24 or third parties.

### Installation via HACS (custom repository)

1. Open HACS, menu (three dots) > **Custom repositories**.
2. Add `https://github.com/Cangos655/itrend-player-homeassistant`, category **Integration**.
3. Search **iTrend Player** in HACS, download it, restart Home Assistant.

Without HACS: copy the folder `custom_components/itrend_player` into `config/custom_components/` of your Home Assistant installation and restart.

### Setup

1. **Settings > Devices & services > Add integration > iTrend Player.**
2. Home Assistant shows a **six-digit code** and the **address** of your Home Assistant instance. The code is valid for 5 minutes, works once, and allows at most 3 wrong attempts.
3. In the app on the TV: **Settings > Home Assistant**, enter address and code and confirm the transmission notes. As soon as the app has paired, Home Assistant creates the device (name taken from the app).
4. Several TVs: repeat; each TV gets its own device and its own secret.

**Renew pairing:** if the app ended the pairing or it is no longer valid, Home Assistant offers **Reconfigure / Renew pairing** on the entry. Entities and history are kept.

**Delete:** deleting the device or entry removes the webhook and the key. The app will then show "renew pairing" and can be disconnected.

**Network access (option):** By default the integration only accepts messages from your home network. If the TV reaches Home Assistant through a domain name, proxy or hairpin NAT (the sender appears as a public address), Home Assistant answers with an empty body; the app shows "unconfirmed (`empty_body`)" and "App active" stays off. Then enable **Configure > Also allow requests from outside the home network** on the entry. Security hardly changes because every message is signed and sequence numbers and rate limits still apply.

### Entities (per TV)

| Entity | Content |
|---|---|
| Media player | playing, paused, buffering, idle, off, unavailable; title, channel, type, series/season/episode, duration, position. No control features in stage 1. |
| App version sensor | diagnostic |
| Subscription expiry sensor | timestamp (start of the reported day), only if the app shares it |
| Connections sensor | active connections, attribute `connections_max` |
| Allowed connections sensor | `connections_max` as reported by the provider (also available without active connections) |
| App active binary sensor | on while the app is sending |

Events on the HA bus: `itrend_player_event` with `type` = `playback_started`, `playback_stopped` (`reason`), `channel_changed`, `trailer_opened`, plus `device_id`, `entry_id` and, if shared, `media`.

After about **90 seconds** without a sign of life (three missed heartbeats) entities become "unavailable". This cannot be distinguished from "TV off". If the app quits cleanly, the media player switches to "off" immediately.

### Privacy and security

- Only what you allow in the app is sent (status only, titles and channels, subscription expiry). The default is nothing. Credentials, playlist and provider addresses are never sent.
- Messages are sent as a **signed webhook** (HMAC-SHA-256; the key is never transmitted). Over `http` in your home network the content is **not encrypted**: titles can be read on the same network. Use `https` where possible.
- Keys are kept in Home Assistant's config entry storage. Titles and channels are not stored permanently; the integration excludes title attributes from the recorder history. Events (`itrend_player_event`) may contain titles; automations, logbook and logs are your responsibility.
- Do not publish Home Assistant logs: Home Assistant itself writes webhook addresses of unregistered webhooks to the log.
- If a pairing code gets locked without you having entered it wrongly, someone on your network is trying to interfere. Create a new code.

### Protocol

The protocol (pairing with SRP-6a, signatures, test vectors) is described in [`docs/protocol/PROTOCOL.md`](docs/protocol/PROTOCOL.md); `vectors.json` and `reference.py` are next to it. Implementation decisions: [`docs/DECISIONS.md`](docs/DECISIONS.md).

### Development

```bash
python3.13 -m venv .venv && . .venv/bin/activate
pip install -r requirements_test.txt
pytest
```

License: MIT.
