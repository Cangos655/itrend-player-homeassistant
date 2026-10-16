# iTrend Player for Home Assistant / für Home Assistant

[English](#english) | [Deutsch](#deutsch)

> Status: **Version 0.3.0**: secure pairing, receiving state (title, series, cover/channel logo, playlist status, subscription expiry, connections), sensors and events. Control (play/pause/…) comes later (stage 3) after a separate security review.
> Status: **Version 0.3.0**: sichere Kopplung, Zustand empfangen (Titel, Serie, Cover/Senderlogo, Playlist-Status, Abo-Ablauf, Verbindungen), Sensoren und Ereignisse. Steuerung (Play/Pause/…) folgt später (Stufe 3) und braucht eine eigene Sicherheitsprüfung.

---
## English

This integration shows in Home Assistant what iTrend Player is doing on your TV (Android TV / Fire TV and Samsung/Tizen). The app provides no content; the integration only receives the app's state, locally on your network. There is no cloud and nothing is sent to iTrend24 or third parties.

The icon appears from Home Assistant 2026.3 on; older versions show the default icon.

**What the integration shows:**
- Media player with state, title, series, season, episode, duration and position, plus cover or channel logo (when allowed)
- "Now playing" sensor (title as text), app version, subscription expiry, allowed and active connections
- Playlist status: last refresh, number of channels, movies, series, kind of error
- "App active" and events (`playback_started`, `playback_stopped`, `channel_changed`, `trailer_opened`, `playlist_refreshed`, `playlist_failed`)
- Pairing by code (SRP-6a), every message signed; by default the app sends nothing, you switch on each kind of data separately; content from categories locked with the PIN is never sent

### Installation via HACS (custom repository)

1. Open HACS, menu (three dots) > **Custom repositories**.
2. Add `https://github.com/Cangos655/itrend-player-homeassistant`, category **Integration**.
3. Search **iTrend Player** in HACS, download it, restart Home Assistant.

Without HACS: copy the folder `custom_components/itrend_player` into `config/custom_components/` of your Home Assistant installation and restart.

### Setup

1. **Settings > Devices & services > Add integration > iTrend Player.**
2. Home Assistant shows a **six-digit code** and the **address** of your Home Assistant instance. The code is valid for 5 minutes, works once, and allows at most 3 wrong attempts.
3. In the app on the TV: **Settings > Home Assistant**, enter address and code and confirm the transmission notes. As soon as the app has paired, Home Assistant asks about network access (see below) and then creates the device (name taken from the app).
4. Several TVs: repeat; each TV gets its own device and its own secret.

**Renew pairing:** if the app ended the pairing or it is no longer valid, Home Assistant offers **Reconfigure / Renew pairing** on the entry. Entities and history are kept.

**Delete:** deleting the device or entry removes the webhook and the key. The app will then show "renew pairing" and can be disconnected.

**Messages do not arrive (`empty_body`)?** If the app shows "unconfirmed (`empty_body`)" and "App active" stays off, the TV reaches Home Assistant through a domain, proxy, Nabu Casa or hairpin NAT and Home Assistant drops messages from outside the home network. After pairing, the setup dialog asks for the option **Also allow requests from outside the home network** (preset to on if pairing came from outside or another entry uses the option). Change it later via entry > gear (Configure). Messages are signed either way.

**Network access (option):** By default the integration only accepts messages from your home network. If the TV reaches Home Assistant through a domain name, proxy or hairpin NAT (the sender appears as a public address), Home Assistant answers with an empty body; the app shows "unconfirmed (`empty_body`)" and "App active" stays off. Then enable **Configure > Also allow requests from outside the home network** on the entry. Security hardly changes because every message is signed and sequence numbers and rate limits still apply.

### Entities (per TV)

| Entity | Content |
|---|---|
| Media player | playing, paused, buffering, idle, off, unavailable; title, channel, type, series/season/episode, duration, position. No control features in stage 1. |
| Now playing sensor | title as text: movie = title, episode = "Series, Season S, Episode E", live = channel; otherwise "–". **Note:** Home Assistant stores the state in its history; to exclude it set `recorder: exclude: entity_globs: [sensor.*_now_playing]` (check the entity ID). |
| App version sensor | diagnostic |
| Subscription expiry sensor | timestamp (start of the reported day), only if the app shares it |
| Connections sensor | active connections, attribute `connections_max` |
| Allowed connections sensor | `connections_max` as reported by the provider (also available without active connections) |
| App active binary sensor | on while the app is sending |

Events on the HA bus: `itrend_player_event` with `type` = `playback_started`, `playback_stopped` (`reason`), `channel_changed`, `trailer_opened`, plus `device_id`, `entry_id` and, if shared, `media`.

After about **90 seconds** without a sign of life (three missed heartbeats) entities become "unavailable". This cannot be distinguished from "TV off". If the app quits cleanly, the media player switches to "off" immediately.

**Artwork and playlist status (since 0.2.0):** If the app shares artwork, the media player uses the reported image address as the entity picture. Your browser or the Home Assistant app loads the image directly from that address (the image host will see those requests); Home Assistant and the integration never fetch anything server-side. The address is checked strictly (no private/local addresses, no credentials, no stream patterns). With playlist sharing, the sensors "Playlist updated", "Channels", "Movies", "Series" (diagnostic) and "Playlist error" show the state of the loaded playlist (numbers and error type only, no addresses or names), plus the events `playlist_refreshed` and `playlist_failed` (with `error`). Image addresses and titles are not kept in the recorder history.

### Privacy and security

- Only what you allow in the app is sent (status only, titles and channels, subscription expiry). The default is nothing. Credentials, playlist and provider addresses are never sent.
- Messages are sent as a **signed webhook** (HMAC-SHA-256; the key is never transmitted). Over `http` in your home network the content is **not encrypted**: titles can be read on the same network. Use `https` where possible.
- Keys are kept in Home Assistant's config entry storage. The integration itself stores no titles or channels; it excludes the media player's title attributes from the recorder history. **Exception:** the state of the "Now playing" sensor is the title, and the Home Assistant recorder stores it in the history. If you do not want that, exclude the sensor with `recorder: exclude` (example next to the sensor description above) or disable it. Events (`itrend_player_event`) may contain titles; automations, logbook and logs are your responsibility.
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

---

## Deutsch

Diese Integration zeigt in Home Assistant, was iTrend Player auf Ihrem Fernseher gerade tut (Android TV / Fire TV und Samsung/Tizen). Die App liefert keine Inhalte; die Integration empfängt nur den Zustand der App, lokal in Ihrem Netz. Es gibt keine Cloud und keine Weitergabe an iTrend24 oder Dritte.

Das Symbol erscheint ab Home Assistant 2026.3, ältere Versionen zeigen das Standard-Icon.

**Was die Integration zeigt:**
- Media-Player mit Zustand, Titel, Serie, Staffel, Folge, Dauer und Position, dazu Cover oder Senderlogo (wenn freigegeben)
- Sensor „Läuft gerade“ (Titel als Text), App-Version, Abo-Ablauf, erlaubte und aktive Verbindungen
- Playlist-Status: letzte Aktualisierung, Anzahl Sender, Filme, Serien, Fehlerart
- „App aktiv“ und Ereignisse (`playback_started`, `playback_stopped`, `channel_changed`, `trailer_opened`, `playlist_refreshed`, `playlist_failed`)
- Kopplung per Code (SRP-6a), jede Meldung signiert; standardmäßig sendet die App nichts, jede Datenart schaltest du einzeln ein; Inhalte aus mit PIN gesperrten Kategorien werden nie gesendet

### Installation über HACS (benutzerdefiniertes Repository)

1. HACS öffnen, Menü (drei Punkte) > **Benutzerdefinierte Repositories**.
2. Adresse `https://github.com/Cangos655/itrend-player-homeassistant` eintragen, Kategorie **Integration**, hinzufügen.
3. **iTrend Player** in HACS suchen, herunterladen, Home Assistant neu starten.

Ohne HACS: den Ordner `custom_components/itrend_player` in das Verzeichnis `config/custom_components/` Ihrer Home-Assistant-Installation kopieren und neu starten.

### Einrichtung

1. **Einstellungen > Geräte & Dienste > Integration hinzufügen > iTrend Player.**
2. Home Assistant zeigt einen **sechsstelligen Code** und die **Adresse** Ihrer Home-Assistant-Instanz an. Der Code gilt 5 Minuten, nur einmal und erlaubt höchstens 3 Fehlversuche.
3. In der App am Fernseher: **Einstellungen > Home Assistant**, Adresse und Code eingeben, die Hinweise zur Übertragung bestätigen. Sobald die App gekoppelt hat, fragt Home Assistant nach dem Netzwerkzugriff (siehe unten) und legt dann das Gerät an (Name aus der App).
4. Mehrere Fernseher: Schritte wiederholen; jeder Fernseher hat ein eigenes Gerät und ein eigenes Geheimnis.

**Kopplung erneuern:** Hat die App die Kopplung beendet oder ist sie ungültig, bietet Home Assistant am Eintrag **Neu konfigurieren / Kopplung erneuern** an. Entitäten und Verlauf bleiben erhalten.

**Löschen:** Gerät oder Eintrag in Home Assistant löschen entfernt Webhook und Schlüssel. Die App meldet danach „Kopplung erneuern“ und kann getrennt werden.

**Meldungen kommen nicht an (`empty_body`)?** Zeigt die App „nicht bestätigt (`empty_body`)“ und bleibt „App aktiv“ aus, erreicht der Fernseher Home Assistant über Domain, Proxy, Nabu Casa oder Hairpin-NAT, und Home Assistant verwirft Meldungen von außerhalb des Heimnetzes. Der Einrichtungsdialog fragt nach der Kopplung nach der Option **Auch Anfragen von außerhalb des Heimnetzes erlauben** (vorbelegt „an“, wenn die Kopplung von außen kam oder ein anderer Eintrag die Option nutzt). Nachträglich ändern: Eintrag > Zahnrad (Konfigurieren). Die Meldungen sind in jedem Fall signiert.

**Netzwerkzugriff (Option):** Normalerweise nimmt die Integration nur Meldungen aus dem Heimnetz an. Erreicht der Fernseher Home Assistant über einen Domainnamen, Proxy oder Hairpin-NAT (Absender erscheint als öffentliche Adresse), beantwortet Home Assistant die Meldungen mit leerem Body; die App zeigt „nicht bestätigt (`empty_body`)“ und „App aktiv“ bleibt aus. Dann am Eintrag **Konfigurieren > Auch Anfragen von außerhalb des Heimnetzes erlauben** einschalten. Die Sicherheit ändert sich kaum, da jede Meldung signiert ist und Sequenznummern und Rate-Limits weiter gelten.

### Entitäten (je Fernseher)

| Entität | Inhalt |
|---|---|
| Media-Player | spielt, Pause, Puffern, Leerlauf, aus, nicht verfügbar; Titel, Sender, Typ, Serie/Staffel/Folge, Dauer, Position. Keine Steuerfunktionen in Stufe 1. |
| Sensor Läuft gerade | Titel als Text: Film = Titel, Folge = „Serie, Staffel S, Folge E“, Live = Sender; sonst „–“. **Hinweis:** Home Assistant speichert den Zustand im Verlauf; zum Ausschließen `recorder: exclude: entity_globs: [sensor.*_now_playing]` (Entitäts-ID prüfen) in der Konfiguration setzen. |
| Sensor App-Version | Diagnose |
| Sensor Abo-Ablauf | Zeitstempel (Beginn des gemeldeten Tages), nur wenn die App ihn freigibt |
| Sensor Verbindungen | aktive Verbindungen, Attribut `connections_max` |
| Sensor Erlaubte Verbindungen | `connections_max` laut Anbieter (kommt auch ohne aktive Verbindungen) |
| Binär-Sensor App aktiv | an, solange die App sendet |

Ereignisse auf dem HA-Bus: `itrend_player_event` mit `type` = `playback_started`, `playback_stopped` (`reason`), `channel_changed`, `trailer_opened`, dazu `device_id`, `entry_id` und, falls freigegeben, `media`.

Nach etwa **90 Sekunden** ohne Lebenszeichen (drei verpasste Herzschläge) werden die Entitäten „nicht verfügbar“. Das ist von „Fernseher aus“ nicht zu unterscheiden. Beendet die App ordentlich, wechselt der Media-Player sofort auf „aus“.

**Cover und Playlist-Status (ab 0.2.0):** Gibt die App Cover/Senderlogo frei, setzt der Media-Player die gemeldete Bild-Adresse als Entitätsbild. Das Bild lädt Ihr Browser bzw. die Home-Assistant-App direkt von dieser Adresse (Bilderserver des Anbieters sehen dann Ihre Zugriffe); Home Assistant und die Integration laden nichts serverseitig. Die Adresse wird streng geprüft (keine privaten/lokalen Adressen, keine Zugangsdaten, keine Stream-Muster). Mit Freigabe der Playlist zeigen Sensoren „Playlist aktualisiert“, „Sender“, „Filme“, „Serien“ (Diagnose) und „Playlist-Fehler“ den Zustand der geladenen Playlist (nur Zahlen und Fehlerart, keine Adressen oder Namen); dazu die Ereignisse `playlist_refreshed` und `playlist_failed` (mit `error`). Bild-Adressen und Titel stehen nicht im Recorder-Verlauf.

**Hinweis (Cover):** Liefert der Anbieter seine Bilder nur über `http`, während Home Assistant über `https` läuft, kann der Browser die Bilder je nach Einstellung blockieren („Mixed Content“). Viele Browser stellen solche Bild-Adressen automatisch auf `https` um, dann erscheinen sie trotzdem (im Test von Chrome und der Home-Assistant-Oberfläche wurde ein `http`-Cover angezeigt); fehlt ein Cover, liegt es meist am Bild-Server des Anbieters oder am Browser, nicht an der App. Die Karte „Steuerung“ auf der Geräteseite zeigt in der zweiten Zeile nur den Zustand; Titel, Serie, Staffel und Folge stehen in den Attributen und in einer Media-Player-Karte im Dashboard.

### Datenschutz und Sicherheit

- Gesendet wird nur, was Sie in der App freigeben (nur Status, Titel und Sender, Abo-Ablauf). Standard ist: nichts. Zugangsdaten, Playlist- und Anbieteradressen werden nie gesendet.
- Die Übertragung erfolgt per **signiertem Webhook** (HMAC-SHA-256, Schlüssel wird nie übertragen). Bei `http` im Heimnetz ist der Inhalt **nicht verschlüsselt**: Titel sind im selben Netz mitlesbar. Wenn möglich `https` verwenden.
- Schlüssel liegen im Speicher der Konfigurationseinträge von Home Assistant. Die Integration selbst speichert keine Titel und Sender; sie nimmt Titelattribute des Media-Players vom Recorder-Verlauf aus. **Ausnahme:** Der Zustand des Sensors „Läuft gerade“ ist der Titel, und den speichert der Recorder von Home Assistant im Verlauf. Wer das nicht möchte, schließt den Sensor per `recorder: exclude` aus (Beispiel oben bei der Sensorbeschreibung) oder deaktiviert ihn. Ereignisse (`itrend_player_event`) können Titel enthalten; Automationen, Logbuch und Protokolle sind Ihre Sache.
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
