# iTrend Player ↔ Home Assistant: Protokoll v1

Stand: 2026-10-15. Status: **Entwurf zur Prüfung**, noch nicht freigegeben. Gehört zum Entwurf `../superpowers/specs/2026-10-15-home-assistant-integration-design.md` (Schritt 1). Normativ sind dieser Text, `vectors.json` und `reference.py` gemeinsam; bei Widerspruch gilt der Text, und der Widerspruch ist ein Fehler, der gemeldet wird.

Schlüsselwörter: MUSS, DARF NICHT, SOLL, KANN im Sinne von RFC 2119. Stellen, bei denen die Kryptografie unabhängig geprüft werden muss, sind mit **[zu prüfen durch unabhängige Prüfung]** markiert (Liste in Abschnitt 9.4).

Feld- und Nachrichtennamen sind Englisch, der Rest Deutsch.

---

## 1. Begriffe, Rollen, Version

| Begriff | Bedeutung |
|---|---|
| **App** | iTrend Player (Android/Fire TV oder Tizen). Das Gerät. Absender aller Meldungen, Client der WebSocket-Verbindung. |
| **HA** / **Integration** | Home Assistant mit der Integration `itrend_player`. Empfänger, Server. |
| **Kopplung** | Einmaliger Ablauf, an dessen Ende beide Seiten zwei gemeinsame Schlüssel kennen (Abschnitt 3). |
| **device_id** | 16 Zufallsbytes, base64url (22 Zeichen). Von HA vergeben, je Kopplung neu. |
| **webhook_id** | 32 Zufallsbytes, base64url (43 Zeichen). Von HA vergeben, Teil des Webhook-Pfads. Kein Geheimnis im kryptografischen Sinn (geht im Klartext durchs LAN), schützt aber nichts allein. |
| **K_a2h** | 32-Byte-Schlüssel: signiert alles, was die App sendet. |
| **K_h2a** | 32-Byte-Schlüssel: signiert alles, was HA sendet (Antworten, Befehle). Getrennt von K_a2h, damit eine App-Nachricht nie als HA-Nachricht durchgeht (Reflexion). |
| **seq** | Sequenznummer je Gerät, streng aufsteigend (Abschnitt 4.3). |
| **Basisadresse** | Vom Nutzer eingegeben: `http(s)://host[:port][/präfix]`, ohne Pfad zu API-Endpunkten. |

**Kodierung (überall):** Binärwerte als **base64url ohne Padding** (RFC 4648 §5, Alphabet `A–Z a–z 0–9 - _`). Empfänger MÜSSEN streng dekodieren: kein `=`, keine anderen Zeichen, Länge `≡ 1 (mod 4)` ungültig, Restbits MÜSSEN null sein (nur die kanonische Form wird angenommen). Zahlen im Text sind Dezimal ohne führende Nullen. Text ist UTF-8. Zeilenende ist LF (`\n`), nie CRLF. Hash ist überall SHA-256.

**MAC-Eingaben (überall, Befund 1):** Jede MAC-Eingabe (Webhook-Signatur, `proof`, WebSocket-Handshake, Nonce, Befehl, Ack, `M1`, `M2`) wird als **längenpräfixierte Feldliste** gebildet: `LP(f1, …, fn) = len(f1) ‖ f1 ‖ … ‖ len(fn) ‖ fn`, mit `len` als 4 Byte Big-Endian. Textfelder gehen als UTF-8. Das erste Feld ist immer die Beschriftung (`ITP1-REQ`, `ITP1-RESP`, `ITP1-WS-H`, `ITP1-WS-A`, `ITP1-NONCE`, `ITP1-CMD`, `ITP1-ACK`, `ITP1-M1`, `ITP1-M2`, `ITP1-TH`). So kann kein Feldwechsel (z. B. Verschieben eines Zeichens zwischen `id` und `nonce`) dieselbe MAC-Eingabe ergeben. Zusätzlich gelten strenge Formatprüfungen aller Felder (9.6).

### 1.1 Protokollversion

- Das Protokoll heißt `v1`. Die Version steht in jeder Nachricht (`"v":1` in JSON, `ITP/1` in der ersten Zeile des Webhook-Bodys).
- **Hauptversion** (1, 2, …) ändert sich nur bei inkompatibler Änderung (Signaturform, Kopplung, Bedeutung bestehender Felder). **Kompatible Erweiterungen** (neue optionale Felder, neue Ereignisnamen, neue Befehle) bleiben in `v1`.
- Empfänger MÜSSEN unbekannte JSON-Felder ignorieren und unbekannte `type`-Werte und Ereignisnamen annehmen, aber ignorieren (Antwort `200`, `ignored`). Sender DÜRFEN keine Felder senden, die diese Spezifikation nicht kennt.
- **Versionsabweichung:** Kennt HA die Hauptversion der App nicht, antwortet sie `400 unsupported_version` mit `{"supported":[1]}`. Die App zeigt „Integration in Home Assistant aktualisieren“, wenn ihre Version höher als jede unterstützte ist, sonst „App aktualisieren“. Es gibt keine Verhandlung mit stillem Zurückfallen; eine App spricht genau eine Hauptversion.

---

## 2. Endpunkte

Alle Pfade relativ zur Basisadresse. Die App MUSS ausschließlich die Basisadresse des Nutzers ansprechen.

| Zweck | Methode, Pfad | Authentisierung |
|---|---|---|
| Kopplung Schritt 1 | `POST /api/itrend_player/pair/start` | keine (Code-Beweis in Schritt 2) |
| Kopplung Schritt 2 | `POST /api/itrend_player/pair/finish` | keine (Code-Beweis `M1`) |
| Kopplung, Preflight | `OPTIONS` auf beide Pfade | keine |
| Meldungen App → HA | `POST /api/webhook/<webhook_id>` | Signatur im Body (Abschnitt 4) |
| Befehlskanal (Stufe 3) | `GET /api/itrend_player/ws` (WebSocket-Upgrade) | Handshake im Protokoll (Abschnitt 6) |

**Der signierte Pfad** („PATH“) ist immer `"/api/webhook/" + webhook_id`, unabhängig von einem Präfix der Basisadresse oder einem Reverse-Proxy. HA bildet ihn aus der `webhook_id` des Eintrags, nicht aus `request.path`.

### 2.1 CORS und Preflight

Tizen-Web-Apps lösen bei Anfragen mit eigenen Headern oder `Content-Type: application/json` einen CORS-Preflight aus. Der Webhook von HA beantwortet `OPTIONS` nicht. Deshalb gilt:

- Der Webhook-Aufruf ist eine **einfache Anfrage**: `POST`, `Content-Type: text/plain;charset=UTF-8`, **keine eigenen Header**. Signatur, Geräte-ID und Sequenz stehen **im Body** (daher weichen die Feldnamen von „Header-Namen“ ab: es gibt keine).
- Alle Antworten der Integration (Webhook, Pairing, auch Fehler) MÜSSEN `Access-Control-Allow-Origin: *` tragen (es gibt keine Cookies oder Anmeldedaten, `*` ist unbedenklich). Beim Webhook setzt der Handler den Header selbst, weil HA CORS dort nur für konfigurierte Ursprünge ergänzt.
- Die Pairing-Endpunkte akzeptieren ebenfalls `text/plain` (JSON-Text). Zusätzlich beantworten sie `OPTIONS` mit `204` und `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: POST, OPTIONS`, `Access-Control-Allow-Headers: Content-Type`, `Access-Control-Max-Age: 600`, und akzeptieren auch `Content-Type: application/json`.
- Ob die Tizen-App mit `<access origin>` die Antworten lesen kann, ist **am Gerät zu prüfen**. Fehlt der Lesezugriff, kann die App keine Beweise (`proof`) prüfen und zeigt dauerhaft „nicht bestätigt“; dann ist die Kopplung am TV nicht nutzbar.

### 2.2 Größen und Grenzen

| Wert | Grenze |
|---|---|
| Webhook-Body gesamt | 4096 Byte (sonst `413 payload_too_large`) |
| Nutzlast (JSON) | 2048 Byte |
| Pairing-Body | 4096 Byte |
| WebSocket-Nachricht | 1024 Byte |
| Zeichenketten | in Unicode-Codepunkten gezählt (nicht UTF-16-Einheiten, nicht Bytes); Steuerzeichen U+0000–U+001F und U+007F sind verboten |

Zu lange Titel kürzt die **App** vor dem Senden (am Codepunkt, mit angehängtem `…` innerhalb der Grenze). HA lehnt zu lange Werte ab, es kürzt nicht.

---

## 3. Kopplung

### 3.1 Ehrliche Prüfung: „Schlüssel aus 6-stelligem Code per HKDF“

**Nein, das ist nicht sicher.** Der Code hat nur 10^6 Werte (≈ 20 Bit). Wenn beide Seiten den Schlüssel allein aus Code und ausgetauschten Zufallswerten ableiten und eine Seite die Kenntnis per Schlüsselbestätigung beweist, sieht ein passiver Mitleser Nonces und Bestätigung und kann alle 10^6 Codes **offline** durchprobieren (Sekunden). Er kennt dann den Geräteschlüssel und kann jede Meldung und jeden Befehl fälschen.

Auch der Vorschlag „ECDH (X25519) plus HMAC über beide öffentlichen Schlüssel mit einem aus dem Code abgeleiteten Schlüssel“ erfüllt die Anforderung **nicht**:

- Ist der HMAC-Schlüssel **nur** aus dem Code abgeleitet, ist der HMAC über öffentlich sichtbare Werte ein Offline-Prüfwerkzeug für den Code: ein passiver Lauscher lernt den Code sofort. (Das ECDH hilft nicht, die Prüfung braucht es nicht.)
- Fließt zusätzlich das ECDH-Geheimnis in den HMAC-Schlüssel ein, lernt der **passive** Lauscher nichts mehr. Ein **aktiver** Angreifer (spielt gegenüber der App HA) führt aber ein eigenes ECDH mit der App durch, kennt damit den HMAC-Schlüsselanteil und kann aus *einer* Antwort der App alle 10^6 Codes **offline** prüfen. Das „einmal raten pro Versuch“ gilt nur für PAKE-Verfahren, bei denen ein Angreifer ohne Code aus einem Austausch höchstens *einen* Code-Kandidaten prüfen kann.

Die Anforderung (passiver Lauscher lernt nichts, aktiver Angreifer kann je Pairing-Versuch genau einen Code raten) verlangt deshalb ein **passwortauthentisiertes Schlüsselaustauschverfahren (PAKE)**, nicht „ECDH + MAC mit Code“.

### 3.2 Bewertung der Kandidaten

| Verfahren | Passiver Lauscher | Aktiver Angreifer | Aufwand je Plattform | Urteil |
|---|---|---|---|---|
| A. X25519 + HMAC mit Code (Vorschlag) | nur sicher, wenn ECDH-Geheimnis in den MAC-Schlüssel einfließt | **Offline-Raten aller Codes** möglich (siehe 3.1) | X25519 nötig: HA `cryptography` vorhanden; Android API < 33 kein natives X25519 (BouncyCastle oder Tink); Tizen/Chromium 85 kein X25519 in WebCrypto (tweetnacl) | **Nicht geeignet** |
| B. CPace (CFRG) oder SPAKE2 (RFC 9382) auf Curve25519/Edwards25519 | nichts | genau ein Kandidat je Versuch | Braucht Punktoperationen auf Edwards25519 bzw. Elligator-2-Abbildung, die in `cryptography` (Python), Android/Kotlin ohne zusätzliche Bibliothek und Tizen (tweetnacl legt sie nicht offen; `@noble/curves` wäre nötig) nicht fertig verfügbar sind. Selbstbau ist fehleranfällig. | Stand der Technik, aber hier **zu schwer einzubauen und zu prüfen** |
| **C. SRP-6a (3072 Bit, RFC 5054/2945-Stil)** | nichts | genau ein Kandidat je Versuch (für Angreifer in beiden Rollen, siehe 3.5) | **Nur `BigInteger` und SHA-256**: Python `int`/`pow`, Kotlin `java.math.BigInteger`, Tizen natives `BigInt`. Keine zusätzliche Bibliothek. | **Gewählt** |

Begründung für C: Es erfüllt die Sicherheitsanforderung, braucht auf allen drei Plattformen nur Standardbausteine und lässt sich mit den Testvektoren exakt gegenprüfen. Es hat Vorbilder in genau diesem Einsatz (HomeKit-Kopplung per Setup-Code nutzt SRP-6a mit 3072 Bit). Nachteile: alt (1998/2002), große Zahlen (Rechenzeit auf dem TV, siehe 3.8), nicht Konstantzeit in Standardbibliotheken, und eine abgewandelte Beweisform (3.4). CPace bleibt die Zielvariante für ein späteres `v2`, wenn die Plattformen einfache Edwards25519-Bausteine bekommen.

Weil das Pairing kein X25519 braucht, werden **keine** X25519-Bibliotheken benötigt. Die Angaben für den Fall, dass `v2` CPace/SPAKE2 oder ein ECDH einführt, stehen in Abschnitt 3.9.

### 3.3 Parameter

- Gruppe: RFC 3526 Gruppe 15 (3072 Bit, sichere Primzahl), **`g = 2`** wie in RFC 3526 veröffentlicht. (Entwurf nannte `g = 5` nach RFC 5054; auf Befund 7 geändert: `g = 2` ist die in RFC 3526 für diese Gruppe festgelegte Erzeugende, erzeugt bei dieser Primzahl die Untergruppe der Ordnung `(N−1)/2` und vermeidet eine eigene Wahl. `g = 5` wäre ebenfalls tragfähig gewesen; entscheidend ist, dass alle Seiten denselben Wert nutzen.) `N` steht in Anhang A. Die Primzahl ist nach der Formel `2^3072 − 2^3008 − 1 + 2^64 · (⌊2^2942 · π⌋ + 1690314)` berechenbar; `reference.py --check` prüft das, die Primeigenschaft von `N` und `(N−1)/2` (Miller-Rabin) und den bekannten Anfang `FFFFFFFFFFFFFFFF C90FDAA2 …`.
- `PAD(x)`: `x` als Big-Endian-Zahl auf 384 Byte links mit Nullen aufgefüllt.
- `H` = SHA-256. `k = H(PAD(N) ‖ PAD(g))`.
- `I` (feste Kennung) = ASCII `itrend-ha-pair-v1`.
- `P` = Code, 6 ASCII-Ziffern `000000`–`999999`, von HA mit einem kryptografischen Zufallsgenerator gezogen (`secrets.randbelow(10**6)`), **nicht** in Logs.
- `x = H(s ‖ H(I ‖ ":" ‖ P))` (als Zahl, ohne Reduktion), `v = g^x mod N`.
- Geheime Exponenten `a`, `b`: je 256 Bit aus dem kryptografischen Zufallsgenerator, **je Versuch neu**.
- **Randwerte (beide Seiten, auch HA):** `1 < A < N−1` und `1 < B < N−1` als Zahl (die 384 Byte langen Werte dürfen auch nicht `≥ N` sein), und `u ≠ 0`; sonst Abbruch (`400 bad_request` bei HA, Abbruch in der App). Vektoren: `srp_bounds`.
- Salt `s`: 16 Zufallsbytes, je Code neu.

### 3.4 Ablauf

HA erzeugt beim Öffnen des Einrichtungsdialogs: Code `P`, Salt `s`, `v`. Gültigkeit **5 Minuten** (monotone Uhr von HA), **einmalig**, **höchstens 3 Fehlversuche**. HA zeigt `P` (Anzeige „123 456“) und die Adresse an. In der App gibt der Nutzer Basisadresse und Code ein (Ziffern, Leerzeichen werden entfernt; Eingabe über die Handy-Seite bei Tizen ist möglich).

**Schritt 1: `POST /api/itrend_player/pair/start`**

App → HA: `{"v":1}`

HA → App `200`:

| Feld | Typ | Länge | Inhalt |
|---|---|---|---|
| `v` | int | – | `1` |
| `session` | string | 22 Zeichen (16 Byte) | Zufällig, bezeichnet diesen Versuch |
| `salt` | string | 22 Zeichen (16 Byte) | `s` |
| `B` | string | 512 Zeichen (384 Byte, `PAD(B)`) | `B = (k·v + g^b) mod N`, `b` neu je Versuch |

HA merkt sich `(session, b, B)` höchstens **60 Sekunden** und höchstens 4 gleichzeitige offene Versuche insgesamt, davon **höchstens 2 je Quelladresse** (Befund 4; ist die Grenze je Adresse erreicht, fliegt der älteste Versuch *dieser* Adresse raus, nie der einer anderen. Sind alle 4 Plätze belegt und die anfragende Adresse hat **weniger als 2** offene, bekommt sie `429 rate_limited` und **nichts Fremdes wird verdrängt**: Begründung: ein einzelner Teilnehmer darf die Versuche anderer weder verdrängen noch durch eigene ersetzen; belegte Plätze verfallen nach 60 s, die Störung ist zeitlich begrenzt). So kann ein einzelner Teilnehmer im Netz die Versuche anderer nicht verdrängen. Gibt es keinen aktiven Code (nie geöffnet, abgelaufen, verbraucht, gesperrt), antwortet HA `404 pairing_unavailable`.

**Schritt 2: `POST /api/itrend_player/pair/finish`**

Die App berechnet (alle Zahlen als Big-Endian):

```
B  prüfen: B mod N ≠ 0, sonst Abbruch
A  = g^a mod N
u  = H(PAD(A) ‖ PAD(B));  u ≠ 0
x  = H(s ‖ H(I ‖ ":" ‖ P))
S  = (B − k · g^x) ^ (a + u·x)  mod N          (Differenz mod N, nichtnegativ)
K0 = H(PAD(S))                         (nur HKDF-Eingabe, nie direkt als HMAC-Schlüssel)
ctx = LP(name, platform, app_version)               (Text als UTF-8)
th  = H(LP("ITP1-TH", PAD(A), PAD(B), ctx))
PRK = HKDF-Extract(salt = th, IKM = K0)
K_proof = HKDF-Expand(PRK, "ITP1 proof", 32)       (eigener Schlüssel nur für M1/M2)
M1 = HMAC-SHA256(K_proof, LP("ITP1-M1", PAD(A), PAD(B), ctx))
```

App → HA:

| Feld | Typ | Grenze | Inhalt |
|---|---|---|---|
| `v` | int | = 1 | |
| `session` | string | 22 Zeichen | aus Schritt 1 |
| `A` | string | 512 Zeichen | `PAD(A)` |
| `M1` | string | 43 Zeichen (32 Byte) | Beweis, dass die App den Code kennt |
| `name` | string | 1–40 Codepunkte | Anzeigename des Fernsehers, frei wählbar, ohne Steuerzeichen |
| `platform` | string | `android` oder `tizen` | |
| `app_version` | string | Muster `^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(-[A-Za-z0-9.]{1,16})?$`, ≤ 32 | |

**Reihenfolge bei HA (Befund 2):** (1) Formate und Randwerte (`1 < A < N−1`, `name` nach 9.6) prüfen; (2) Versuch **atomar entnehmen und löschen** (jeder Versuch ist einmalig) und **in derselben atomaren Operation den Fehlversuchszähler des Codes erhöhen, bevor** rechenintensiv gearbeitet wird; (3) erst dann `u`, `S = (A · v^u)^b mod N`, `K0`, `K_proof`, erwartetes `M1` (mit den empfangenen `name/platform/app_version`) berechnen und **in konstanter Zeit** vergleichen. Bei Erfolg wird der Zähler nicht mehr gebraucht (Code verbraucht). So kann kein paralleler Strom von Anfragen die Zählung durch Rechenzeit umgehen. Die Potenz läuft im Executor.

- **Stimmt `M1`:** HA vergibt `device_id` (16 Byte) und `webhook_id` (32 Byte), berechnet
  ```
  M2 = HMAC-SHA256(K_proof, LP("ITP1-M2", PAD(A), PAD(B), M1, device_id, webhook_id))
  ```
  (`device_id` und `webhook_id` in ihrer base64url-Textform) und antwortet `200` mit `{"v":1,"M2":…,"device_id":…,"webhook_id":…}`. Der Code ist danach verbraucht. HA legt Eintrag, Schlüssel und `last_seq = 0` an.
- **Stimmt `M1` nicht:** `403 pairing_failed` mit `{"error":"pairing_failed","attempts_left":n}`. Der Fehlversuchszähler des Codes steigt. Bei 3 Fehlversuchen ist der Code ungültig (danach `404 pairing_unavailable`); HA zeigt im Dialog „Code gesperrt, bitte neuen Code erzeugen“.

Die App prüft `M2` (konstante Zeit). Stimmt es nicht, bricht sie ab mit „HA hat den Code nicht bestätigt: Adresse oder Code prüfen“ und speichert nichts. Erst bei gültigem `M2` speichert sie die Kopplung.

**Schlüsselableitung (beide Seiten, nach gültigem M1/M2):**

```
(th, PRK wie oben)
K_a2h = HKDF-Expand(PRK, "ITP1 app-to-ha" ‖ LP(device_id, webhook_id), 32)
K_h2a = HKDF-Expand(PRK, "ITP1 ha-to-app" ‖ LP(device_id, webhook_id), 32)
```

(HKDF nach RFC 5869 mit HMAC-SHA256.) Die Schlüssel werden **nie** übertragen. Nach der Kopplung löschen beide Seiten `a`, `b`, `S`, `K0`, `K_proof`, `x`, `P`. `K0` dient ausschließlich als HKDF-Eingabe, `K_proof` ausschließlich für `M1`/`M2`, `K_a2h`/`K_h2a` ausschließlich für Meldungen (Schlüsseltrennung, Befund 7).

### 3.5 Warum das hält (und was nicht)

- **Passiver Lauscher:** sieht `salt, B, A, M1, M2` und kennt weder `a` noch `b`. Um einen Code zu prüfen, müsste er `S` berechnen können, also ein diskretes Logarithmusproblem in der 3072-Bit-Gruppe lösen. Er lernt nichts über den Code.
- **Aktiver Angreifer gegen HA (spielt die App):** muss `M1` liefern, kann das nur mit dem richtigen Code. Je Versuch genau ein Kandidat; nach 3 Fehlversuchen ist der Code tot. Erfolgswahrscheinlichkeit je Code ≤ 3/10^6 = 3·10^-6, und er braucht Netzzugang genau während der 5 Minuten.
- **Aktiver Angreifer gegen die App (spielt HA):** wählt `B` aus einem Kandidatencode `P'` und lernt aus dem `M1` der App, ob `P' = P`. Ebenfalls genau ein Kandidat je Versuch; er sieht aber nur, ob er richtig lag. Der Nutzer sieht bei falscher Adresse oder falschem Code „nicht bestätigt“; mehrere Fehlversuche in der App, die nicht zu einer erfolgreichen Kopplung führen, SOLLEN dem Nutzer als Warnung gezeigt werden („Wenn das mehrmals passiert, ist jemand im Netz“).
- **Verbleibend (nicht durch die Rate-Limits zu beseitigen):** Fremde Webseiten im Browser eines Nutzers im Heimnetz können wegen `Access-Control-Allow-Origin: *` Anfragen an die Pairing-Endpunkte senden (Fehlversuche, Last). Das Limit je Quelladresse (die Adresse des Browsers) begrenzt es; HA SOLL zusätzlich anhand `Origin` zählen und Anfragen mit `Origin` einer öffentlichen Webseite (nicht Tizen-/App-Ursprung) bevorzugt verwerfen, sobald die Tizen-Ursprungswerte am Gerät bekannt sind (offen, 9.5). Ein Angreifer im selben Netz kann durch absichtliche Fehlversuche den Code sperren (Störung, kein Einbruch). Der Nutzer erzeugt einen neuen Code. Der Dialog SOLL das als Hinweis nennen („Wird der Code gesperrt, ohne dass Sie ihn falsch eingegeben haben, versucht jemand im Netz zu stören. Erzeugen Sie einen neuen Code.“). Der Pairing-Endpunkt ist unauthentifiziert und damit **DoS-fähig** (Code sperren, Versuche belegen, Rechenzeit): Störung, kein Einbruch.
- Diese Bewertung ist die einer Entwurfsüberlegung, keine Sicherheitsprüfung. **[zu prüfen durch unabhängige Prüfung]**: (a) die Abwandlung der Beweise `M1/M2` (HMAC mit aus `S` abgeleitetem Schlüssel, statt der Hash-Formeln aus RFC 2945/SRP-6a), (b) Behandlung von `A`/`B`-Randwerten, (c) 256-Bit-Exponenten und `g = 2`, (d) Zeitverhalten (3.7).

### 3.6 Grenzen und Fehlerantworten

| Bedingung | Antwort |
|---|---|
| Kein aktiver Code (nie, abgelaufen, verbraucht, gesperrt) | `404 pairing_unavailable` |
| Versuch unbekannt, abgelaufen (> 60 s) oder bereits verbraucht | `410 session_expired` (und Fehlversuch zählt **nicht**; erst falsches `M1` zählt) |
| Falsches `M1` | `403 pairing_failed` (`attempts_left`) |
| Ungültiges Feld, Länge oder Kodierung, `A mod N = 0` | `400 bad_request` |
| Unbekannte Hauptversion | `400 unsupported_version` (`supported`) |
| Zu viele Anfragen | `429 rate_limited` (`Retry-After`) |
| Body > 4096 Byte | `413 payload_too_large` |

**Rate-Limit:** je Quelladresse höchstens **10 Anfragen pro Minute** an die Pairing-Endpunkte zusammen (zählt jede Anfrage, auch erfolgreiche); danach `429`. Zusätzlich: höchstens ein aktiver Code gleichzeitig; höchstens 2 offene Versuche je Quelladresse; zeitgleich laufende `pair/finish`-Berechnungen höchstens 2 (weitere bekommen `429`, ihr Versuch bleibt erhalten und zählt nicht als Fehlversuch); `OPTIONS` zählt nicht zum Rate-Limit; bei zwei gleichzeitig richtigen Beweisen gewinnt nur einer, der andere bekommt `404 pairing_unavailable`; nach 3 gesperrten Codes innerhalb von 10 Minuten SOLL HA die Kopplung 10 Minuten lang gar nicht anbieten. Hinter einem Reverse-Proxy ohne `X-Forwarded-For`-Auswertung sieht HA nur die Proxy-Adresse; das Limit wirkt dann für alle gemeinsam (bekannte Einschränkung).

Antworten haben das Format `{"error":"<code>", …}` mit `Content-Type: application/json`.

### 3.7 Bibliotheken je Plattform (SRP und Hilfsfunktionen)

| Plattform | Bedarf | Lösung |
|---|---|---|
| **HA / Python** | `pow`, SHA-256, HMAC, Zufall | Standardbibliothek (`hashlib`, `hmac`, `secrets`). `cryptography` ist nicht nötig. `pow(…, 3072-Bit)` dauert gemessen 4–10 ms: trotzdem im Executor ausführen, nicht im Event-Loop. |
| **Android / Kotlin** (Fire TV ab API 22, Android TV) | `BigInteger.modPow`, SHA-256, HMAC, Zufall | `java.math.BigInteger`, `MessageDigest("SHA-256")`, `Mac.getInstance("HmacSHA256")`, `SecureRandom`: alles in der Plattform seit API 1, **keine Zusatzbibliothek**. HKDF ist ~15 Zeilen (Extract = HMAC, Expand = Schleife, siehe `reference.py`). Gemessen (Prüfung): Python 4–10 ms je Potenz bei HA, ca. 13 ms clientseitig mit Node-`BigInt`. Auf schwachen Fire-TV-Sticks ist mit 20–100-fach längerer Zeit zu rechnen, insgesamt etwa 0,3–1,3 s für die Kopplung: unproblematisch. |
| **Tizen / Chromium 85** | `BigInt`, SHA-256, HMAC, Zufall | `BigInt` ist ab Chromium 67 vorhanden. **Modelle mit älterem Chromium** (Tizen vor 5.5) können nicht koppeln; die App zeigt dann „Dieses Fernsehermodell unterstützt Home Assistant nicht“. SHA-256/HMAC/HKDF: `@noble/hashes` (MIT, unabhängig geprüft, nur `sha256`, `hmac`, `hkdf` einbinden, wenige KB; Größe und Chromium-85-Tauglichkeit des gebauten Pakets beim Einbau prüfen) oder eigene kleine Umsetzung. Nicht auf `crypto.subtle` verlassen (nur in sicherem Kontext, nicht auf allen Modellen); `crypto.getRandomValues` ist für Zufall zu verwenden und ist auf Tizen verfügbar (am Gerät zu prüfen). Die Potenz `modPow` ist in JS selbst zu schreiben (Quadrieren-und-Multiplizieren auf `BigInt`); Rechenzeit: Node-`BigInt` braucht ca. 13 ms; auf schwachen TVs 20–100-fach langsamer, also etwa 0,3–1,3 s insgesamt. Trotzdem **am TV zu bestätigen**. Die 3072-Bit-Gruppe bleibt; ein Wechsel auf Gruppe 14 ist nur bei Messwerten weit darüber vorgesehen (ändert `N`, `NLEN` und alle Vektoren, vor Auslieferung). |

Alle Zufallswerte MÜSSEN aus dem Betriebssystem-Zufallsgenerator stammen (`SecureRandom`, `crypto.getRandomValues`, `secrets`), niemals `Math.random`.

Konstante Zeit: Vergleiche von `M1`, `M2`, Signaturen und Beweisen MÜSSEN konstantzeitig sein (`hmac.compare_digest`, `MessageDigest.isEqual`, XOR-Schleife in JS). Die Potenz mit `BigInteger`/`BigInt`/`pow` ist **nicht** konstantzeitig; da `a`/`b` je Versuch neu sind und der Angreifer nur wenige Messungen bekommt, ist das als Restrisiko akzeptiert **[zu prüfen durch unabhängige Prüfung]**.

### 3.8 Verhalten der Seiten

- HA: zeigt den Code nur im Einrichtungsdialog, loggt ihn nie, löscht ihn bei Abbruch des Dialogs oder nach Ablauf.
- App: Eingabe der Adresse wird geprüft (Schema `http` oder `https`, kein Benutzername im URL). Die App SOLL vor dem Absenden der ersten Kopplungsanfrage die Einwilligungsseite zeigen (Abschnitt 8.2). Wiederholungsversuche der App nach Netzfehlern in Schritt 1 sind erlaubt, in Schritt 2 nicht (jedes Senden von `M1` verbraucht den Versuch; neu bei Schritt 1 beginnen).
- Ablauf in der Zeit: Schritt 1 → 2 innerhalb von 60 s.

### 3.9 Falls später ein ECDH-Verfahren dazukommt (v2, Bibliotheken zu prüfen)

Nicht Teil von `v1`. Angaben zum Planen; Größen, Lizenzen und Versionen **vor dem Einbau prüfen**:

| Plattform | Option | Bemerkung |
|---|---|---|
| HA / Python | `cryptography` (Apache-2.0/BSD) | In HA vorhanden; X25519, Ed25519 verfügbar. Punktoperationen für CPace/SPAKE2 nicht offen. |
| Android | BouncyCastle `bcprov-jdk18on` (MIT-ähnlich) oder Google Tink (Apache-2.0) | Natives X25519 erst ab API 33 (`KeyAgreement "X25519"`). Fire TV ab API 22 braucht eine Bibliothek. BouncyCastle ist im Rohzustand mehrere MB groß (R8 verkleinert stark), Tink-Android deutlich kleiner; Mindest-API von Tink ist zu prüfen. |
| Tizen / Chromium 85 | `tweetnacl` (gemeinfrei) oder `@noble/curves` (MIT) | WebCrypto kann X25519 erst in neueren Chromium-Versionen. `tweetnacl` (rund 7 KB) bietet `nacl.scalarMult` (X25519), aber keine Edwards-Punktoperationen; `@noble/curves` bietet sie und braucht `BigInt`. |

---

## 4. Meldungen App → HA: Signatur und Webhook

### 4.1 Aufbau des Bodys

`POST <Basisadresse>/api/webhook/<webhook_id>`, `Content-Type: text/plain;charset=UTF-8`, keine eigenen Header. Der Body ist Text aus **fünf Teilen**, getrennt durch LF:

```
ITP/1\n
<device_id>\n
<seq>\n
<sig>\n
<payload>
```

- Zeile 1 ist exakt `ITP/1`.
- `<device_id>`: 22 Zeichen base64url.
- `<seq>`: Dezimalzahl, `1 ≤ seq ≤ 2^53−1` (9007199254740991, größte exakt in JS darstellbare Ganzzahl), ohne führende Null, höchstens 16 Ziffern.
- `<sig>`: 43 Zeichen base64url (32 Byte).
- `<payload>`: alles nach dem **vierten** LF bis zum Ende: JSON-Text (UTF-8, ein JSON-Objekt, kompakt). Sender SOLLEN keine rohen LF in die Nutzlast schreiben (JSON-Escapes `\n` sind normal); Empfänger akzeptieren sie, da die Nutzlast als signierte Rohbytes gilt.

HA trennt mit `body.split(b"\n", 4)` und verlangt genau 5 Teile.

### 4.2 Kanonische Form und Signatur

Die Signatur läuft über die **Rohbytes** der Nutzlast, wie gesendet. HA prüft die Signatur, **bevor** die Nutzlast als JSON gelesen wird; es gibt keine JSON-Kanonisierung, die Sender schreiben das JSON frei (Reihenfolge, Escapes), solange die gesendeten Bytes signiert sind.

```
signing_input = LP("ITP1-REQ", METHOD, PATH, device_id, seq, payload_bytes)
sig = base64url( HMAC-SHA256( K_a2h, signing_input ) )
```

- `METHOD` ist `POST` (Großbuchstaben). `PATH` ist `/api/webhook/<webhook_id>`. `seq` in der Dezimalform des Bodys.
- Der Vektor `webhook.cases[*].signing_input_hex` in `vectors.json` zeigt die Eingabe in Hex; `reference.py` ist die Quelle.
- HA berechnet den erwarteten Wert aus der `webhook_id` des Eintrags und vergleicht in konstanter Zeit. Passt `device_id` im Body nicht zum Eintrag oder die Signatur nicht, ist die Antwort in beiden Fällen gleich: `401 bad_signature` (kein Unterschied zwischen „Gerät unbekannt“ und „Signatur falsch“).

### 4.3 Sequenznummer

- Je Gerät eigene Zählung, beginnt bei 1 (erste Meldung nach Kopplung), **streng aufsteigend**; Lücken sind erlaubt, Wiederholung oder Rückschritt nicht. Es gibt **keine Zeitstempel** in der Prüfung (Uhren am Fernseher gehen falsch).
- **HA**: speichert `last_seq` je Gerät. **Die Signatur wird VOR dem Geräte-Lock geprüft** (Aufbau, Format und HMAC brauchen keinen Zustand außer dem Schlüssel); sonst könnte jemand ohne Schlüssel den Lock halten (Lock-DoS). **Nur Prüfen von `seq`, Speichern der Reservierung und Setzen von `last_seq` liegen im Lock** (ein Sperrmechanismus je Gerät); parallele gültig signierte Anfragen desselben Geräts laufen dort nacheinander, sonst könnten zwei gleichzeitige Meldungen dieselbe Sequenz verbrauchen oder `last_seq` zurücksetzen. Da die Signatur die Sequenz bindet, ändert die Reihenfolge nichts am Ergebnis. Akzeptiert nur `seq > last_seq`, sonst `409 seq_too_low` (Details unten). Vor dem Lesen der Nutzlast wird `last_seq := seq` gesetzt: Die Sequenz ist mit gültiger Signatur **verbraucht**, auch wenn die Nutzlast danach `422` ergibt.
- **Dauerhaftigkeit auf HA-Seite durch Reservierung:** HA speichert einen Wert `reserved ≥` jedes je akzeptierten `seq`. Muss `seq` über `reserved` hinaus, speichert HA **zuerst** `reserved := seq + 99` (mit Warten auf das Speichern) und akzeptiert danach. Beim Start gilt `last_seq := reserved`. So kann ein HA-Absturz nie dazu führen, dass eine alte Meldung wieder akzeptiert wird; die App holt den Rückstand über den Abgleich (unten) auf.
- **App**: speichert einen Reservierungswert `reserved_app` (höchste je verwendete oder reservierte Nummer) im lokalen Speicher. Vor `seq = n` mit `n > reserved_app` setzt sie `reserved_app := n + 99` und speichert **zuerst**. Nach einem Neustart beginnt sie bei `reserved_app + 1`. Es entstehen höchstens 99 Lücken pro Neustart, ein Schreibvorgang etwa alle 100 Meldungen.
- **Abgleich bei `409`:** Die Antwort enthält `last_seq` und einen `proof` (4.5). Prüft die App den Beweis erfolgreich und ist `last_seq` ≤ `2^53 − 1000`, setzt sie `reserved_app := max(reserved_app, last_seq + 100)`, `seq := last_seq + 1` und sendet die Meldung **einmal** neu (mit neuer Sequenz). Eine Meldung nach `409` ist **idempotent**: `state` ersetzt den ganzen Zustand (nochmaliges Senden schadet nicht), ein `event` wird nur wiederholt, wenn HA mit `409` ablehnte (dann wurde er nicht verarbeitet), nie nach Netzfehler oder Zeitüberschreitung. Die App hat je Gerät **höchstens eine Anfrage gleichzeitig** offen und sendet `state`, `heartbeat` und `event` in Reihenfolge der Sequenznummern; beim Zusammentreffen von `state`, `heartbeat` und Abgleich gilt: erst Abgleich, dann den aktuellen `state` senden, dann ggf. den wartenden `heartbeat` (veraltete wartende `state` werden verworfen). Das deckt zurückgesetzte App-Speicher (Sicherung eingespielt) und HA-Neustarts ab. Ist der Beweis ungültig, übernimmt die App nichts („nicht bestätigt“).
- **Geklonter Schlüssel:** Läuft dasselbe Gerät mit demselben Schlüssel auf zwei Geräten (Sicherung kopiert), führen deren Meldungen zu wechselnden `409` oder zu Sprüngen. HA zählt gültig signierte Meldungen mit `seq ≤ last_seq` je Gerät; ab **5 in 10 Minuten** (ein einzelner `409` nach HA-Neustart oder App-Wiederherstellung ist normal) oder einem Sprung von mehr als 1000 über `last_seq` zeigt HA eine Reparatur-Meldung „Schlüssel möglicherweise kopiert, Gerät neu koppeln“. Heilung nur durch Löschen und erneutes Koppeln.
- Überlauf: Erreicht `seq` `2^53 − 1`, ist die Kopplung zu erneuern (rechnerisch unerreichbar).

### 4.4 Antworten des Webhooks

Alle Antworten sind JSON (`Content-Type: application/json`) mit `Access-Control-Allow-Origin: *` und `Cache-Control: no-store`.

**Content-Type:** Der Webhook akzeptiert nur `text/plain` (Parameter wie `charset` und Groß-/Kleinschreibung egal); jeder andere Typ → `400 bad_request`, die Sequenz bleibt unverbraucht (Vektoren `wrong_content_type`, `content_type_charset_ok`). Die Pairing-Endpunkte akzeptieren `text/plain` und `application/json`, sonst `400 bad_request`.

| HTTP | `error` / `code` | Bedeutung | Reaktion der App |
|---|---|---|---|
| 200 | `ok` | angenommen (auch: unbekannter Typ/Ereignis, dann zusätzlich `"ignored":true`) | normal |
| 400 | `bad_request` | Aufbau, Kodierung, Sequenzform fehlerhaft | Fehler im Sender; nicht wiederholen |
| 400 | `unsupported_version` | Hauptversion unbekannt (`supported`) | Hinweis aktualisieren |
| 401 | `bad_signature` | Signatur falsch oder Gerät unbekannt | nicht wiederholen; nach 3 in Folge „Kopplung erneuern“ |
| 409 | `seq_too_low` | Sequenz nicht größer als `last_seq` | Abgleich (4.3) |
| 413 | `payload_too_large` | Body > 4096 oder Nutzlast > 2048 Byte | Fehler im Sender |
| 422 | `bad_payload` | Signatur gültig, Nutzlast verletzt Schema | Fehler im Sender; Sequenz ist verbraucht |
| 429 | `rate_limited` | zu viele Meldungen (`Retry-After`) | warten, dann weiter (keine Wiederholungsschleife) |
| 5xx | – | Fehler in HA | mit Pause erneut, nicht puffern (Abschnitt 5.5) |

**Antwortformate (verbindlich, so setzt es die Integration um):**

| Fall | Webhook | Pairing |
|---|---|---|
| Erfolg | `{"ok":true,"code":"ok","seq":<seq>,"resync":<bool>,"proof":"…"[,"ignored":true]}` | je Schritt wie in 3.4 (ohne `ok`) |
| Fehler | `{"ok":false,"error":"<code>"[,…]}` | `{"error":"<code>"[,…]}` (ohne `ok`) |
| `unsupported_version` | zusätzlich `"supported":[1]` | zusätzlich `"supported":[1]` |
| `409 seq_too_low` | zusätzlich `"last_seq":<n>,"proof":"…"` | – |
| `429 rate_limited` | zusätzlich `"retry_after":<Sekunden>` und Header `Retry-After` | Header `Retry-After` und `retry_after` |
| `403 pairing_failed` | – | zusätzlich `"attempts_left":<n>` |
| `500 internal` | `{"ok":false,"error":"internal"}` | `{"error":"internal"}` |

Das Feld heißt immer `error` (String-Code aus 7.1), nie `code` im Fehlerfall; `code` steht nur in Erfolgsantworten.

**Fehlerantworten (`400`, `401`, `413`, `422`, `429`, `5xx`) sind nicht authentisiert** (ein Mitspieler im Netz kann sie fälschen). Die App löscht deshalb **niemals** automatisch Schlüssel oder Kopplung aufgrund einer Fehlerantwort, sondern zeigt nur einen Zustand an und lässt den Nutzer entscheiden. `Retry-After` wird auf höchstens **300 s** gedeckelt. Auch die Zählung „3 in Folge → Kopplung erneuern“ löst nur eine Anzeige aus.

**Wichtig:** Ist ein Webhook in HA nicht (mehr) registriert (Gerät gelöscht), antwortet HA selbst mit `200` und **leerem** Body (HA-Verhalten, nicht beeinflussbar). Die App wertet deshalb nur eine Antwort mit gültigem `proof` als „bestätigt“. Antworten ohne gültigen Beweis (leer, HTML, falsches JSON) zählen als „nicht bestätigt“; nach **3 aufeinanderfolgenden** (ca. 90 s) zeigt die App „Kopplung erneuern“. Netzfehler (Verbindung verweigert, Zeitüberschreitung) zeigen „nicht verbunden“, nicht „Kopplung erneuern“.

### 4.5 Antwortbeweis

Damit die App HA erkennt (und eine fremde Antwort nicht als „angekommen“ gilt), trägt jede `200`- und jede `409`-Antwort einen `proof`:

```
proof = base64url( HMAC-SHA256( K_h2a,
    LP("ITP1-RESP", device_id, seq, req_sig, code, last_seq, resync) ) )
```

`seq` ist die Sequenz der beantworteten Anfrage, `req_sig` ist das `sig`-Feld (Text) dieser Anfrage (bindet die Antwort an genau diese Anfrage; eine ältere Antwort mit gleichem `seq` auf eine andere Meldung passt nicht), `code` ist `ok` oder `seq_too_low`, `last_seq` ist `0` außer bei `seq_too_low`, `resync` ist `1` oder `0`. Das gibt zusätzlich die gegenseitige Echtheitsprüfung nach einer Adressänderung (Abschnitt 7.4).

### 4.6 Rate-Limits Webhook

- **Je Gerät:** höchstens 10 **angenommene** Meldungen in 10 Sekunden; das Limit wird **nach** der Sequenzprüfung angewandt, `429` verbraucht **keine** Sequenz, und Wiederholungen eines Angreifers (`409`) verbrauchen es nicht. Ein Angreifer ohne Schlüssel kann es nicht verbrauchen.
- **Je Quelladresse:** höchstens 30 abgewiesene Meldungen (`401`, `409`) pro Minute; danach `429` ohne weitere Prüfung.
- Sender SOLLEN `state` zusammenfassen: höchstens 1 `state` pro Sekunde (letzter Stand gewinnt), Heartbeat alle 30 s.

---

## 5. Nachrichten App → HA: Inhalte

Die Nutzlast ist ein JSON-Objekt. Immer vorhanden: `v` (int, = 1) und `type` (string).

| `type` | Zweck |
|---|---|
| `state` | Zustand der App und des Abspielers, bei jeder Änderung |
| `heartbeat` | Lebenszeichen alle 30 s |
| `event` | Ereignis für Automationen |
| `unpair` | App trennt die Kopplung (letzte Meldung) |

Formale Schemas stehen in Abschnitt 5.6, ausführbar in `reference.py` (`validate_payload`); Testfälle in `vectors.json` unter `payloads`.

### 5.1 Einwilligungsstufen

Standard ist **aus**; nichts wird gesendet, bevor der Nutzer eingewilligt hat. Fünf Schalter in der App (die Stufen bauen aufeinander auf; Erweiterung „Bild und Playlist“ additiv in `v1`):

| Schalter | Wirkung | Voraussetzung |
|---|---|---|
| `share_status` | App-Status (`status`), `heartbeat`, Ereignisse **ohne** Inhaltsangaben | Kopplung |
| `share_titles` | `media` (Titel, Sender, Serie/Staffel/Folge, Typ, Position, Laufzeit) in `state` und Ereignissen | `share_status` |
| `share_subscription` | `sub` (Abo-Ablauf, Verbindungen) im `heartbeat` | `share_status` |
| `share_artwork` | `picture` (Cover-/Logo-URL) in `state` | `share_titles` |
| `share_playlist` | `playlist` im `heartbeat`, Ereignisse `playlist_refreshed`/`playlist_failed` | `share_status` |

Ohne `share_status` sendet die App gar nichts (auch keinen Herzschlag). Ohne `share_titles` fehlt `media` überall. Der Steuerkanal (Abschnitt 6) braucht zusätzlich den Schalter `allow_control`.

### 5.2 `state`

Wird bei jeder Änderung gesendet (Start, Pause, Titelwechsel, Seek, Ende, App-Start), mit höchstens 1/s.

| Feld | Typ | Pflicht | Grenzen / Werte | Einwilligung |
|---|---|---|---|---|
| `rev` | int | ja | 0 … 2^53−1; Zähler der gesendeten Zustände seit App-Start, wird in `heartbeat.state_rev` wiederholt | status |
| `status` | string | ja | `idle` (App aktiv, nichts läuft), `buffering`, `playing`, `paused`, `closed` (App wird ordentlich beendet, Best-Effort) | status |
| `media` | object | nein | nur bei `status` ∈ `buffering`, `playing`, `paused` | titles |
| `picture` | string | nein | URL nach 5.2a; nur zusammen mit `media`; höchstens 512 Zeichen | artwork |

`media`:

| Feld | Typ | Pflicht | Grenzen |
|---|---|---|---|
| `kind` | string | ja | `live`, `movie`, `episode`, `trailer`, `other` |
| `title` | string | nein | 1–120 Codepunkte (Livesender: Sendungstitel, falls bekannt) |
| `channel` | string | nein | 1–80; nur bei `kind = live` |
| `series` | string | nein | 1–120; nur bei `episode` |
| `season` | int | nein | 0–999; nur bei `episode` |
| `episode` | int | nein | 0–9999; nur bei `episode` |
| `duration_ms` | int | nein | 0–172800000 (48 h); nicht bei `live` |
| `position_ms` | int | nein | 0–172800000; nicht bei `live`; ≤ `duration_ms`, wenn beide da |

HA schätzt die Position bei `playing` selbst weiter (Position + Zeit seit Empfang) und gleicht mit der nächsten Meldung ab. Die App sendet Position nur bei Zustandsänderung, nicht fortlaufend.

### 5.2a Verhalten von HA nach Zuständen

- **Start von HA:** `ha_state_rev` ist unbekannt (`null`); der erste `heartbeat` löst immer `resync:true` aus (Vektor `heartbeat_after_restart`).
- **Nach `closed`:** Der Player bleibt „aus“, der Verfügbarkeits-Timer ruht, bis wieder ein Zustand eintrifft. `buffering` wird als „Puffern“ gezeigt, ein unbekannter Status als „Leerlauf“.
- **Nach 90 s Stille:** Zustand und Titel werden verworfen. Der Binär-Sensor „App aktiv“ ist immer verfügbar (aus statt nicht verfügbar).
- **Abo-Ablauf:** Das Protokoll liefert nur ein Datum; HA setzt den Beginn dieses Tages in der HA-Zeitzone.

### 5.2a `picture` (Cover oder Senderlogo)

Additiv in `v1`: Ältere Integrationen ignorieren das Feld (unbekannte Felder werden ignoriert), ältere Apps senden es nicht (die Integration toleriert sein Fehlen). `picture` ist die URL eines Bildes des **Film-Covers, Serien-Covers oder Senderlogos** und wird nur mit `share_artwork` (Standard aus, setzt `share_titles` voraus) und nur zusammen mit `media` gesendet. Läuft geschützter Inhalt (5.7 Nr. 3), fehlt `picture` ebenso.

Anforderungen (App prüft vor dem Senden, Integration prüft beim Empfang **dasselbe strikt**). **Maßgeblich ist `reference.py: picture_ok` mit den festen Erwartungen in `vectors.json` (`picture_urls`)**; das JSON-Schema (5.6) ist nur ein Vorfilter. Die Prüfung ist rein syntaktisch, ohne DNS-Auflösung, und lässt sich in Python, Kotlin und JavaScript ohne Bibliotheksfunktionen wie `is_global` nachbauen.

1. **Zeichen und Länge:** 1–512 Zeichen, nur ASCII `0x21`–`0x7E` (kein Leerzeichen, keine Steuerzeichen, kein Backslash, kein `#`/Fragment). Nicht-ASCII-Hosts als Punycode, Pfade und Werte prozentkodiert.
2. **Aufbau:** `^(https?)://([^/?]*)([^?]*)(\?(.*))?` mit **kleingeschriebenem** Schema `http` oder `https` (alles andere, auch `javascript:`, `file:`, `data:`, `ftp:`, `//…` und `HTTPS:`, ist ungültig). Prüfungen mit **ganzer Übereinstimmung** (`fullmatch`, `\A…\z`), nie mit `$` (kann ein angehängtes LF durchlassen).
3. **Userinfo:** kein `@` in der Autorität.
4. **Host und Port:**
   - Eckige Klammern **nur** bei einem IPv6-Literal (Hexziffern, `:` und `.` zwischen den Klammern, ohne Zone-ID); Klammern um Hostnamen oder IPv4 sind ungültig, ebenso offene oder nachgestellte Zeichen.
   - Port optional, **genau** `[1-9][0-9]{0,4}` und ≤ 65535. Ungültig: `:` ohne Ziffern, `:0`, führende Nullen, Vorzeichen, Buchstaben, > 65535.
   - IPv4-Literal nur strikt dezimal `a.b.c.d` (je `0` oder ohne führende Null, ≤ 255). Dezimal-, Oktal-, Hex- und Kurzschreibweisen (`2130706433`, `0x7f.1`, `127.1`, `010.0.0.1`) sind ungültig (ein Host, dessen letztes Label nur aus Ziffern besteht oder mit `0x` beginnt, ist ungültig).
   - Hostname: Kleinschreibung, mindestens zwei Labels `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, höchstens 253 Zeichen, kein Punkt am Ende.
5. **Sperrliste Hostnamen:** `localhost` und alles darunter, sowie die Endungen `.test`, `.invalid`, `.example`, `.local`, `.localhost`, `.internal`, `.lan`, `.home.arpa`, `.localdomain`, `.corp`, `.home`, `.intranet`, `.private`.
6. **Sperrliste IP-Literale (normativ, keine `is_global`-Funktion):** Eine Adresse in einem dieser Bereiche macht die URL ungültig.

   | IPv4 | IPv6 |
   |---|---|
   | 0.0.0.0/8 | ::/128, ::1/128 |
   | 10.0.0.0/8 | ::/96 (IPv4-kompatibel) |
   | 100.64.0.0/10 | ::ffff:0:0/96 (IPv4-gemappt, **immer gesperrt**, auch bei öffentlicher IPv4) |
   | 127.0.0.0/8 | 64:ff9b::/96 (NAT64, gesperrt) |
   | 169.254.0.0/16 | 64:ff9b:1::/48 |
   | 172.16.0.0/12 | 100::/64 |
   | 192.0.0.0/24, 192.0.2.0/24 | 2001::/32 (Teredo) |
   | 192.88.99.0/24 | 2001:db8::/32 |
   | 192.168.0.0/16 | 2002::/16 (6to4, gesperrt) |
   | 198.18.0.0/15, 198.51.100.0/24 | fc00::/7 |
   | 203.0.113.0/24 | fe80::/10 |
   | 224.0.0.0/4 (Multicast) | fec0::/10 (Site-Local, veraltet), 2001:10::/28 |
   | 240.0.0.0/4, 255.255.255.255/32 | ff00::/8 (Multicast), ::ffff:0:0:0/96 (SIIT) |

7. **Query:** Trenner sind `&` **und** `;`; `+` zählt als Leerzeichen; Namen und Werte werden **genau einmal** prozentdekodiert (UTF-8, streng). Eine ungültige %-Folge (`%zz`, `%`, `%0`), ungültiges UTF-8 oder ein NUL-/Steuerzeichen im dekodierten Namen oder Wert macht die **ganze URL ungültig** (auch im Pfad). Der dekodierte Name wird in Kleinbuchstaben umgewandelt, `-`, `_` und Leerzeichen werden entfernt; ist das Ergebnis eines von `username`, `user`, `usr`, `login`, `uid`, `password`, `pass`, `passwd`, `pw`, `pwd`, `token`, `accesstoken`, `key`, `apikey`, `auth`, `authorization`, `secret`, `sig`, `signature`, `xamzsignature`, `xamzcredential`, `xamzsecuritytoken`, `session`, `sessionid`, `sid`, `ticket`, `credential`, `bearer`, ist die URL ungültig (Beispiele: `user_name`, `X-Amz-Signature`, `to+ken`, `%74oken`). Zweifach kodierte Namen (`%2570assword`) werden nur einmal dekodiert und bleiben unauffällig, weil der Bildserver ebenfalls nur einmal dekodiert.
8. **Pfad:** Der Pfad wird **als Ganzes einmal** prozentdekodiert (ein kodiertes `%2F` wird dabei zum Segmenttrenner) und dann an `/` in Segmente geteilt. Der Vergleich ist **ohne Beachtung der Groß-/Kleinschreibung** (auch Hostnamen werden klein geschrieben verglichen): ist ein Segment genau `live`, `movie`, `series`, `vod`, `stream` oder `hls`, oder endet es auf `.ts`, `.m3u8`, `.m3u`, `.mp4`, `.mkv`, `.avi` oder `.mp3` (also auch `Movie`, `.MP4`, `a%2Flive`), ist die URL ungültig (Stream-/Xtream-Muster wie `/movie/<user>/<pass>/1.mp4`). Die Integration prüft das ohne Kenntnis der Zugangsdaten.
9. **Herkunft (nur App, Pflicht):** Die URL stammt ausschließlich aus dem Bild-/Logo-Feld des Katalogeintrags, nie aus Stream-, Playlist- oder Anbieter-Zugangs-URLs. Die App **verwirft `picture`**, wenn der Benutzername oder das Passwort des Nutzers (nicht leer) im **Pfad oder in der Query** vorkommt (Schema und Host zählen nicht), **ohne Beachtung der Groß-/Kleinschreibung**: bei weniger als 4 Zeichen nur als **vollständiges Pfadsegment oder vollständiger Query-Wert**, ab 4 Zeichen als **Teilzeichenkette** in Pfad oder Query, jeweils roh oder einmal dekodiert (auch `+` als Leerzeichen); `picture_has_credentials`, Vektoren `app_credential_cases` (kurze Namen `a`, `com`, `http`, Sonderzeichen `p@ss`, `a b`, `a+b`, Umlaute, Großschreibung, Teilstrings). Doppelt kodierte oder auf mehrere Segmente verteilte Werte werden nicht erkannt (Restrisiko, 8.3a). Im Zweifel nicht senden. Ändern oder „Säubern“ der URL ist verboten.
10. **Unbekannte Felder:** Die App sendet in `playlist`, `media`, `sub` und im Rest der Nachricht nur die hier definierten Felder. Die Integration **verwirft nach erfolgreicher Prüfung unbekannte Felder in allen Objekten** (`state`, `media`, `heartbeat`, `sub`, `playlist`, `event`, `unpair`), speichert und loggt sie nicht. Eine Nachricht mit **unbekanntem `type`** oder ein `event` mit **unbekanntem Namen** wird mit `200 ignored` angenommen und **vollständig verworfen** (nichts gespeichert, nichts geloggt). Vektoren `strip_unknown`.

Die Integration setzt die URL als `entity_picture_remote_url` (HA-Frontend und Clients laden das Bild selbst); sie lädt **keine** Bilder serverseitig und speichert sie nicht. Verletzt `picture` die Regeln: `422 bad_payload` (Sequenz verbraucht). Vektoren: `picture_urls` (204 Fälle mit von Hand eingetragenen Erwartungen, nicht aus der Referenz erzeugt), `app_credential_cases`, `payloads`.

### 5.3 `heartbeat`

Alle 30 s, solange die App im Vordergrund läuft und `share_status` an ist.

| Feld | Typ | Pflicht | Grenzen |
|---|---|---|---|
| `app_version` | string | ja | Muster `^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(-[A-Za-z0-9.]{1,16})?$`, ≤ 32 |
| `platform` | string | ja | `android` (auch Fire TV) oder `tizen` |
| `state_rev` | int | ja | `rev` des zuletzt gesendeten `state` (0, wenn noch keiner) |
| `ws` | bool | nein | Steuerkanal verbunden |
| `sub` | object | nein | nur mit `share_subscription` |
| `playlist` | object | nein | nur mit `share_playlist` |

`sub`: `expires` (string `YYYY-MM-DD`, gültiges Datum, oder `null`), `connections_active` (int 0–99), `connections_max` (int 0–99), alle optional.

`playlist` (additiv in `v1`, Zustand der geladenen Playlist, **keine Adressen, keine Namen von Kategorien oder Titeln**): alle Felder optional:

| Feld | Typ | Grenzen |
|---|---|---|
| `updated` | string oder `null` | UTC, genau `YYYY-MM-DDTHH:MM:SSZ` mit ASCII-Ziffern, gültiges Datum und gültige Uhrzeit (kein Offset, kein Bruchteil, kein angehängtes Zeichen) |
| `live`, `movies`, `series` | int | 0–999999 (Anzahl Einträge) |
| `error` | string | `none`, `no_network`, `unauthorized`, `server_error`, `connection_lost`, `storage`, `other` |

Der Wert von `error` beschreibt nur die Art des letzten Fehlers, nie den Fehlertext des Anbieters. Unbekannte Felder in `playlist` (und in allen anderen Objekten) sendet die App nie; die Integration verwirft sie (5.2a Nr. 10).

Stimmt `state_rev` nicht mit dem zuletzt von HA verarbeiteten `rev` überein (HA neu gestartet, Meldung verloren), setzt HA in der Antwort `"resync":true`; die App sendet sofort einen vollständigen `state`. HA markiert die Entität als verfügbar, solange Herzschläge eintreffen, und als nicht verfügbar, wenn **90 s** (drei verpasste) nichts Gültiges kommt (Startwerte, am Gerät zu prüfen).

### 5.4 `event`

| Feld | Typ | Pflicht | Grenzen |
|---|---|---|---|
| `name` | string | ja | `^[a-z_]{1,32}$`. Bekannt: `playback_started`, `playback_stopped`, `channel_changed`, `trailer_opened`, `playlist_refreshed`, `playlist_failed`; unbekannte Namen werden angenommen und ignoriert |
| `reason` | string | nein | nur bei `playback_stopped`: `ended`, `user`, `error` |
| `media` | object | nein | wie in `state`, nur mit `share_titles` (z. B. `channel_changed`: `{"kind":"live","channel":…}`; `trailer_opened`: `{"kind":"trailer","title":…}`) |

`error` (Pflicht bei `playlist_failed`, dort ein Wert aus der Menge von `playlist.error` außer `none`; sonst verboten): Ereignisse `playlist_refreshed` und `playlist_failed` gibt es nur mit `share_playlist`, ohne weitere Felder (keine Adressen, keine Namen).

Ereignisse tragen in HA nur die erlaubten Felder in das Ereignis `itrend_player_event` auf dem HA-Bus ein.

### 5.5 Fehlerverhalten der App beim Senden

HA nicht erreichbar, Fehler oder Zeitüberschreitung (5 s): **nichts puffern**, kein Nachsenden alter Zustände. Nächster Versuch beim nächsten Herzschlag (30 s) oder bei der nächsten Zustandsänderung, mit dem dann aktuellen Zustand. Wiederholungen mit Pause (mindestens 5 s, bei Fehlern bis 60 s steigend); die Einstellungen zeigen „nicht verbunden“.

### 5.6 JSON-Schemas (Referenz, JSON Schema 2020-12)

`additionalProperties` ist absichtlich offen (unbekannte Felder werden ignoriert). Gleichheit in Codepunkten statt UTF-16 und der Ausschluss von Steuerzeichen sind im Muster nur genähert; maßgeblich ist die Beschreibung oben und `reference.py`.

```json
{
  "$defs": {
    "text": {"type": "string", "pattern": "^[^\\u0000-\\u001f\\u007f]+$"},
    "ms": {"type": "integer", "minimum": 0, "maximum": 172800000},
    "media": {
      "type": "object",
      "required": ["kind"],
      "properties": {
        "kind": {"enum": ["live", "movie", "episode", "trailer", "other"]},
        "title": {"$ref": "#/$defs/text", "maxLength": 120},
        "channel": {"$ref": "#/$defs/text", "maxLength": 80},
        "series": {"$ref": "#/$defs/text", "maxLength": 120},
        "season": {"type": "integer", "minimum": 0, "maximum": 999},
        "episode": {"type": "integer", "minimum": 0, "maximum": 9999},
        "duration_ms": {"$ref": "#/$defs/ms"},
        "position_ms": {"$ref": "#/$defs/ms"}
      }
    }
  },
  "oneOf": [
    {"properties": {"v": {"const": 1}, "type": {"const": "state"},
       "rev": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
       "status": {"enum": ["idle", "buffering", "playing", "paused", "closed"]},
       "media": {"$ref": "#/$defs/media"},
       "picture": {"type": "string", "maxLength": 512, "pattern": "^https?://[\\x21-\\x7e]+$"}},
     "required": ["v", "type", "rev", "status"]},
    {"properties": {"v": {"const": 1}, "type": {"const": "heartbeat"},
       "app_version": {"type": "string", "maxLength": 32,
          "pattern": "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(-[A-Za-z0-9.]{1,16})?$"},
       "platform": {"enum": ["android", "tizen"]},
       "state_rev": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
       "ws": {"type": "boolean"},
       "playlist": {"type": "object", "properties": {
          "updated": {"type": ["string", "null"], "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},
          "live": {"type": "integer", "minimum": 0, "maximum": 999999},
          "movies": {"type": "integer", "minimum": 0, "maximum": 999999},
          "series": {"type": "integer", "minimum": 0, "maximum": 999999},
          "error": {"enum": ["none", "no_network", "unauthorized", "server_error", "connection_lost", "storage", "other"]}}},
       "sub": {"type": "object", "properties": {
          "expires": {"type": ["string", "null"], "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
          "connections_active": {"type": "integer", "minimum": 0, "maximum": 99},
          "connections_max": {"type": "integer", "minimum": 0, "maximum": 99}}}},
     "required": ["v", "type", "app_version", "platform", "state_rev"]},
    {"properties": {"v": {"const": 1}, "type": {"const": "event"},
       "name": {"type": "string", "pattern": "^[a-z_]{1,32}$"},
       "reason": {"enum": ["ended", "user", "error"]},
       "media": {"$ref": "#/$defs/media"}},
     "required": ["v", "type", "name"]},
    {"properties": {"v": {"const": 1}, "type": {"const": "unpair"}},
     "required": ["v", "type"]}
  ]
}
```

**Das Schema ist nur ein Vorfilter; maßgeblich sind `reference.py` und die Vektoren.** Die Muster mit `^…$` gelten als ganze Übereinstimmung; Implementierungen MÜSSEN `fullmatch` oder `\A…\z` benutzen (in manchen Engines lässt `$` ein angehängtes LF durch). Ziffern sind überall nur ASCII `[0-9]` (kein `\d`, das Unicode-Ziffern wie `٢` oder `２` annimmt; Vektoren `playlist_updated_arabic_digits_bad`, `heartbeat_expires_fullwidth_digits_bad`). Zusatzregeln, die das Schema nicht ausdrückt (aber `reference.py` prüft): `picture` nur zusammen mit `media` und nach den URL-Regeln aus 5.2a; `error` bei Ereignissen nur bei `playlist_failed`, dort Pflicht und nicht `none`; `media` nur bei `status` ∈ `buffering/playing/paused`; `series/season/episode` nur bei `kind = episode`; `channel` nur bei `live`; keine Position oder Laufzeit bei `live`; `position_ms ≤ duration_ms`; Datum `expires` muss existieren; `reason` nur bei `playback_stopped`; Ganzzahlen dürfen keine Gleitkommadarstellung (`5.0`, `5e2`) und keine Booleans sein.

### 5.7 Was NIE gesendet wird

Die App DARF NICHT senden, und die Integration DARF NICHT annehmen, speichern oder loggen:

1. Benutzername, Passwort oder sonstige **Zugangsdaten** zum Anbieter; Tokens, Schlüssel, Code der Kopplung.
2. **Adressen**: Playlist-URL, Xtream-Server-URL, Stream-URLs, Adresse des Anbieters in jeder Form (auch Teile, Hostnamen). **Einzige Ausnahme:** `picture` (5.2a) mit der Bild-/Logo-URL aus dem Katalog, nur mit `share_artwork` und nur nach den dortigen Regeln; auch dann nie Stream-, Playlist- oder Zugangs-URLs. Playlist-Status (`playlist`) enthält nie Adressen, Kategorien- oder Titelnamen.
3. **Inhalte hinter einer Erwachsenen-PIN**: Läuft ein geschützter Inhalt, sendet die App `status` wie üblich, aber **ohne `media`** und ohne Titel in Ereignissen, **ohne** Kennzeichnung, dass es geschützt ist. Der Zustand ist von „Titel-Freigabe aus“ nicht zu unterscheiden. Auch Trailer-/Suchverläufe dazu entfallen.
4. Name oder Nummer des Anbieters, Kontonummern, E-Mail, Name des Nutzers, Gerätekennungen des Fernsehers (Seriennummer, MAC, Werbe-ID), Standort, WLAN-Name.
5. Suchbegriffe, Favoritenlisten, Wiedergabeverlauf als Liste, Playlist-Inhalt, Programmführer (EPG) als Ganzes.
6. Fehlertexte aus dem Player oder Netz, Stack-Traces, Log-Zeilen.
7. Dateipfade, Rohdaten der Nutzereingabe.

---

## 6. WebSocket-Befehlskanal (Stufe 3)

**Stufe 3 wird erst nach einer unabhängigen Sicherheitsprüfung dieses Abschnitts freigegeben.** Die App öffnet den Kanal nur, wenn `allow_control` an ist und die App im Vordergrund läuft.

### 6.1 Verbindung und Handshake

App verbindet zu `ws(s)://<host>/api/itrend_player/ws` (Schema nach Basisadresse: `http` → `ws`, `https` → `wss`). Alle Nachrichten sind JSON-Textrahmen, ≤ 1024 Byte, mit `type`. Das Handshake hat **10 s** Zeitgrenze (sonst Schließen `4408`).

1. App → HA: `{"type":"hello","v":1,"device_id":D,"nonce":Na}` — `Na`: 16 Zufallsbytes base64url.
2. HA → App: `{"type":"challenge","v":1,"nonce":Nh,"proof":Ph}` — `Nh`: 16 Zufallsbytes. Ist `D` unbekannt, schließt HA mit `4401` (gleiche Antwort wie bei falschem Beweis).
   `Ph = base64url(HMAC(K_h2a, LP("ITP1-WS-H", D, Na, Nh)))` — beweist der App, dass HA den Schlüssel kennt. Prüft die App `Ph` nicht erfolgreich, schließt sie.
3. App → HA: `{"type":"auth","proof":Pa}`
   `Pa = base64url(HMAC(K_a2h, LP("ITP1-WS-A", D, Na, Nh)))`.
4. HA prüft `Pa` (konstante Zeit) → `{"type":"ready","v":1}` oder `{"type":"error","code":"bad_signature"}` und Schließen `4401`.

`Na` und `Nh` sind je Verbindung neu; damit sind Handshake-Beweise nicht wiederholbar. Die **Verbindungskennung** ist `sid = Na ‖ "." ‖ Nh` (die beiden base64url-Texte). Je Gerät gilt höchstens **eine** Verbindung; eine neue ersetzt die alte (alte wird mit `4409` geschlossen).

Schließcodes: `4400` bad_request, `4401` Authentisierung, `4408` Zeitüberschreitung, `4409` ersetzt, `4410` Kopplung beendet, `4426` Version, `4429` Rate-Limit.

### 6.2 Nonce für Befehle (Challenge je Befehl)

Jeder Befehl braucht eine **von der App ausgegebene, einmalige Nonce**. Die App hält zu jedem Zeitpunkt höchstens **eine** gültige Nonce.

- Nach `ready` und danach alle **8 s** (und nach jedem verbrauchten Befehl, siehe `ack`) sendet die App `{"type":"nonce","value":N,"mac":M}` mit `N`: 16 neue Zufallsbytes (22 Zeichen), `M = base64url(HMAC(K_a2h, LP("ITP1-NONCE", D, sid, N)))`. Die neue Nonce ersetzt die vorige sofort (die vorige ist ungültig).
- HA speichert die zuletzt erhaltene, MAC-geprüfte Nonce.
- Gültigkeit: bis zum Ersetzen oder Verbrauch, **höchstens 10 s** nach Ausgabe (gemessen mit der **monotonen** Uhr der App: `System.nanoTime()` bzw. `performance.now()`, nicht mit `Date.now()`).
- **Abstimmung mit dem HA-Timeout (Befund 3):** HA sendet einen Befehl nur mit einer Nonce, die höchstens **8 s** vorher empfangen wurde, und erklärt ihn **11 s nach Empfang dieser Nonce** für verloren (Timeout, 1 s Reserve für Laufzeit). Da die App die Nonce spätestens 10 s nach Ausgabe verwirft und der Empfang bei HA nie vor der Ausgabe liegt, ist ein von einem Angreifer zurückgehaltener Befehl nach dem HA-Timeout **nicht mehr ausführbar**. HA wiederholt einen Befehl nach Timeout nicht.

### 6.3 Befehl HA → App

```json
{"type":"command","id":"<16 Byte b64u>","nonce":"<N>","cmd":"play","arg":"","sig":"<b64u>"}
```

| `cmd` | `arg` (immer String) | Wirkung |
|---|---|---|
| `play` | `""` | Wiedergabe fortsetzen/starten (nur wenn Medium geladen) |
| `pause` | `""` | |
| `stop` | `""` | |
| `seek_relative` | `"-10000"` oder `"10000"` | ±10 s (nur bei Medien mit Position, nicht Live) |
| `next` | `""` | nächster Titel/Folge (wenn vorhanden) |
| `previous` | `""` | vorheriger Titel/Folge |
| `unpair` | `""` | HA beendet die Kopplung (immer erlaubt, auch ohne `allow_control`) |

`id`: 16 Zufallsbytes base64url (genau 22 Zeichen), von HA je Befehl neu. `nonce`: genau 22 Zeichen. `sig`: genau 43 Zeichen. `sig = base64url(HMAC(K_h2a, LP("ITP1-CMD", D, sid, nonce, id, cmd, arg)))`. Alle Felder sind Strings; es gibt keine Zahlenkanonisierung.

Die App prüft in dieser Reihenfolge und führt **nur bei vollständigem Erfolg** aus:

1. **Strenges Format:** `id` und `nonce` genau 22 Zeichen base64url (kanonisch, 16 Byte), `sig` genau 43 Zeichen (32 Byte), `cmd` und `arg` Strings mit höchstens 16 Zeichen, alle Felder vorhanden → sonst `rejected/bad_request`. Die `id` des `ack` ist dann **leer** (`""`), weil eine formal ungültige `id` nicht zurückgespiegelt wird;
2. Signatur (konstante Zeit) → `rejected/bad_sig`, `ack`-`id` leer. **Die Nonce bleibt unverändert** (wer den Schlüssel nicht hat, kann sie nicht „verbrennen“; Begründung der Wahl: würde jede Ablehnung die Nonce rotieren, könnte ein Angreifer im Netz mit beliebigen Rahmen ständig die Nonce wechseln und echte Befehle auflaufen lassen);
3. `nonce` = die aktuelle ausstehende Nonce und nicht abgelaufen → `rejected/stale_nonce` (Signatur war gültig, also von HA; Nonce bleibt, `next_nonce` = die aktuelle). **Erst ab hier ist der Befehl echt und aktuell: die Nonce wird verbraucht**, und jedes weitere Ergebnis (auch Ablehnung) liefert eine neue `next_nonce`;
4. `id` nicht unter den letzten 64 gesehenen → `rejected/duplicate_id`;
5. `cmd` und `arg` aus der Tabelle → `rejected/unsupported`;
6. `unpair` → ausführen; sonst `allow_control` an → `rejected/control_disabled`;
7. läuft nichts (außer bei `play`) → `rejected/nothing_playing`;
8. Ausführung; bei Fehler im Player `failed/error`, spätestens nach 5 s `failed/timeout`.

### 6.4 Bestätigung (`ack`)

Die App antwortet auf **jeden** Befehl:

```json
{"type":"ack","id":"<id oder leer>","result":"ok","reason":"","next_nonce":"<N2>","mac":"<b64u>"}
```

`result`: `ok`, `rejected`, `failed`. `reason`: leer bei `ok`, sonst `bad_request`, `bad_sig`, `stale_nonce`, `duplicate_id`, `unsupported`, `control_disabled`, `nothing_playing`, `error`, `timeout`. `next_nonce`: die neue Nonce (ersetzt die verbrauchte). `mac = base64url(HMAC(K_a2h, LP("ITP1-ACK", D, sid, id, result, reason, next_nonce)))`. **HA prüft den `ack` strikt:** alle fünf Felder vorhanden und Strings; `id` leer oder genau 22 Zeichen; `next_nonce` 22, `mac` 43 Zeichen, kanonisch; `result` und `reason` aus den festen Mengen, `reason` leer genau bei `ok`; MAC konstantzeitig; `id` gleich der ausstehenden Befehls-`id` (nur bei `bad_request`/`bad_sig` darf sie leer sein). Alles andere: Verbindung schließen (`4400`). Zu `next_nonce`: Bei Ablehnung wegen `bad_request`/`bad_sig`/`stale_nonce` ist sie die unveränderte aktuelle Nonce; sonst die frisch erzeugte.

HA wartet auf den `ack` bis **11 s nach Empfang der verwendeten Nonce** (6.2); sonst gilt der Befehl als nicht bestätigt (`timeout`) und wird **nicht** wiederholt (er könnte trotzdem ausgeführt worden sein). Bei `stale_nonce` darf HA **einmal** mit der inzwischen neuesten Nonce neu senden (neue `id`). Eine `seek_relative`-Wiederholung nach `timeout` ist nicht zulässig.

### 6.5 Zeitlimits, Wiederholungsschutz, Raten

- Nonce einmalig und kurzlebig (6.2), `id` einmalig (6.3), Signatur bindet `sid` (kein Wiederverwenden auf anderer Verbindung), Richtungsschlüssel getrennt.
- Ablauf: Nonce ≤ 10 s, Erneuerung alle 8 s, HA-Timeout 11 s nach Empfang der Nonce (6.2); Ausführung in der App spätestens nach 5 s `failed/timeout`. Ein Befehl ohne `ack` gilt in HA als verloren und kann wegen des Nonce-Ablaufs nicht mehr ausgeführt werden.
- Rate: HA sendet je Gerät höchstens 5 Befehle pro Sekunde; die App verwirft über 10 pro Sekunde (`rejected/unsupported` nicht senden, stillschweigend schließen mit `4429`).
- Zusätzlich SOLL die App vor `seek_relative` die Position gegen den Bereich prüfen und bei Überlauf an die Grenze klemmen.

### 6.6 Liveness und Verbindungsabbruch

- HA sendet alle 20 s `{"type":"ping"}`, die App antwortet `{"type":"pong"}`. Ohne `pong` binnen 10 s schließt HA. Die App schließt und verbindet neu, wenn 60 s lang nichts von HA kam. (Anwendungsebene, weil die Tizen-WebSocket-API keine Ping-Rahmen sendet.)
- Verbindungsabbruch verwirft alle Nonces und ausstehenden Befehle. Neuaufbau mit Backoff 1, 2, 4, … höchstens 60 s, plus ±20 % Zufall; solange die App im **Vordergrund** und `allow_control` an ist.
- App im Hintergrund oder Standby: Verbindung wird geschlossen (`1001`), keine Befehle zugesagt. HA lehnt Befehle ohne Verbindung sofort ab („Gerät nicht erreichbar; Steuerung nur bei geöffneter App“).
- Die Verfügbarkeit der Entitäten folgt dem **Webhook-Herzschlag**, nicht dem WebSocket.

---

## 7. Fehlercodes, Trennen, Adressänderung

### 7.1 Zusammenfassung der Fehlercodes

`bad_request`, `unsupported_version`, `bad_signature`, `seq_too_low`, `payload_too_large`, `bad_payload`, `rate_limited`, `pairing_unavailable`, `pairing_failed`, `session_expired`, `internal` (5xx). Im WebSocket zusätzlich die `reason`-Werte aus 6.4. HTTP-Zuordnung siehe 3.6 und 4.4. Fehlerantworten enthalten nie Teile der Anfrage, nie Schlüssel, nie Adressen.

### 7.2 Trennen von der App aus

Die App sendet (wenn erreichbar) eine signierte Meldung `{"v":1,"type":"unpair"}`, löscht danach **sofort lokal** Schlüssel, `device_id`, `webhook_id`, `reserved_app` und Adresse, und zeigt „nicht gekoppelt“. HA markiert das Gerät als „von der App getrennt“, löscht den Schlüssel, entfernt den Webhook und zeigt in HA eine Reparatur-Meldung („Gerät hat die Kopplung beendet, Eintrag entfernen“). Ist HA nicht erreichbar, bleibt der Eintrag in HA verwaist und verfügbarkeits-`unavailable`; der Nutzer löscht ihn in HA. Eine Meldung ohne Erfolg wird nicht wiederholt.

### 7.2a Erneute Kopplung („Kopplung erneuern“)

Wird ein Gerät erneut gekoppelt, gelten **neue** `device_id`, `webhook_id` und Schlüssel; Sequenzspeicher und Reservierung werden zurückgesetzt, alte Reparatur-Meldungen gelöscht. Die Geräte-Kennung in HA (Entitäten, Verlauf) ist **unabhängig von der `device_id`** des Protokolls (die Integration nutzt die `entry_id`), damit die Entitäten erhalten bleiben. Meldet die App `unpair`, löscht die Integration Schlüssel und Webhook, legt eine nicht behebbare Reparatur-Meldung an und startet den Erneuerungs-Ablauf.

### 7.3 Trennen von HA aus

Löscht der Nutzer das Gerät in HA, entfernt die Integration Schlüssel und Webhook (und schickt, wenn der Kanal offen ist, `command unpair`). Die App erkennt es an „3 aufeinanderfolgenden unbestätigten Antworten“ (4.4) oder am `unpair`-Befehl und meldet „Kopplung erneuern“; der Nutzer kann dort trennen (lokal löschen) oder neu koppeln. Die alte `device_id` wird nicht wiederverwendet.

### 7.4 Adressänderung ohne neue Kopplung

Ändert sich die Adresse von HA (neue IP, anderer Port, `http` → `https`), trägt der Nutzer in der App die neue **Basisadresse** ein. Schlüssel, `device_id`, `webhook_id` und Sequenz bleiben. Weil der signierte Pfad die Adresse nicht enthält, ist die Signatur unverändert gültig. Die App prüft die neue Adresse mit einem `heartbeat` und akzeptiert sie erst, wenn die Antwort einen **gültigen `proof`** trägt (4.5): damit ist belegt, dass dort wirklich HA mit diesem Gerät antwortet. Ohne gültigen Beweis bleibt die alte Adresse gespeichert, und die App zeigt „Adresse nicht bestätigt“. Während der Prüfung gesendete Zustandsdaten gehen an die neue Adresse (Heartbeat enthält keine Titel; die App sendet bis zur Bestätigung nur den Heartbeat, ohne `sub`).

---

## 8. Sicherheit, Datenschutz, Logs

### 8.1 Bedrohungsmodell

Ein Angreifer im selben Netz (WLAN, kompromittiertes Gerät) kann Datenverkehr mitlesen, verzögern, löschen und Anfragen an HA senden. Er kennt weder Schlüssel noch Code (bei richtigem Ablauf). Nicht abgedeckt: Kompromittierung von HA oder der App selbst, Root auf dem Fernseher, böswilliger Nutzer.

### 8.2 Einwilligung (App)

Vor der ersten Kopplungsanfrage zeigt die App eine Seite, die in einfacher Sprache nennt: was gesendet wird (abhängig von den Schaltern), **dass die Übertragung bei `http` unverschlüsselt ist** (Titel sind im Heimnetz mitlesbar; die Signatur schützt Echtheit, nicht Vertraulichkeit), dass `https` empfohlen ist, dass nichts an iTrend24 oder Dritte geht, dass die Funktion jederzeit trennbar ist. Für `share_artwork` nennt der Text zusätzlich: „Gesendet wird die Adresse (URL) des Cover- oder Senderbildes, wie sie Ihr Anbieter liefert. Home Assistant bzw. Ihre Geräte laden das Bild später von diesem Anbieter-Server; der Anbieter-Server und seine Adresse werden dadurch in Ihrem Heimnetz bzw. in Home Assistant sichtbar, und der Anbieter kann sehen, dass das Bild abgerufen wird.“ Für `share_playlist`: „Gesendet werden Zeitpunkt der letzten Aktualisierung, Anzahl der Einträge und eine Fehlerart, keine Adressen oder Namen.“ Beide Schalter sind einzeln, Standard aus. Zustimmung ist ausdrücklich (Schalter/Bestätigung), Standard aus, widerrufbar, und je Schalter einzeln. Der Wortlaut ist rechtlich zu prüfen.

### 8.3 Bekannte Restrisiken

1. **Klartext über `http`**: Inhalte der Meldungen (Titel, Sender, Abo-Ablauf) sind mitlesbar; Befehle sind unverschlüsselt, aber signiert. Das ist eine bewusste Einschränkung für Heimnetz-HA ohne Zertifikat.
2. **Verzögerte Zustellung**: Ein Angreifer im Pfad kann gültige Meldungen zurückhalten und später ausliefern (innerhalb der Sequenzfolge); HA zeigt dann einen veralteten Zustand. Gegenmaßnahme nur teilweise: nachfolgende Meldungen mit höherer Sequenz machen zurückgehaltene ungültig; Befehle sind durch die kurzlebige App-Nonce (≤ 10 s, an den HA-Timeout gekoppelt, 6.2) nicht verzögert nutzbar.
3. **Kein Schlüsselspeicher auf Tizen**: Das Geheimnis liegt im App-Speicher; es ist nicht als „verschlüsselt“ zu bewerben. Rootzugang oder Debug-Zugriff auf das Gerät legt es offen.
4. **Android**: Geheimnis in app-privatem Speicher; SOLL durch einen Schlüssel im Android Keystore umhüllt werden (AES-GCM), soweit auf Fire-TV-Modellen verlässlich nutzbar (**zu prüfen**, Keystore ist auf manchen Geräten fehlerhaft). Sicherungen (Auto-Backup) MÜSSEN das Geheimnis ausschließen (`android:allowBackup="false"` oder `fullBackupContent`-Regel).
5. **Kein Vorwärtsgeheimnis nach der Kopplung**: Wer K_a2h später erlangt, kann Aufzeichnungen nur auf Echtheit prüfen, nicht entschlüsseln (es gibt keine Verschlüsselung). Ein Schlüsseltausch ist in `v1` nicht vorgesehen; Erneuerung heißt neu koppeln.
6. **Störung**: Code sperren durch Fehlversuche (3.5), Webhook-Flut, Verbindungsflut, Belegen der Versuche (je Quelladresse begrenzt, 3.4), Rechenlast durch `pair/finish`: Störung, kein Einbruch. Fremde Webseiten im Browser eines Nutzers können wegen `Access-Control-Allow-Origin: *` an die Pairing-Endpunkte senden; Gegenmittel sind das Rate-Limit je Quelladresse und eine mögliche Auswertung von `Origin` (9.5).
7. **Nicht-Konstantzeit** bei Potenzen (3.7).
8. **Quelladresse hinter Proxy** (3.6).
9. Das Protokoll verhindert nicht, dass ein Nutzer in HA die Zustandsverläufe des Recorders speichert; die Dokumentation weist darauf hin (Titel landen sonst im HA-Verlauf).

### 8.3a Sicherheit und Datenschutz von `picture` (Bild-URL)

- **SSRF:** Würde HA oder eine Erweiterung die URL serverseitig laden, könnte eine manipulierte Meldung (nur mit gültiger Signatur, also vom gekoppelten Gerät) HA auf interne Ziele lenken (Router, Metadaten-Dienste, Loopback). Deshalb: strikte Prüfung nach 5.2a Nr. 6, **kein serverseitiges Laden und kein Speichern** durch die Integration; sie setzt nur `entity_picture_remote_url`, das Bild laden Browser und Clients.
- **Zugangsdaten in URLs:** Manche Anbieter betten Zugangsdaten in Bild-Adressen ein (Userinfo, Query, Pfad). Die Regeln 3–5 verhindern die erkennbaren Fälle; Pfad-eingebettete Zugangsdaten sind nicht sicher erkennbar, deshalb gilt die Herkunftsregel (nur Katalog-Bildfeld) und im Zweifel nicht senden.
- **Restrisiken:** (a) HA bzw. die Clients laden das Bild **später** und direkt vom Anbieter-Server: der Anbieter-Host wird für HA (Entitätsattribut, Verlauf, Logs von HA und Browser) sichtbar, der Anbieter sieht Abrufe mit der IP-Adresse des HA-Nutzers; (b) die URL kann trotz Prüfung per DNS auf eine interne Adresse zeigen (**DNS-Rebinding**, die Prüfung ist hostbasiert und löst nichts auf) und wird vom Browser abgerufen, nicht von HA; (c) die URL steht im Entitätsattribut, MUSS wie die Titelattribute vom Recorder ausgenommen sein (nicht dauerhaft speichern) und kann in HA-Dashboards von Dritten mit Zugriff gelesen werden; (d) mit `http` ist die Bild-URL im Netz lesbar. Der Einwilligungstext (8.2) nennt (a).
- **Weiterleitungen und DNS-Namen:** Browser folgen HTTP-Weiterleitungen des Bildservers (auch auf interne Ziele); DNS-Namen wie `127.0.0.1.nip.io` oder `localtest.me` lösen auf Loopback/intern auf und lassen sich syntaktisch nicht ausschließen (Vektoren markieren das als gültig mit Restrisiko). Die Sperrlisten (`.test`, `.invalid`, `.example`, `.local`, `.internal`, `.lan`, `.home.arpa`, `.localdomain`, `.corp`, `localhost` und Unterdomänen) mindern, beseitigen es nicht. Schutz ist, dass **nur der Browser/Client** lädt, nie die Integration oder HA-Core, und dass die Integration die URL nie selbst abruft.
- **Pfad-Zugangsdaten:** Die Pfadverbote (5.2a Nr. 8) und die Prüfung gegen Benutzername/Passwort der App (Nr. 9) decken die bekannten Muster ab; Zugangsdaten in unbekannter Form im Pfad bleiben ein Restrisiko, ebenso doppelt kodierte oder auf mehrere Pfadsegmente verteilte Benutzernamen/Passwörter sowie sehr kurze (unter 4 Zeichen), die nur als ganzes Segment oder ganzer Query-Wert erkannt werden.
- Die Integration DARF die URL nicht ins Log schreiben (8.5).

### 8.4 Datenschutzanforderungen an die Implementierungen

- **App:** Standard aus. Senden nur nach Einwilligung, nur an die eingegebene Adresse. Keine Analyse-Dienste. Alles aus 5.7 ausgeschlossen. Widerruf (Schalter aus, Trennen) wirkt sofort: keine weitere Meldung, Löschen der Schlüssel bei Trennen.
- **Integration:** speichert je Gerät nur Schlüssel (K_a2h, K_h2a im Config-Entry-Speicher von HA), `device_id`, `webhook_id`, `last_seq`, `reserved`, Name, Plattform, App-Version und den **letzten** Zustand im Arbeitsspeicher. Titel und Sender werden nicht dauerhaft vorgehalten (kein „Zustand wiederherstellen“ für Titelfelder). Ereignisse tragen nur erlaubte Felder. Keine Weitergabe an Dritte, keine Cloud.
- Unbekannte Felder werden verworfen, bevor sie in Entitäten, Ereignisse oder Logs gelangen.

### 8.5 Anforderungen an Logs

Logs (App, Integration, Test-Ausgaben) DÜRFEN NICHT enthalten: Code `P`, `a`, `b`, `x`, `S`, `K0`, `K_a2h`, `K_h2a`, Signaturen, Beweise, Nonces, vollständige `webhook_id` (höchstens die ersten 4 Zeichen), Basisadresse mit Zugangsdaten, Zugangsdaten und Adressen des Anbieters, Titel, Sender, Serie oder andere Inhalte der Nutzlast (außer auf der Stufe `debug`, die der Nutzer ausdrücklich einschaltet und die einen Warnhinweis zeigt; selbst dort keine Dinge aus 5.7). Fehlerlogs nennen Fehlercode und Gerätename, nicht den Body. **Grenze unserer Wirkung:** Home Assistant selbst (Core, Webhook-Komponente) schreibt eine nicht registrierte `webhook_id` im Klartext ins Log (z. B. bei einer Anfrage nach Löschen des Geräts). Die Vier-Zeichen-Regel gilt nur für Logs der Integration und der App; der Nutzer wird in der Anleitung darauf hingewiesen, Logs nicht zu veröffentlichen. Die `webhook_id` ist ohnehin kein Geheimnis, das Sicherheit trägt (4.2). Tests und Beispiele nutzen nur die Testdaten aus `vectors.json`.

---

### 8.7 Webhook `local_only` und `allow_remote` (Praxisbefund 2026-10-15)

Die Integration registriert den Webhook standardmäßig mit `local_only=True`. Home Assistant beantwortet Anfragen von **nicht-lokalen Absendern** dann mit **HTTP 200 und leerem Body** („Received remote request for local webhook“). Die App sieht dann `unconfirmed (empty_body)`, „App aktiv“ bleibt aus. Das tritt auf, wenn der Fernseher HA über einen Domainnamen erreicht (Hairpin-NAT: Absender erscheint als öffentliche Router-Adresse), über einen Reverse-Proxy oder Duck-DNS/Nabu-Casa-ähnliche Adressen. Die Pairing-Endpunkte sind nicht davon betroffen, deshalb gelingt die Kopplung, die Meldungen aber nicht.

Abhilfe: Optionen der Integration → „Auch Anfragen von außerhalb des Heimnetzes erlauben“ (`allow_remote`, Standard aus; bei an `local_only=False`, der Eintrag wird neu geladen). Die Sicherheit beruht auf der Signatur jeder Meldung (HMAC, Sequenznummer, Raten-Limits); `local_only` ist nur eine zusätzliche Schicht. Die Integration legt eine Reparatur-Meldung an, wenn die Kopplung von einer nicht-privaten Quelladresse kam. Apps zeigen bei leerem 200-Body den Grund `empty_body` und einen Hinweis auf diese Option. Die Integration ab 0.1.1 enthält die Option.

## 9. Konformität und offene Punkte

### 9.1 Checkliste Integration (HA)

- [ ] Pairing: SRP-6a nach 3.3/3.4 mit Gruppe aus Anhang A (`g = 2`); Randwerte `1 < A,B < N−1`, `u ≠ 0` (`srp_bounds`); Versuch entnehmen und Fehlversuchszähler **vor** der Berechnung; höchstens 2 offene Versuche je Quelladresse; Code aus kryptografischem Zufall; 5 min, einmalig, 3 Fehlversuche; Versuch einmalig und 60 s; Rate-Limit 10/min/Quelladresse; `OPTIONS`-Antwort; CORS auf allen Antworten.
- [ ] `M1` und `M2` stimmen mit `vectors.json` (`pairing`) überein; falscher Code erzeugt ein anderes `M1`.
- [ ] Schlüsselableitung K_a2h/K_h2a stimmt mit den Vektoren.
- [ ] Webhook: Body-Aufbau, Signatur über Rohbytes, PATH aus `webhook_id`, Prüfung vor JSON-Lesen, konstantzeitiger Vergleich.
- [ ] Alle `webhook.cases` aus `vectors.json` ergeben dieselbe HTTP-Antwort, denselben Fehlercode und `last_seq` danach.
- [ ] Lock je Gerät um Prüfen/Speichern/Setzen von `seq`; Erkennung geklonter Schlüssel (4.3); doppelte JSON-Schlüssel abgelehnt; `name` nach 9.6.
- [ ] Sequenz: strenge Erhöhung, Reservierung `seq+99` mit Speichern vor Annahme, `409` mit `proof`, Verbrauch auch bei `422`.
- [ ] Antwort-`proof` nach 4.5, Access-Control-Header am Webhook, `resync`-Logik.
- [ ] `picture`: strikte Prüfung `picture_ok` (alle `picture_urls`, Sperrliste als CIDR-Tabelle, kein `is_global`), `strip_unknown`, `entity_picture_remote_url` setzen, **nie** serverseitig laden oder speichern, nicht ins Log, vom Recorder ausnehmen; fehlendes `picture`/`playlist` (ältere App) tolerieren; `playlist`-Werte und Ereignisse prüfen.
- [ ] Schema-Prüfung: alle `payloads.cases` aus `vectors.json`; unbekannte Felder/Typen/Ereignisse angenommen und ignoriert.
- [ ] Verfügbarkeit 90 s, `unpair`-Behandlung, Löschen entfernt Schlüssel und Webhook.
- [ ] Logs nach 8.5; keine Inhalte aus 5.7.
- [ ] (Stufe 3) WebSocket-Handshake und Befehle nach Abschnitt 6, nur nach Freigabe; strenge Prüfung des `ack` (`ack_cases`); Befehl nur mit Nonce ≤ 8 s alt, Timeout 11 s nach Nonce-Empfang.

### 9.2 Checkliste Android

- [ ] BigInteger-SRP, `M1`/`M2`, HKDF, Schlüssel stimmen mit den Vektoren; Zufall aus `SecureRandom`.
- [ ] Webhook-Aufbau (`text/plain`, keine eigenen Header), Signatur über Rohbytes, Sequenzreservierung vor Senden, Abgleich bei `409` mit Beweisprüfung.
- [ ] Antworten ohne gültigen Beweis zählen als „nicht bestätigt“; 3 in Folge → nur Anzeige „Kopplung erneuern“, nie automatisches Löschen; `Retry-After` auf 300 s gedeckelt.
- [ ] Einwilligung (8.2), Schalter einzeln, Standard aus; Klartext-Hinweis; Network-Security-Config nur für diese Funktion (`http` zu den Nutzereingaben).
- [ ] Nichts aus 5.7; geschützte Inhalte ohne `media`, ohne `picture` und ohne Kennzeichnung.
- [ ] `picture` nur mit `share_artwork`, URL aus dem Katalog-Bildfeld, `picture_ok` vor dem Senden (alle `picture_urls`-Fälle) und `picture_has_credentials` mit Benutzername/Passwort (`app_credential_cases`); Sperrliste als CIDR-Tabelle (kein `is_global`); `playlist`/Ereignisse nur mit `share_playlist` (Werte nach 5.3, `payloads`-Fälle); Einwilligungstext nach 8.2.
- [ ] Geheimnis nicht im Backup; Keystore-Umhüllung geprüft.
- [ ] Keine Puffer, Backoff nach 5.5, Logs nach 8.5.
- [ ] (Stufe 3) Nonce (Erneuerung 8 s, Ablauf 10 s), `ack`, Befehlsprüfung genau in der Reihenfolge von 6.3 (strenges Format, `bad_sig` lässt die Nonce stehen); nur im Vordergrund.

### 9.3 Checkliste Tizen

- [ ] `BigInt` vorhanden (sonst „nicht unterstützt“); eigene `modPow`; Messung der Kopplungszeit am TV; SHA-256/HMAC/HKDF (kein Verlass auf `crypto.subtle`); Zufall über `crypto.getRandomValues`.
- [ ] Zeichen zählen in Codepunkten (`[...s]`), Kürzen vor dem Senden; `JSON.stringify` für Nutzlast, Signatur über die gesendeten UTF-8-Bytes (`TextEncoder` o. Ä., Umlaute/Emoji laut Vektor `unicode_title`).
- [ ] `config.xml`: `<access origin>` für die HA-Adresse und das Netzwerkrecht; einfache Anfrage ohne Preflight am TV bestätigt; Antworten lesbar.
- [ ] Sequenzreservierung im lokalen Speicher; Abgleich bei `409`.
- [ ] Alle Vektoren aus `vectors.json` nachgerechnet (Unit-Tests ohne TV).
- [ ] Einwilligung, Standard aus, Nichts aus 5.7, Logs nach 8.5.
- [ ] `picture` und `playlist` wie bei Android (eigene `picture_ok`-Umsetzung mit CIDR-Tabelle und Bit-Vergleich, IPv6-Parser mit `::`-Kurzform, alle Fälle aus `picture_urls` und `app_credential_cases`; `Date`→UTC-Text mit `Z` ohne Millisekunden für `updated`).
- [ ] Hinweis „Geheimnis nicht verschlüsselt gespeichert“ nicht als Verschlüsselung bewerben.
- [ ] (Stufe 3) WebSocket mit Anwendungs-Ping/Pong, Nonce, `ack` nach Abschnitt 6.

### 9.4 Zur unabhängigen Prüfung vorgemerkt (Kryptografie)

1. SRP-6a-Abwandlung: Beweise `M1`, `M2` als HMAC mit aus `S` gehashtem Schlüssel statt der Standard-Hashformeln; Einfluss von `ctx` und `device_id/webhook_id` auf die Beweise.
2. Gruppenwahl (3072 Bit, `g = 2`), Exponentenlänge 256 Bit, Prüfung der Randwerte (`A`, `B`, `u`) und Reduktion von `x`.
3. Schlüsselableitung (HKDF-Salt = Transkript-Hash, getrennte `info` je Richtung).
4. Signatur: längenpräfixierte Eingabe `LP("ITP1-REQ", …)` mit Rohbytes, Domänentrennung der Beschriftungen (`ITP1-REQ`, `-RESP`, `-WS-H`, `-WS-A`, `-NONCE`, `-CMD`, `-ACK`, `-M1`, `-M2`, `-TH`).
5. Sequenzreservierung und Abgleich (kann ein Angreifer mit einem alten, gültigen `409`-Beweis die Sequenz der App nach oben treiben? Beweis bindet `seq` der Anfrage, aber ein Mitschnitt kann gezielt eine alte Antwort liefern; die App nimmt nur `last_seq ≤ 2^53−1000` und höchstens einmal je Meldung).
6. WebSocket: Befehlsbindung an `sid`, Nonce-Modell mit nur einer ausstehenden Nonce und `stale_nonce`-Wiederholung; Verhalten bei absichtlich verzögerten Rahmen.
7. Nicht-Konstantzeit der Potenzen und der Vergleiche in JS.
8. Unauthentifizierte Pairing-Endpunkte als Angriffsfläche (Speicher, Rate-Limit).

### 9.5 Ausdrücklich offene Punkte

- Rechenzeit der Kopplung am Tizen-TV (3.7) und Entscheidung 3072 oder 2048 Bit.
- Lesbarkeit der Webhook-Antworten bei Tizen (`<access origin>`), sonst Beweise nicht prüfbar (2.1).
- Zeitwerte (90 s, 30 s, Nonce 8/10 s, HA-Timeout 11 s, 60 s) sind Startwerte, am Gerät zu prüfen.
- Bekannte Rennen (akzeptiert): Verlässt der Nutzer den Einrichtungsdialog nach `M2`, aber vor dem Anlegen des Eintrags, kennt die App eine Kopplung, die HA nicht kennt (Zeitfenster Millisekunden; App zeigt „Kopplung erneuern“). Die erste Meldung kann vor der Webhook-Registrierung eintreffen (HA antwortet leer; die App toleriert 2 Fehlschläge, bevor sie „Kopplung erneuern“ zeigt).
- Ob und wie HA anhand `Origin` Pairing-Anfragen fremder Webseiten abweisen kann, ohne Tizen auszuschließen (Ursprung der Tizen-App am Gerät bestimmen).
- Android-Mindest-API für Zusatzbibliotheken ist in `v1` kein Thema; erst bei `v2` (3.9).

---

### 9.6 Weitere Festlegungen

- **`name`:** keine Normalisierung (auch keine Unicode-Normalisierung), UTF-8, 1–40 Codepunkte, höchstens 160 Byte, keine Steuerzeichen. Die Anzeige maskiert es wie jeden fremden Text. Vektoren: `names`.
- **Doppelte JSON-Schlüssel** in Nutzlast und Pairing-Nachrichten sind verboten und werden mit `422 bad_payload` (Pairing: `400 bad_request`) abgelehnt (Vektor `duplicate_json_key`). JSON-Parser, die das nicht melden, sind mit einer Prüfung zu umgehen (z. B. Zählen der Schlüssel im Quelltext).
- **60-Sekunden-Uhr** (Gültigkeit eines Pairing-Versuchs, ebenso die 5 Minuten des Codes): immer die **monotone** Uhr der HA-Seite (`time.monotonic()` bzw. `loop.time()`), nie die Systemzeit. Toleranz: keine; nach Ablauf `410 session_expired`. Bei der App gilt die monotone Uhr (`System.nanoTime()`, `performance.now()`) für alle Zeitfenster.
- **Strenge Formatprüfung aller WebSocket-Felder:** alle Pflichtfelder vorhanden und vom richtigen Typ; `device_id`, `id`, `nonce`, `Na`, `Nh`, `next_nonce`, `value` genau 22 Zeichen base64url (16 Byte), alle `proof`/`mac`/`sig` genau 43 Zeichen (32 Byte), kanonisch dekodierbar; `cmd` und `arg` höchstens 16 Zeichen; `type` aus fester Menge; unbekannte `type`-Werte im WebSocket schließen die Verbindung (`4400`) statt ignoriert zu werden (anders als im Webhook).
- **Gleichzeitiges `state`, `heartbeat` und `409`-Abgleich:** nach 4.3 (eine Anfrage gleichzeitig, Reihenfolge nach Sequenz, Meldungen nach Abgleich idempotent, keine Duplikate).
- **Geklonter Schlüssel:** Erkennung über wiederholte `409`/Sequenzsprünge, Reparatur-Meldung in HA, Heilung nur durch erneutes Koppeln (4.3).

### 9.7 Festlegungen aus der Umsetzung von Stufe 1 (`iTrendPlayerHomeAssistant/docs/DECISIONS.md`)

Übernommen: Content-Type (4.4), Antwortformate (4.4), `ha_state_rev` nach Start, Verhalten nach `closed`, Verfügbarkeit, Geräte-Kennung und erneute Kopplung (7.2a), Rate-Limit-Zählung (4.6), Platzvergabe bei Pairing (3.4/3.6), Signatur vor Lock (4.3), Nutzlast mit rohem LF.

Ergänzend (Implementierungsentscheidungen, kein Protokollteil): Ein neuer Einrichtungsdialog ersetzt einen offenen Code (der alte zeigt „ersetzt“). Der Fehlversuchszähler (`used`) zählt entnommene Versuche **vor** der Rechnung; der Code wird gesperrt, sobald 3 Beweise bestätigt falsch waren (das deckt sich mit 3.4, da jeder entnommene, nicht bestätigte Versuch zählt). Titelattribute sind vom Recorder ausgenommen, es gibt kein „Zustand wiederherstellen“; Ereignisse tragen nur `device_id`, `entry_id`, `type`, `reason`, `media` (erlaubte Felder). Unbekannte Felder in Pairing-Nachrichten werden ignoriert. Pairing-Views registrieren ihre Routen selbst, damit der eigene `OPTIONS`-Handler nicht mit HA-CORS kollidiert.

**Abweichungen von der früheren Fassung dieser Spezifikation (jetzt hier festgelegt):** (a) Rohes LF in der Nutzlast war „verboten“, ist jetzt für Empfänger zulässig. (b) Das Gerätelimit zählte „gültig signierte“ Meldungen, jetzt nur „angenommene“. (c) Fehlerfeld im Fehlerfall ist `error`, nicht `code`. Nicht umgesetzt in Stufe 1: WebSocket (Stufe 3), `Origin`-Auswertung (offen, 9.5), Markenbilder.

## Anhang A: Gruppe

`N` (3072 Bit, RFC 3526 Gruppe 15), hexadezimal, `g = 2`:

```
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74
020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437
4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed
ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05
98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb
9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b
e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718
3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33
a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7
abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864
d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2
08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff
```

`k = H(PAD(N) ‖ PAD(g))` steht in `vectors.json` unter `srp_group.k_hex`.

## Anhang B: Testvektoren

`vectors.json` enthält, jeweils mit Eingaben und Erwartung: `encodings` (gültiges und ungültiges base64url), `primitives` (RFC-4231- und RFC-5869-Fälle, SHA-256), `srp_group`, `pairing` (feste Testwerte `a`, `b`, Salt, Code; alle Zwischenwerte, Nachrichten, falscher Code), `length_prefix`, `srp_bounds` (Randwerte), `names`, `webhook` (28 Fälle, u. a. falscher Content-Type, `ha_state_rev` unbekannt, u. a. doppelter JSON-Schlüssel: gültig, Wiederholung, Lücke, Manipulation, falscher Pfad/Schlüssel/Gerät, Version, Aufbaufehler, Sequenzformen, zu groß, unbekannte Typen), `picture_urls` (Bild-URL gültig/ungültig, von Hand eingetragen), `app_credential_cases`, `strip_unknown`, `payloads` (65 Nutzlast-Fälle, darunter neu `picture_*`, `playlist_*`, `event_playlist_*`, auch mit angehängtem LF gültig/ungültig, mit Codepunkt-Grenzen), `websocket` (Handshake, Nonce, 16 Befehlsfälle mit Formatfehlern und `bad_sig` ohne Nonce-Verbrauch, 10 `ack`-Fälle mit strenger Prüfung). Prüfen: `python3 reference.py --check` (nur Standardbibliothek). Neu erzeugen: `python3 reference.py --generate`; geänderte Vektoren erfordern eine Änderung des Protokolls oder einen Fehlerbericht.
