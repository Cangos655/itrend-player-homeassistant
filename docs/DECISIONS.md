# Entscheidungen der Umsetzung (Stufe 1)

Wo PROTOCOL.md offen ist, wurde konservativ entschieden. Die Spezifikation wurde nicht geändert.

1. **Versionen:** getestet mit Python 3.13 und Home Assistant 2026.2.3 (pytest-homeassistant-custom-component 0.13.316). `hacs.json` nennt deshalb 2026.2.0 als Minimum; Absenken erst nach Test.
2. **Gerät/Reauth:** Geräte-Kennung in HA ist die `entry_id`, nicht die `device_id` der Kopplung. So behält "Kopplung erneuern" Entitäten und Verlauf. Bei erneuter Kopplung gelten neue `device_id`/`webhook_id`/Schlüssel, der Sequenzspeicher wird zurückgesetzt, Reparaturmeldungen werden gelöscht.
3. **Content-Type:** Webhook akzeptiert nur `text/plain` (Parameter egal), sonst `400 bad_request`. Pairing akzeptiert `text/plain` und `application/json`, sonst `400`. (Spezifikation schweigt zu anderen Typen.)
4. **Pairing-Views** registrieren ihre Routen selbst (ohne HA-CORS-Anmeldung), da aiohttp_cors sonst mit dem eigenen OPTIONS-Handler kollidiert, falls der Nutzer `cors_allowed_origins` setzt. `OPTIONS` zählt nicht zum Rate-Limit.
5. **Reihenfolge `pair/start`:** Rate-Limit, Größe, Content-Type, JSON, Version, aktiver Code, Platz, Rechnung.
6. **Ein Code:** Ein neuer Dialog ersetzt einen offenen Code (der alte Dialog zeigt "ersetzt"). Nach 3 gesperrten Codes in 10 min wird die Kopplung 10 min nicht angeboten.
7. **Zähler:** `used` zählt entnommene Versuche (vor der Rechnung), gesperrt wird bei 3 bestätigt falschen Beweisen. Bei 4 offenen Versuchen insgesamt und weniger als 2 der eigenen Adresse bekommt der Anfrager `429` (nichts Fremdes wird verdrängt). Mehr als 2 gleichzeitige `finish`-Rechnungen: `429`, der Versuch bleibt erhalten. Gewinner bei zwei gleichzeitig richtigen Beweisen: nur einer, der andere `404`.
8. **Signatur vor Sperre:** Die Signatur wird vor dem Geräte-Lock geprüft (nicht darin), damit ohne Schlüssel niemand den Lock halten kann. Semantik gleich.
9. **Rate-Limits Webhook:** Das Geräte-Limit (10/10 s) zählt nur angenommene Meldungen (Replays eines Angreifers verbrauchen es nicht) und wird nach der Sequenzprüfung angewandt; `429` verbraucht keine Sequenz. `401` und `409` zählen im Quelladressen-Limit (30/min).
10. **Antwortformat:** Erfolg `{"ok":true,"code":"ok","seq","resync","proof"[,"ignored"]}`; Fehler `{"ok":false,"error":…}`; `409` mit `last_seq`, `proof`.
11. **`ha_state_rev`** ist nach Start unbekannt: Der erste Herzschlag erzeugt `resync:true`.
12. **Trennen durch die App (`unpair`):** Schlüssel im Eintrag gelöscht, Webhook entfernt, Reparaturmeldung (nicht behebbar) und Reauth-Fluss gestartet.
13. **Geklonter Schlüssel:** 5 gültig signierte Meldungen mit `seq ≤ last_seq` in 10 min oder Sprung > 1000: Reparaturmeldung. Sie bleibt bis zur Neukopplung/Löschen.
14. **Verfügbarkeit:** Nach `closed` bleibt der Player "aus" (Timer ruht). Nach 90 s Stille werden Zustand und Titel verworfen. Der Binär-Sensor ist immer verfügbar (aus statt unverfügbar). `buffering` wird als "Puffern" gezeigt, unbekannter Status als "Leerlauf".
15. **Abo-Ablauf:** Das Protokoll liefert nur ein Datum; der Zeitstempel ist der Beginn dieses Tages in der HA-Zeitzone.
16. **Datenschutz:** Titelattribute sind vom Recorder ausgenommen; kein "Zustand wiederherstellen". Ereignisse tragen nur `device_id`, `entry_id`, `type`, `reason`, `media` (erlaubte Felder).
17. **Rohes LF in der Nutzlast** ist wie in reference.py zulässig (signierte Bytes). Unbekannte Felder in Pairing-Nachrichten werden ignoriert.
18. **Bekannte Rennen:** Verlässt der Nutzer den Dialog nach `M2`, aber vor dem Anlegen des Eintrags, kennt die App eine Kopplung, die HA nicht kennt (Fenster Millisekunden; App zeigt "Kopplung erneuern"). Die erste Meldung kann vor der Webhook-Registrierung eintreffen (HA antwortet leer, die App toleriert 2 Fehlschläge).
19. **Nicht umgesetzt:** WebSocket/Befehle (Stufe 3), Auswertung von `Origin` (9.5 offen), Markenbilder (HACS-Action ignoriert `brands`).
