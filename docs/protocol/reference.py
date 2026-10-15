#!/usr/bin/env python3
"""Referenzimplementierung des iTrend-Player-HA-Protokolls v1 (nur Testdaten!).

Nur Python-3-Standardbibliothek. Erzeugt und prueft vectors.json.

  python3 reference.py --generate   schreibt vectors.json neu
  python3 reference.py --check      prueft vectors.json (muss gruen sein)

Die Funktionen unten sind absichtlich klein und lesbar gehalten; sie
definieren zusammen mit PROTOCOL.md das Verhalten. Alle Schluessel, Codes
und Nonces in vectors.json sind aus festen Beschriftungen abgeleitet und
nirgends echt.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors.json")

SRP_ID = "itrend-ha-pair-v1"
G = 2
NLEN = 384  # Bytes der 3072-Bit-Gruppe
MAX_SEQ = 2 ** 53 - 1
MAX_BODY = 4096
MAX_PAYLOAD = 2048


# --------------------------------------------------------------- Grundlagen
def sha256(b):
    return hashlib.sha256(b).digest()


def hmac256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def lp(*fields):
    """Laengenpraefixierte Kodierung: je Feld 4 Byte Big-Endian-Laenge + Bytes.
    Str wird als UTF-8 kodiert. Alle MAC-Eingaben benutzen diese Form."""
    out = b""
    for f in fields:
        if isinstance(f, str):
            f = f.encode("utf-8")
        out += len(f).to_bytes(4, "big") + f
    return out


def ct_eq(a, b):
    return hmac.compare_digest(a, b)


_B64RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_dec(s):
    """Streng: kein Padding, nur Alphabet, kanonisch (Restbits null)."""
    if not isinstance(s, str) or not _B64RE.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError("bad base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(raw) != s:
        raise ValueError("non-canonical base64url")
    return raw


def hkdf_extract(salt, ikm):
    return hmac256(salt if salt else b"\x00" * 32, ikm)


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


def T(label):
    """Fester Testwert (32 Byte) aus Beschriftung. Nie fuer echte Schluessel."""
    return sha256(b"itrend-ha-protocol-test:" + label.encode("ascii"))


# ------------------------------------------------------------ SRP-Gruppe
def _pi_scaled(bits):
    guard = 64
    one = 1 << (bits + guard)

    def atan_inv(x):
        total = term = one // x
        x2, n, sign = x * x, 1, -1
        while term:
            term //= x2
            n += 2
            total += sign * (term // n)
            sign = -sign
        return total

    return (4 * (4 * atan_inv(5) - atan_inv(239))) >> guard


def modp_3072():
    # RFC 3526, Gruppe 15: 2^3072 - 2^3008 - 1 + 2^64 * (floor(2^2942 * pi) + 1690314)
    return 2 ** 3072 - 2 ** 3008 - 1 + 2 ** 64 * (_pi_scaled(2942) + 1690314)


_SMALL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_probable_prime(n, rounds=8):
    if n < 2:
        return False
    for p in _SMALL:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _SMALL[:rounds]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


N = modp_3072()


def pad(n):
    return n.to_bytes(NLEN, "big")


def srp_k():
    return int.from_bytes(sha256(pad(N) + pad(G)), "big")


def srp_x(salt, code):
    inner = sha256((SRP_ID + ":" + code).encode("ascii"))
    return int.from_bytes(sha256(salt + inner), "big")


def srp_u(A, B):
    return int.from_bytes(sha256(pad(A) + pad(B)), "big")


def ctx_bytes(name, platform, app_version):
    return lp(name, platform, app_version)


def valid_name(name):
    """name: keine Normalisierung, UTF-8, 1-40 Codepunkte, hoechstens 160 Byte, keine Steuerzeichen."""
    return _is_text(name, 1, 40) and len(name.encode("utf-8")) <= 160


def valid_public(x):
    """SRP-Randwerte: 1 < x < N-1 (gilt fuer A und B)."""
    return isinstance(x, int) and 1 < x < N - 1


def derive_keys(S, A, B, ctx, device_id, webhook_id):
    k_srp = sha256(pad(S))
    th = sha256(lp("ITP1-TH", pad(A), pad(B), ctx))
    prk = hkdf_extract(th, k_srp)
    ids = lp(device_id, webhook_id)
    return {
        "K_srp": k_srp,
        "transcript_hash": th,
        "PRK": prk,
        "K_proof": hkdf_expand(prk, b"ITP1 proof", 32),
        "K_a2h": hkdf_expand(prk, b"ITP1 app-to-ha" + ids, 32),
        "K_h2a": hkdf_expand(prk, b"ITP1 ha-to-app" + ids, 32),
    }


def proof_m1(k_proof, A, B, ctx):
    return hmac256(k_proof, lp("ITP1-M1", pad(A), pad(B), ctx))


def proof_m2(k_proof, A, B, m1, device_id, webhook_id):
    return hmac256(k_proof, lp("ITP1-M2", pad(A), pad(B), m1, device_id, webhook_id))


# ------------------------------------------------- Signatur (App -> HA)
def signing_input(method, path, device_id, seq, payload):
    return lp("ITP1-REQ", method, path, device_id, str(seq), payload)


def build_body(key, path, device_id, seq, payload):
    sig = b64u(hmac256(key, signing_input("POST", path, device_id, seq, payload)))
    return ("ITP/1\n%s\n%d\n%s\n" % (device_id, seq, sig)).encode("ascii") + payload


def resp_proof(key_h2a, device_id, seq, req_sig, code, last_seq, resync):
    return b64u(hmac256(key_h2a, lp("ITP1-RESP", device_id, str(seq), req_sig, code,
                                    str(last_seq), "1" if resync else "0")))


# ------------------------------------------------------- Nutzlast-Pruefung
KINDS = {"live", "movie", "episode", "trailer", "other"}
STATUSES = {"idle", "buffering", "playing", "paused", "closed"}
EVENTS = {"playback_started", "playback_stopped", "channel_changed", "trailer_opened",
          "playlist_refreshed", "playlist_failed"}
PLAYLIST_ERRORS = {"none", "no_network", "unauthorized", "server_error", "connection_lost",
                   "storage", "other"}
PICTURE_MAX = 512
# Normalisierte Namen (klein, ohne '-', '_' und Leerzeichen); Vergleich nach genau einmaligem URL-Dekodieren.
SECRET_QUERY_NAMES = {
    "username", "user", "usr", "login", "uid", "password", "pass", "passwd", "pw", "pwd",
    "token", "accesstoken", "key", "apikey", "auth", "authorization", "secret", "sig",
    "signature", "xamzsignature", "session", "sid", "ticket", "credential", "xamzcredential",
    "xamzsecuritytoken", "sessionid", "bearer"}
BLOCKED_SUFFIXES = (".test", ".invalid", ".example", ".local", ".localhost", ".internal", ".lan",
                    ".home.arpa", ".localdomain", ".corp", ".home", ".intranet", ".private")
BLOCKED_PATH_SEGMENTS = {"live", "movie", "series", "vod", "stream", "hls"}
BLOCKED_EXTENSIONS = (".ts", ".m3u8", ".m3u", ".mp4", ".mkv", ".avi", ".mp3")
# Normative Sperrlisten (PROTOCOL.md 5.2a). Nichts davon haengt von is_global o. ae. ab.
BLOCKED_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32")]
BLOCKED_V6 = [ipaddress.ip_network(n) for n in (
    "::/128", "::1/128", "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001::/32", "2001:10::/28", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10",
    "ff00::/8", "::ffff:0:0:0/96")]
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_V4 = re.compile(r"(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}")
_PORT = re.compile(r"[1-9][0-9]{0,4}")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
STOP_REASONS = {"ended", "user", "error"}
VERSION_RE = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(-[A-Za-z0-9.]{1,16})?$")
MAX_MS = 172800000


def _is_int(x, lo, hi):
    return isinstance(x, int) and not isinstance(x, bool) and lo <= x <= hi


def _is_text(x, lo, hi):
    if not isinstance(x, str) or not lo <= len(x) <= hi:
        return False
    try:
        x.encode("utf-8")  # keine einzelnen Surrogate
    except UnicodeEncodeError:
        return False
    return all(ord(c) >= 0x20 and ord(c) != 0x7F for c in x)


def _pct_decode_once(s):
    """Genau einmal dekodieren; ungueltige %-Folge, ungueltiges UTF-8, NUL/Steuerzeichen -> None."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", s):
        return None
    try:
        out = urllib.parse.unquote(s, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in out):
        return None
    return out


def _norm_name(n):
    return n.lower().replace("-", "").replace("_", "").replace(" ", "")


def picture_ok(u):
    """Strenge Pruefung der Bild-URL (App vor dem Senden, Integration beim Empfang).
    Ohne DNS-Aufloesung; Rebinding/Weiterleitungen sind Restrisiken (PROTOCOL.md 8.3a)."""
    if not isinstance(u, str) or not 1 <= len(u) <= PICTURE_MAX:
        return False
    if any(not 0x21 <= ord(c) <= 0x7E or c == "\\" for c in u) or "#" in u:
        return False
    m = re.fullmatch(r"(https?)://([^/?]*)([^?]*)(?:\?(.*))?", u)
    if not m:
        return False  # Schema nur klein geschrieben http/https
    _scheme, auth, path, query = m.groups()
    if not auth or "@" in auth:
        return False
    # --- Host und Port
    if auth.startswith("["):
        mm = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::(.*))?", auth)
        if not mm:
            return False
        host_s, port_s = mm.group(1), mm.group(2)
        try:
            ip = ipaddress.IPv6Address(host_s)
        except ValueError:
            return False
        if any(ip in n for n in BLOCKED_V6):
            return False
        host = None
    else:
        if "[" in auth or "]" in auth:
            return False
        host_s, sep, port_s = auth.partition(":")
        if not sep:
            port_s = None
        host = host_s.lower()
        if not host or not re.fullmatch(r"[a-z0-9.-]+", host):
            return False
        if _V4.fullmatch(host):
            octets = [int(x) for x in host.split(".")]
            if any(o > 255 for o in octets):
                return False
            ip4 = ipaddress.IPv4Address(host)
            if any(ip4 in n for n in BLOCKED_V4):
                return False
        else:
            last = host.rsplit(".", 1)[-1]
            if last.isdigit() or last.startswith("0x"):
                return False  # Dezimal-/Oktal-/Hex-/Kurzschreibweisen
            if host == "localhost" or host.endswith(BLOCKED_SUFFIXES) or "." not in host:
                return False
            if len(host) > 253 or not all(_LABEL.fullmatch(lbl) for lbl in host.split(".")):
                return False
    if port_s is not None and (not _PORT.fullmatch(port_s) or int(port_s) > 65535):
        return False
    # --- Pfad: einmal als Ganzes dekodieren (%2F wird zu '/'), dann Segmente, ohne Beachtung der Gross-/Kleinschreibung
    dpath = _pct_decode_once(path)
    if dpath is None:
        return False
    for seg in dpath.lower().split("/"):
        if seg in BLOCKED_PATH_SEGMENTS or seg.endswith(BLOCKED_EXTENSIONS):
            return False
    # --- Query: '&' und ';' trennen, '+' = Leerzeichen, einmal dekodieren
    if query:
        for pair in re.split(r"[&;]", query):
            if not pair:
                continue
            name, _eq, value = pair.partition("=")
            dn = _pct_decode_once(name.replace("+", " "))
            dv = _pct_decode_once(value.replace("+", " "))
            if dn is None or dv is None:
                return False
            if _norm_name(dn) in SECRET_QUERY_NAMES:
                return False
    return True


def _forms(text):
    """Roh, einmal dekodiert und einmal dekodiert mit '+' = Leerzeichen; klein geschrieben."""
    out = {text.lower()}
    for t in (text, text.replace("+", " ")):
        d = _pct_decode_once(t)
        if d is not None:
            out.add(d.lower())
    return out


def picture_has_credentials(u, username, password):
    """App-seitige Pflicht: picture verwerfen, wenn Pfad oder Query (nicht Schema/Host)
    Benutzername oder Passwort des Nutzers enthalten; ohne Beachtung der Gross-/Kleinschreibung.
    Unter 4 Zeichen nur als vollstaendiges Pfadsegment oder vollstaendiger Query-Wert, ab
    4 Zeichen als Teilzeichenkette in Pfad oder Query (roh oder einmal dekodiert).
    Leer/None zaehlt nicht. Doppelt kodiert oder ueber Segmente verteilt: Restrisiko."""
    m = re.fullmatch(r"https?://[^/?#]*([^?#]*)(?:\?([^#]*))?.*", u)
    if not m:
        return False
    path, query = m.group(1) or "", m.group(2) or ""
    path_forms = _forms(path)
    query_forms = _forms(query)
    seg_forms = set()
    for seg in path.split("/"):
        seg_forms |= _forms(seg)
    val_forms = set()
    for pair in re.split(r"[&;]", query):
        val_forms |= _forms(pair.partition("=")[2])
    for val in (username, password):
        if not val:
            continue
        v = val.lower()
        if len(val) < 4:
            if v in seg_forms or v in val_forms:
                return True
        elif any(v in f for f in path_forms | query_forms):
            return True
    return False


KNOWN_FIELDS = {
    "state": {"v", "type", "rev", "status", "media", "picture"},
    "heartbeat": {"v", "type", "app_version", "platform", "state_rev", "ws", "sub", "playlist"},
    "event": {"v", "type", "name", "reason", "error", "media"},
    "unpair": {"v", "type"},
    "media": {"kind", "title", "channel", "series", "season", "episode", "duration_ms", "position_ms"},
    "sub": {"expires", "connections_active", "connections_max"},
    "playlist": {"updated", "live", "movies", "series", "error"},
}


def strip_unknown(o):
    """Integration (nach erfolgreicher Pruefung): unbekannte Felder in allen Objekten verwerfen, unbekannte
    Nachrichtentypen und Ereignisnamen ganz verwerfen (nicht speichern, nicht loggen)."""
    if o.get("type") not in KNOWN_FIELDS or o.get("type") in ("media", "sub", "playlist"):
        return {}  # unbekannter Typ: Nutzlast vollstaendig verwerfen
    if o["type"] == "event" and o.get("name") not in EVENTS:
        return {}  # unbekanntes Ereignis: vollstaendig verwerfen
    out = {k: o[k] for k in o if k in KNOWN_FIELDS[o["type"]]}
    for key in ("media", "sub", "playlist"):
        if isinstance(out.get(key), dict):
            out[key] = {k: out[key][k] for k in out[key] if k in KNOWN_FIELDS[key]}
    return out


def validate_media(m):
    if not isinstance(m, dict):
        return "media_not_object"
    if m.get("kind") not in KINDS:
        return "media_kind"
    for key, lo, hi in (("title", 1, 120), ("channel", 1, 80), ("series", 1, 120)):
        if key in m and not _is_text(m[key], lo, hi):
            return "media_" + key
    for key, lo, hi in (("season", 0, 999), ("episode", 0, 9999),
                        ("duration_ms", 0, MAX_MS), ("position_ms", 0, MAX_MS)):
        if key in m and not _is_int(m[key], lo, hi):
            return "media_" + key
    kind = m["kind"]
    if kind != "episode" and any(k in m for k in ("series", "season", "episode")):
        return "media_episode_fields_only_for_episode"
    if kind != "live" and "channel" in m:
        return "media_channel_only_for_live"
    if kind == "live" and ("duration_ms" in m or "position_ms" in m):
        return "media_no_position_for_live"
    if "duration_ms" in m and "position_ms" in m and m["position_ms"] > m["duration_ms"]:
        return "media_position_after_end"
    return None


def validate_payload(o):
    """Gibt None zurueck, wenn gueltig, sonst einen kurzen Grundcode."""
    if not isinstance(o, dict):
        return "not_object"
    if not _is_int(o.get("v"), 1, 1000):
        return "v"
    if o["v"] != 1:
        return "unsupported_version"
    t = o.get("type")
    if t == "state":
        if o.get("status") not in STATUSES:
            return "status"
        if not _is_int(o.get("rev"), 0, MAX_SEQ):
            return "rev"
        if "media" in o:
            if o["status"] not in ("buffering", "playing", "paused"):
                return "media_not_allowed_in_status"
            r = validate_media(o["media"])
            if r:
                return r
        if "picture" in o:
            if "media" not in o:
                return "picture_without_media"
            if not picture_ok(o["picture"]):
                return "picture"
        return None
    if t == "heartbeat":
        av = o.get("app_version")
        if not isinstance(av, str) or len(av) > 32 or not VERSION_RE.fullmatch(av):
            return "app_version"
        if o.get("platform") not in ("android", "tizen"):
            return "platform"
        if not _is_int(o.get("state_rev"), 0, MAX_SEQ):
            return "state_rev"
        if "ws" in o and not isinstance(o["ws"], bool):
            return "ws"
        if "sub" in o:
            s = o["sub"]
            if not isinstance(s, dict):
                return "sub"
            if "expires" in s and s["expires"] is not None:
                e = s["expires"]
                if not isinstance(e, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", e):
                    return "sub_expires"
                try:
                    datetime.date.fromisoformat(e)
                except ValueError:
                    return "sub_expires"
            for key in ("connections_active", "connections_max"):
                if key in s and not _is_int(s[key], 0, 99):
                    return "sub_" + key
        if "playlist" in o:
            p = o["playlist"]
            if not isinstance(p, dict):
                return "playlist"
            if "updated" in p and p["updated"] is not None:
                u = p["updated"]
                if not isinstance(u, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", u):
                    return "playlist_updated"
                try:
                    datetime.datetime.strptime(u, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    return "playlist_updated"
            for key in ("live", "movies", "series"):
                if key in p and not _is_int(p[key], 0, 999999):
                    return "playlist_" + key
            if "error" in p and p["error"] not in PLAYLIST_ERRORS:
                return "playlist_error"
        return None
    if t == "event":
        name = o.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z_]{1,32}", name):
            return "name"
        if name not in EVENTS:
            return None  # unbekannte Ereignisse: annehmen und ignorieren
        if "reason" in o and (name != "playback_stopped" or o["reason"] not in STOP_REASONS):
            return "reason"
        if name == "playlist_failed" and (o.get("error") not in PLAYLIST_ERRORS or o["error"] == "none"):
            return "error"
        if name != "playlist_failed" and "error" in o:
            return "error"
        if "media" in o:
            return validate_media(o["media"])
        return None
    if t == "unpair":
        return None
    return None  # unbekannter Typ: annehmen und ignorieren


def is_known_type(o):
    return isinstance(o, dict) and o.get("type") in ("state", "heartbeat", "event", "unpair")


# ----------------------------------------- Webhook-Empfang (HA-Seite, Logik)
def _no_dupes(pairs):
    d = {}
    for k, val in pairs:
        if k in d:
            raise ValueError("doppelter Schluessel")
        d[k] = val
    return d


def receive(body, webhook_id, dev, content_type="text/plain;charset=UTF-8"):
    """Referenzverhalten der Integration. dev: dict mit device_id, key_a2h,
    key_h2a (bytes), last_seq, ha_state_rev. Veraendert dev bei Annahme."""
    path = "/api/webhook/" + webhook_id
    # Reihenfolge: Groesse, Content-Type, Aufbau, Format, Signatur (OHNE Geraete-Lock,
    # damit ohne Schluessel niemand den Lock halten kann), dann erst im Lock:
    # seq pruefen, Reservierung speichern, last_seq setzen.
    if len(body) > MAX_BODY:
        return {"http": 413, "code": "payload_too_large"}
    if content_type.split(";")[0].strip().lower() != "text/plain":
        return {"http": 400, "code": "bad_request"}
    parts = body.split(b"\n", 4)
    if len(parts) != 5:
        return {"http": 400, "code": "bad_request"}
    try:
        magic, device_id, seq_s, sig_s = [p.decode("ascii") for p in parts[:4]]
    except UnicodeDecodeError:
        return {"http": 400, "code": "bad_request"}
    payload = parts[4]
    if magic != "ITP/1":
        if re.fullmatch(r"ITP/[0-9]+", magic):
            return {"http": 400, "code": "unsupported_version"}
        return {"http": 400, "code": "bad_request"}
    if not re.fullmatch(r"0|[1-9][0-9]{0,15}", seq_s) or not 1 <= int(seq_s) <= MAX_SEQ:
        return {"http": 400, "code": "bad_request"}
    seq = int(seq_s)
    try:
        sig = b64u_dec(sig_s)
        if len(sig) != 32:
            raise ValueError
    except ValueError:
        return {"http": 400, "code": "bad_request"}
    expected = hmac256(dev["key_a2h"], signing_input("POST", path, device_id, seq, payload))
    if device_id != dev["device_id"] or not ct_eq(sig, expected):
        return {"http": 401, "code": "bad_signature"}
    if seq <= dev["last_seq"]:
        return {"http": 409, "code": "seq_too_low", "last_seq": dev["last_seq"],
                "proof": resp_proof(dev["key_h2a"], device_id, seq, sig_s, "seq_too_low",
                                    dev["last_seq"], False)}
    dev["last_seq"] = seq  # Sequenz ist ab hier verbraucht, auch bei 422
    if len(payload) > MAX_PAYLOAD:
        return {"http": 413, "code": "payload_too_large"}
    try:
        obj = json.loads(payload.decode("utf-8"), object_pairs_hook=_no_dupes)
    except (UnicodeDecodeError, ValueError):
        return {"http": 422, "code": "bad_payload"}
    reason = validate_payload(obj)
    if reason == "unsupported_version":
        return {"http": 400, "code": "unsupported_version"}
    if reason:
        return {"http": 422, "code": "bad_payload"}
    resync = False
    if obj.get("type") == "state":
        dev["ha_state_rev"] = obj["rev"]
    elif obj.get("type") == "heartbeat":
        resync = obj["state_rev"] != dev["ha_state_rev"]
    out = {"http": 200, "code": "ok", "resync": resync,
           "proof": resp_proof(dev["key_h2a"], device_id, seq, sig_s, "ok", 0, resync)}
    if not is_known_type(obj) or (obj.get("type") == "event" and obj.get("name") not in EVENTS):
        out["ignored"] = True
    return out


# ------------------------------------------------------------- WebSocket
B22 = re.compile(r"^[A-Za-z0-9_-]{22}$")
B43 = re.compile(r"^[A-Za-z0-9_-]{43}$")


def fmt22(x):
    """Genau 22 Zeichen base64url, kanonisch (16 Byte)."""
    if not isinstance(x, str) or not B22.fullmatch(x):
        return False
    try:
        return len(b64u_dec(x)) == 16
    except ValueError:
        return False


def fmt43(x):
    if not isinstance(x, str) or not B43.fullmatch(x):
        return False
    try:
        return len(b64u_dec(x)) == 32
    except ValueError:
        return False


def ws_hello_proof_h(key_h2a, device_id, na, nh):
    return b64u(hmac256(key_h2a, lp("ITP1-WS-H", device_id, na, nh)))


def ws_auth_proof_a(key_a2h, device_id, na, nh):
    return b64u(hmac256(key_a2h, lp("ITP1-WS-A", device_id, na, nh)))


def ws_nonce_mac(key_a2h, device_id, sid, value):
    return b64u(hmac256(key_a2h, lp("ITP1-NONCE", device_id, sid, value)))


def ws_cmd_sig(key_h2a, device_id, sid, nonce, cmd_id, cmd, arg):
    return b64u(hmac256(key_h2a, lp("ITP1-CMD", device_id, sid, nonce, cmd_id, cmd, arg)))


def ws_ack_mac(key_a2h, device_id, sid, cmd_id, result, reason, next_nonce):
    return b64u(hmac256(key_a2h, lp("ITP1-ACK", device_id, sid, cmd_id, result, reason,
                                    next_nonce)))


RESULTS = {"ok", "rejected", "failed"}
REASONS = {"", "bad_request", "bad_sig", "stale_nonce", "duplicate_id", "unsupported",
           "control_disabled", "nothing_playing", "error", "timeout"}


def ha_check_ack(msg, st):
    """HA prueft einen ack strikt. st: key_a2h, device_id, sid, sent_id (id des
    ausstehenden Befehls). Gibt None (gueltig) oder einen Grund."""
    if not isinstance(msg, dict) or msg.get("type") != "ack":
        return "bad_request"
    for k in ("id", "result", "reason", "next_nonce", "mac"):
        if not isinstance(msg.get(k), str):
            return "bad_request"
    if not (msg["id"] == "" or fmt22(msg["id"])):
        return "bad_request"
    if msg["result"] not in RESULTS or msg["reason"] not in REASONS:
        return "bad_request"
    if (msg["result"] == "ok") != (msg["reason"] == ""):
        return "bad_request"
    if not fmt22(msg["next_nonce"]) or not fmt43(msg["mac"]):
        return "bad_request"
    exp = ws_ack_mac(st["key_a2h"], st["device_id"], st["sid"], msg["id"], msg["result"],
                     msg["reason"], msg["next_nonce"])
    if not ct_eq(exp.encode("ascii"), msg["mac"].encode("ascii")):
        return "bad_mac"
    if msg["id"] != st["sent_id"] and not (msg["id"] == "" and msg["reason"] in ("bad_request", "bad_sig")):
        return "unknown_id"
    return None


CMD_ARGS = {"play": [""], "pause": [""], "stop": [""], "next": [""], "previous": [""],
            "seek_relative": ["-10000", "10000"], "unpair": [""]}


def app_check_command(msg, st):
    """Referenzverhalten der App. st: key_h2a, device_id, sid, pending_nonce,
    seen_ids (Liste), control_enabled, nothing_playing. Gibt (result, reason, ack_id,
    nonce_consumed). Die Nonce wird nur bei gueltiger Signatur UND passender Nonce
    verbraucht; wer keinen Schluessel hat, kann sie nicht verbrennen."""
    fmt_ok = (isinstance(msg, dict) and fmt22(msg.get("id")) and fmt22(msg.get("nonce"))
              and fmt43(msg.get("sig")) and isinstance(msg.get("cmd"), str)
              and isinstance(msg.get("arg"), str) and len(msg["cmd"]) <= 16 and len(msg["arg"]) <= 16)
    if not fmt_ok:
        return ("rejected", "bad_request", "", False)
    expect = ws_cmd_sig(st["key_h2a"], st["device_id"], st["sid"], msg["nonce"],
                        msg["id"], msg["cmd"], msg["arg"])
    if not ct_eq(expect.encode("ascii"), msg["sig"].encode("ascii")):
        return ("rejected", "bad_sig", "", False)  # Nonce bleibt
    if st["pending_nonce"] is None or msg["nonce"] != st["pending_nonce"]:
        return ("rejected", "stale_nonce", msg["id"], False)
    st["pending_nonce"] = None  # gueltig signiert und aktuell: einmalig verbraucht
    if msg["id"] in st["seen_ids"]:
        return ("rejected", "duplicate_id", msg["id"], True)
    st["seen_ids"].append(msg["id"])
    if msg["cmd"] not in CMD_ARGS or msg["arg"] not in CMD_ARGS[msg["cmd"]]:
        return ("rejected", "unsupported", msg["id"], True)
    if msg["cmd"] == "unpair":
        return ("ok", "", msg["id"], True)
    if not st["control_enabled"]:
        return ("rejected", "control_disabled", msg["id"], True)
    if st["nothing_playing"] and msg["cmd"] != "play":
        return ("rejected", "nothing_playing", msg["id"], True)
    return ("ok", "", msg["id"], True)


# ----------------------------------------------------------- Vektorbau
def hx(b):
    return b.hex()


def build_vectors():
    v = {}
    v["meta"] = {
        "protocol": "itrend-ha v1",
        "warning": "Nur Testdaten. Alle Werte stammen aus festen Beschriftungen, keine echten Schluessel.",
        "hash": "SHA-256", "encoding": "base64url ohne Padding",
        "mac_input": "Alle MAC-Eingaben: lp(feld1, feld2, ...) mit 4 Byte Big-Endian-Laenge je Feld",
        "generator": "reference.py --generate",
    }

    # Kodierung und Primitive
    v["encodings"] = {
        "valid": [{"hex": h, "b64u": b64u(bytes.fromhex(h))}
                  for h in ("", "00", "0001", "000102", "fffefd", "00010203")],
        "invalid_b64u": ["AA==", "A", "AB", "a+b/", "ab c", "ab\n", "AAAA\n", "AAA=" ],
        "note": "AB hat nichtkanonische Restbits und ist ungueltig; A hat unmoegliche Laenge.",
    }
    v["length_prefix"] = {
        "lp_ab_c_hex": hx(lp("ab", "c")), "lp_a_bc_hex": hx(lp("a", "bc")),
        "note": "lp(ab,c) und lp(a,bc) muessen sich unterscheiden (keine Feldverwechslung)."}
    v["srp_bounds"] = {
        "note": "Gueltig nur 1 < x < N-1 (fuer A und B, auch auf HA-Seite); zusaetzlich u = 0 abbrechen.",
        "cases": [{"name": nm, "value_hex": "%0768x" % val, "valid": valid_public(val)}
                  for nm, val in (("zero", 0), ("one", 1), ("two", 2), ("N_minus_2", N - 2),
                                  ("N_minus_1", N - 1), ("N", N), ("N_plus_1", N + 1),
                                  ("N_plus_2", N + 2), ("max_384_bytes", 2 ** 3072 - 1))]}
    v["names"] = {
        "note": "name: keine Normalisierung, UTF-8, 1-40 Codepunkte, hoechstens 160 Byte, keine Steuerzeichen.",
        "cases": [{"name": lbl, "value": val, "valid": valid_name(val)} for lbl, val in (
            ("simple", "Wohnzimmer TV"), ("empty", ""), ("len40", "a" * 40), ("len41", "a" * 41),
            ("control", "a\tb"), ("emoji40", "\U0001F600" * 40), ("nfd_kept", "Ame\u0301lie"))]}
    v["primitives"] = {
        "hmac_sha256_rfc4231_tc1": {"key_hex": "0b" * 20, "data_utf8": "Hi There",
                                     "mac_hex": hx(hmac256(bytes.fromhex("0b" * 20), b"Hi There"))},
        "hkdf_sha256_rfc5869_tc1": {
            "ikm_hex": "0b" * 22, "salt_hex": "000102030405060708090a0b0c",
            "info_hex": "f0f1f2f3f4f5f6f7f8f9", "length": 42,
            "okm_hex": hx(hkdf_expand(hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"),
                                                    bytes.fromhex("0b" * 22)),
                                       bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42))},
        "sha256_abc_hex": hx(sha256(b"abc")),
    }

    # Gruppe
    v["srp_group"] = {
        "description": "RFC 3526 Gruppe 15 (3072 Bit, sichere Primzahl), g = 2, wie in RFC 3526 veroeffentlicht",
        "N_hex": "%0768x" % N, "g": G, "N_bytes": NLEN,
        "k_hex": "%064x" % srp_k(),
        "identity": SRP_ID,
    }

    # Kopplung
    code = "123456"
    salt = T("salt")[:16]
    a = int.from_bytes(T("a"), "big")
    b = int.from_bytes(T("b"), "big")
    device_id = b64u(T("device")[:16])
    webhook_id = b64u(T("webhook"))
    name, platform, app_version = "Wohnzimmer TV", "tizen", "0.3.0"
    session = b64u(T("session")[:16])
    ctx = ctx_bytes(name, platform, app_version)
    k = srp_k()
    x = srp_x(salt, code)
    ver = pow(G, x, N)
    A = pow(G, a, N)
    B = (k * ver + pow(G, b, N)) % N
    u = srp_u(A, B)
    S_client = pow((B - k * pow(G, x, N)) % N, a + u * x, N)
    S_server = pow(A * pow(ver, u, N) % N, b, N)
    assert S_client == S_server
    keys = derive_keys(S_client, A, B, ctx, device_id, webhook_id)
    m1 = proof_m1(keys["K_proof"], A, B, ctx)
    m2 = proof_m2(keys["K_proof"], A, B, m1, device_id, webhook_id)
    # falscher Code
    x_bad = srp_x(salt, "654321")
    S_bad = pow((B - k * pow(G, x_bad, N)) % N, a + u * x_bad, N)
    keys_bad = derive_keys(S_bad, A, B, ctx, device_id, webhook_id)
    m1_bad = proof_m1(keys_bad["K_proof"], A, B, ctx)
    v["pairing"] = {
        "note": "a und b sind feste Testwerte (256 Bit); in der Praxis zufaellig je Versuch.",
        "inputs": {"code": code, "salt_hex": hx(salt), "a_hex": "%064x" % a, "b_hex": "%064x" % b,
                   "session_b64u": session, "device_id": device_id, "webhook_id": webhook_id,
                   "name": name, "platform": platform, "app_version": app_version},
        "derived": {
            "x_hex": "%064x" % x, "verifier_v_hex": "%0768x" % ver,
            "A_hex": "%0768x" % A, "B_hex": "%0768x" % B, "u_hex": "%064x" % u,
            "S_hex": "%0768x" % S_client, "K_srp_hex": hx(keys["K_srp"]), "K_proof_hex": hx(keys["K_proof"]),
            "ctx_utf8_hex": hx(ctx), "transcript_hash_hex": hx(keys["transcript_hash"]),
            "PRK_hex": hx(keys["PRK"]),
            "K_a2h_hex": hx(keys["K_a2h"]), "K_h2a_hex": hx(keys["K_h2a"]),
            "M1_hex": hx(m1), "M2_hex": hx(m2)},
        "messages": {
            "start_request": {"v": 1},
            "start_response": {"v": 1, "session": session, "salt": b64u(salt),
                               "B": b64u(pad(B))},
            "finish_request": {"v": 1, "session": session, "A": b64u(pad(A)), "M1": b64u(m1),
                               "name": name, "platform": platform, "app_version": app_version},
            "finish_response": {"v": 1, "M2": b64u(m2), "device_id": device_id,
                                "webhook_id": webhook_id}},
        "wrong_code": {"code": "654321", "M1_hex": hx(m1_bad),
                       "expect": "HA lehnt ab (403 pairing_failed), M1 stimmt nicht mit dem erwarteten Wert ueberein"},
        "lengths": {"g": G, "A_b64u_chars": len(b64u(pad(A))), "B_b64u_chars": len(b64u(pad(B))),
                    "M_b64u_chars": len(b64u(m1)), "salt_b64u_chars": len(b64u(salt)),
                    "device_id_chars": len(device_id), "webhook_id_chars": len(webhook_id)},
    }

    # Webhook
    key_a2h, key_h2a = keys["K_a2h"], keys["K_h2a"]
    path = "/api/webhook/" + webhook_id
    other_key = T("other-key")
    other_path = "/api/webhook/" + b64u(T("other-webhook"))

    def j(o):
        return json.dumps(o, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    media_ep = {"kind": "episode", "title": "Pilot", "series": "Beispielserie", "season": 1,
                "episode": 2, "duration_ms": 2700000, "position_ms": 125000}
    p_state = {"v": 1, "type": "state", "rev": 7, "status": "playing", "media": media_ep}
    p_state_idle = {"v": 1, "type": "state", "rev": 8, "status": "idle"}
    p_hb = {"v": 1, "type": "heartbeat", "app_version": "0.3.0", "platform": "tizen",
            "state_rev": 7, "ws": False,
            "sub": {"expires": "2027-03-31", "connections_active": 1, "connections_max": 2}}
    p_ev = {"v": 1, "type": "event", "name": "channel_changed",
            "media": {"kind": "live", "channel": "Beispielsender 1"}}
    p_uml = {"v": 1, "type": "state", "rev": 9, "status": "paused",
             "media": {"kind": "movie", "title": "Größe – Ärger \U0001F600"}}
    long_title = {"v": 1, "type": "state", "rev": 10, "status": "playing",
                  "media": {"kind": "movie", "title": "x" * 121}}
    ev_unknown = {"v": 1, "type": "event", "name": "something_new"}
    st_extra = dict(p_state_idle, future_field=True)
    unpair = {"v": 1, "type": "unpair"}

    def case(name, desc, last_seq, ha_rev, body, extra=None, ctype=None):
        dev = {"device_id": device_id, "key_a2h": key_a2h, "key_h2a": key_h2a,
               "last_seq": last_seq, "ha_state_rev": ha_rev}
        res = receive(body, webhook_id, dev, **(ctype or {}))
        c = {"name": name, "description": desc, "last_seq_before": last_seq,
             "ha_state_rev_before": ha_rev, "body": body.decode("utf-8"),
             "expect": {k: res[k] for k in res if k != "proof"},
             "last_seq_after": dev["last_seq"]}
        if "proof" in res:
            c["expect"]["proof"] = res["proof"]
        if ctype:
            c["content_type"] = ctype["content_type"]
        if extra:
            c.update(extra)
        return c

    def good(seq, payload_obj, kp=path, key=key_a2h, dev_id=device_id):
        return build_body(key, kp, dev_id, seq, j(payload_obj))

    cases = []
    ex = lambda body, seq, pobj: {  # noqa: E731
        "signing_input_hex": hx(signing_input("POST", path, device_id, seq, j(pobj)))}
    cases.append(case("state_episode", "Gueltiger state mit Serie", 41, 6, good(42, p_state),
                      ex(None, 42, p_state)))
    cases.append(case("heartbeat_in_sync", "heartbeat mit passender state_rev", 42, 7, good(43, p_hb)))
    cases.append(case("heartbeat_resync", "state_rev passt nicht: HA verlangt neuen state", 42, 3,
                      good(43, p_hb)))
    cases.append(case("event_channel", "Gueltiges Ereignis", 43, 7, good(44, p_ev)))
    cases.append(case("unicode_title", "Umlaute, Gedankenstrich, Emoji (UTF-8, Signatur ueber Rohbytes)",
                      44, 7, good(45, p_uml), ex(None, 45, p_uml)))
    cases.append(case("idle_state", "state ohne media", 45, 7, good(46, p_state_idle)))
    cases.append(case("gap_ok", "Luecke in der Sequenz ist erlaubt", 46, 8, good(150, p_state_idle)))
    cases.append(case("unpair", "Trennen durch die App", 150, 8, good(151, unpair)))
    cases.append(case("unknown_event_ignored", "Unbekanntes Ereignis wird angenommen und ignoriert",
                      46, 8, good(47, ev_unknown)))
    cases.append(case("unknown_field_ignored", "Unbekanntes Feld wird ignoriert", 46, 8, good(47, st_extra)))
    cases.append(case("replay_same_seq", "Gleiche Sequenz erneut", 47, 8, good(47, p_state_idle)))
    cases.append(case("replay_old_seq", "Alte Sequenz", 100, 8, good(47, p_state_idle)))
    tampered = good(48, p_state).replace(b"Pilot", b"Pilat")
    cases.append(case("tampered_payload", "Nutzlast nach dem Signieren veraendert", 47, 8, tampered))
    cases.append(case("wrong_path", "Fuer anderen Webhook signiert", 47, 8, good(48, p_state, kp=other_path)))
    cases.append(case("wrong_key", "Mit fremdem Schluessel signiert", 47, 8, good(48, p_state, key=other_key)))
    cases.append(case("wrong_device", "Fremde device_id im Body",
                      47, 8, good(48, p_state, dev_id=b64u(T("x")[:16]))))
    cases.append(case("version_2", "Unbekannte Hauptversion", 47, 8,
                      b"ITP/2\n" + good(48, p_state).split(b"\n", 1)[1]))
    cases.append(case("too_few_lines", "Zu wenige Zeilen", 47, 8, b"ITP/1\nabc\n"))
    sig48 = good(48, p_state).split(b"\n", 4)
    cases.append(case("seq_leading_zero", "Sequenz mit fuehrender Null", 47, 8,
                      b"\n".join([sig48[0], sig48[1], b"048", sig48[3], sig48[4]])))
    cases.append(case("seq_zero", "Sequenz 0", 0, 8, good(0, p_state)))
    cases.append(case("sig_not_b64u", "Signatur mit Padding", 47, 8,
                      b"\n".join([sig48[0], sig48[1], sig48[2], sig48[3] + b"=", sig48[4]])))
    cases.append(case("bad_payload_consumes_seq", "Gueltige Signatur, Titel zu lang: 422, Sequenz verbraucht",
                      47, 8, good(48, long_title)))
    cases.append(case("not_json", "Gueltige Signatur, kein JSON: 422", 47, 8, build_body(
        key_a2h, path, device_id, 48, b"not json")))
    dup = build_body(key_a2h, path, device_id, 48,
                     b'{"v":1,"type":"heartbeat","app_version":"0.3.0","platform":"tizen","state_rev":1,"state_rev":2}')
    cases.append(case("duplicate_json_key", "Doppelter JSON-Schluessel: 422", 47, 8, dup))
    cases.append(case("wrong_content_type", "Content-Type application/json am Webhook: 400, Sequenz nicht verbraucht",
                      47, 8, good(48, p_state), ctype={"content_type": "application/json"}))
    cases.append(case("content_type_charset_ok", "text/plain mit Parameter ist erlaubt",
                      47, 8, good(48, p_state_idle), ctype={"content_type": "Text/Plain; charset=utf-8"}))
    cases.append(case("heartbeat_after_restart", "ha_state_rev unbekannt (null) nach HA-Neustart: erster heartbeat gibt resync",
                      47, None, good(48, p_hb)))
    cases.append(case("too_large", "Body ueber 4096 Byte", 47, 8, b"ITP/1\n" + b"x" * 4100))
    v["webhook"] = {
        "device_id": device_id, "webhook_id": webhook_id, "path": path,
        "K_a2h_hex": hx(key_a2h), "K_h2a_hex": hx(key_h2a),
        "canonical_form": "lp(ITP1-REQ, POST, PATH, DEVICE_ID, SEQ-Dezimaltext, PAYLOAD-Rohbytes); lp = 4 Byte Big-Endian-Laenge + Feld je Feld",
        "cases": cases,
    }

    # Nutzlast-Faelle
    def vc(name, obj, expect=None):
        return {"name": name, "payload": obj, "expect": validate_payload(obj) if expect is None else expect}

    m = lambda **kw: dict({"kind": "movie"}, **kw)  # noqa: E731
    st = lambda **kw: dict({"v": 1, "type": "state", "rev": 1, "status": "playing"}, **kw)  # noqa: E731
    emoji120 = "\U0001F600" * 120
    emoji121 = "\U0001F600" * 121
    pl = {"updated": "2026-10-15T08:30:00Z", "live": 1200, "movies": 5400, "series": 800, "error": "none"}
    pic = "https://img.example.com/covers/123.jpg"
    vcs = [
        vc("state_ok", p_state), vc("state_idle_ok", p_state_idle),
        vc("state_live_ok", st(media={"kind": "live", "channel": "Beispielsender 1", "title": "Nachrichten"})),
        vc("title_120_emoji_ok", st(media=m(title=emoji120))),
        vc("title_121_emoji_bad", st(media=m(title=emoji121))),
        vc("title_empty_bad", st(media=m(title=""))),
        vc("title_control_char_bad", st(media=m(title="a\nb"))),
        vc("status_unknown_bad", st(status="running")),
        vc("rev_negative_bad", st(rev=-1)),
        vc("rev_float_bad", st(rev=1.0)),
        vc("rev_bool_bad", st(rev=True)),
        vc("season_negative_bad", st(media={"kind": "episode", "season": -1})),
        vc("episode_fields_on_movie_bad", st(media=m(season=1))),
        vc("channel_on_movie_bad", st(media=m(channel="X"))),
        vc("live_with_position_bad", st(media={"kind": "live", "position_ms": 5})),
        vc("position_after_end_bad", st(media=m(duration_ms=1000, position_ms=2000))),
        vc("duration_over_48h_bad", st(media=m(duration_ms=172800001))),
        vc("media_in_idle_bad", dict(p_state_idle, media={"kind": "movie"})),
        vc("kind_unknown_bad", st(media={"kind": "adult"})),
        vc("version_2", dict(p_state_idle, v=2)),
        vc("heartbeat_ok", p_hb),
        vc("heartbeat_minimal_ok", {"v": 1, "type": "heartbeat", "app_version": "0.3.0",
                                    "platform": "android", "state_rev": 0}),
        vc("heartbeat_version_bad", dict(p_hb, app_version="v0.3")),
        vc("heartbeat_platform_bad", dict(p_hb, platform="webos")),
        vc("heartbeat_expires_bad_date", dict(p_hb, sub={"expires": "2027-02-30"})),
        vc("heartbeat_expires_null_ok", dict(p_hb, sub={"expires": None})),
        vc("heartbeat_connections_bad", dict(p_hb, sub={"connections_active": 100})),
        vc("event_ok", p_ev),
        vc("event_stopped_reason_ok", {"v": 1, "type": "event", "name": "playback_stopped", "reason": "ended"}),
        vc("event_reason_on_wrong_event_bad", {"v": 1, "type": "event", "name": "channel_changed", "reason": "ended"}),
        vc("event_name_uppercase_bad", {"v": 1, "type": "event", "name": "PlaybackStarted"}),
        vc("event_unknown_name_ok", ev_unknown),
        vc("event_name_trailing_lf_bad", {"v": 1, "type": "event", "name": "playback_started\n"}),
        vc("heartbeat_version_trailing_lf_bad", dict(p_hb, app_version="0.3.0\n")),
        vc("heartbeat_expires_trailing_lf_bad", dict(p_hb, sub={"expires": "2027-03-31\n"})),
        vc("unknown_type_ignored", {"v": 1, "type": "future"}),
        vc("not_an_object", [1, 2]),
        vc("picture_ok", dict(p_state, picture=pic)),
        vc("picture_without_media_bad", dict(p_state_idle, picture=pic)),
        vc("picture_javascript_bad", dict(p_state, picture="javascript:alert(1)")),
        vc("picture_userinfo_bad", dict(p_state, picture="https://u:p@img.example.com/a.jpg")),
        vc("picture_private_bad", dict(p_state, picture="http://192.168.1.5/a.jpg")),
        vc("picture_not_string_bad", dict(p_state, picture=5)),
        vc("playlist_updated_arabic_digits_bad", dict(p_hb, playlist={"updated": "\u0662\u0660\u0662\u0666-10-15T08:30:00Z"})),
        vc("heartbeat_expires_fullwidth_digits_bad", dict(p_hb, sub={"expires": "\uff12\uff10\uff12\uff17-03-31"})),
        vc("playlist_unknown_field_ok", dict(p_hb, playlist={"live": 1, "address": "x"})),
        vc("playlist_ok", dict(p_hb, playlist=pl)),
        vc("playlist_empty_ok", dict(p_hb, playlist={})),
        vc("playlist_updated_null_ok", dict(p_hb, playlist={"updated": None})),
        vc("playlist_max_ok", dict(p_hb, playlist={"live": 999999, "movies": 0, "series": 999999})),
        vc("playlist_live_too_big_bad", dict(p_hb, playlist={"live": 1000000})),
        vc("playlist_negative_bad", dict(p_hb, playlist={"movies": -1})),
        vc("playlist_float_bad", dict(p_hb, playlist={"series": 1.0})),
        vc("playlist_updated_no_z_bad", dict(p_hb, playlist={"updated": "2026-10-15T08:30:00"})),
        vc("playlist_updated_offset_bad", dict(p_hb, playlist={"updated": "2026-10-15T08:30:00+02:00"})),
        vc("playlist_updated_bad_date_bad", dict(p_hb, playlist={"updated": "2026-02-30T08:30:00Z"})),
        vc("playlist_updated_lf_bad", dict(p_hb, playlist={"updated": "2026-10-15T08:30:00Z\n"})),
        vc("playlist_error_unknown_bad", dict(p_hb, playlist={"error": "http_404"})),
        vc("playlist_not_object_bad", dict(p_hb, playlist=[1])),
        vc("event_playlist_refreshed_ok", {"v": 1, "type": "event", "name": "playlist_refreshed"}),
        vc("event_playlist_failed_ok", {"v": 1, "type": "event", "name": "playlist_failed", "error": "unauthorized"}),
        vc("event_playlist_failed_no_error_bad", {"v": 1, "type": "event", "name": "playlist_failed"}),
        vc("event_playlist_failed_none_bad", {"v": 1, "type": "event", "name": "playlist_failed", "error": "none"}),
        vc("event_playlist_failed_unknown_error_bad", {"v": 1, "type": "event", "name": "playlist_failed", "error": "x"}),
        vc("event_error_on_other_bad", {"v": 1, "type": "event", "name": "playlist_refreshed", "error": "other"}),
    ]
    E = "https://example.com/x.png"
    # Hand eingetragene Erwartungen (nicht aus picture_ok erzeugt): (url, gueltig, Begruendung)
    pic_cases = [
        ("https://img.example.com/covers/123.jpg", True, "normale URL"),
        ("http://cdn.example.org:8080/logo.png?size=large", True, "http mit Port und harmloser Query"),
        ("https://example.com/a%20b.jpg", True, "Prozent-Kodierung im Pfad"),
        ("https://example.com/p?width=200&height=300", True, "mehrere Parameter"),
        ("https://example.com/x?a=1;b=2", True, "Semikolon als Trenner, harmlos"),
        ("https://example.com/x?name=cover", True, "name allein ist kein Zugangsname"),
        ("https://example.com/livestock/a.jpg", True, "Segment nur aehnlich wie live"),
        ("https://example.com/images/series-cover.jpg", True, "Segment ist nicht exakt series"),
        ("https://example.com/x?%2570assword=1", True, "doppelt kodiert: nur einmal dekodiert, Name bleibt %70assword"),
        ("https://example.com:443/x.png", True, "Port 443"),
        ("http://example.com:65535/x", True, "hoechster Port"),
        ("https://xn--bcher-kva.example.org/x.png", True, "Punycode-Host"),
        ("http://8.8.8.8/x.png", True, "oeffentliche IPv4"),
        ("http://93.184.216.34/x.png", True, "oeffentliche IPv4"),
        ("http://198.51.101.1/x", True, "knapp ausserhalb 198.51.100.0/24"),
        ("http://203.0.114.1/x", True, "knapp ausserhalb 203.0.113.0/24"),
        ("http://172.32.0.1/x", True, "knapp ausserhalb 172.16.0.0/12"),
        ("http://100.128.0.1/x", True, "knapp ausserhalb 100.64.0.0/10"),
        ("http://169.255.0.1/x", True, "knapp ausserhalb 169.254.0.0/16"),
        ("http://11.0.0.1/x", True, "knapp ausserhalb 10.0.0.0/8"),
        ("http://[2001:4860:4860::8888]/x.png", True, "oeffentliche IPv6"),
        ("http://[2600::1]/x.png", True, "oeffentliche IPv6"),
        ("http://[2001:1::1]/x.png", True, "knapp ausserhalb 2001::/32"),
        ("http://127.0.0.1.nip.io/x.png", True, "Restrisiko: DNS-Name mit Loopback-Aufloesung nicht ausschliessbar"),
        ("http://localtest.me/x.png", True, "Restrisiko: DNS-Name mit Loopback-Aufloesung nicht ausschliessbar"),
        # Schema
        ("javascript:alert(1)", False, "Schema javascript"), ("file:///etc/passwd", False, "Schema file"),
        ("data:image/png;base64,AAAA", False, "Schema data"), ("ftp://example.com/x.png", False, "Schema ftp"),
        ("//example.com/a.png", False, "schemalos"), ("HTTPS://example.com/x.png", False, "Schema gross"),
        # Userinfo, Fragment, Laenge, Zeichen
        ("https://user:pass@example.com/x.png", False, "Userinfo"), ("https://user@example.com/x.png", False, "Userinfo ohne Passwort"),
        (E + "#a", False, "Fragment"), (E + "#", False, "leeres Fragment"),
        ("https://example.com/" + "a" * 493, False, "513 Zeichen"), ("", False, "leer"),
        ("https://exa mple.com/x.png", False, "Leerzeichen"), ("https://example.com/\n", False, "LF"),
        (E + "\n", False, "angehaengtes LF"), ("https://bücher.example.org/x.png", False, "Nicht-ASCII"),
        ("https:///x.png", False, "Host leer"), ("https://example.com\\@evil.com/", False, "Backslash"),
        ("http://example.com./x", False, "Punkt am Ende"), ("http://-bad.example.com/x", False, "Label mit Bindestrich"),
        # Host-Klammern und Port
        ("http://[example.com]/", False, "Klammern um Hostnamen"), ("http://[8.8.8.8]/x", False, "Klammern um IPv4"),
        ("http://[::1/x", False, "Klammer offen"), ("http://::1]/x", False, "Klammer zu ohne auf"),
        ("http://[::1]x/", False, "Zeichen nach Klammer"), ("http://[fe80::1%25eth0]/x", False, "Zone-ID"),
        ("http://example.com:/x", False, "Doppelpunkt ohne Port"), ("http://example.com:0/x", False, "Port 0"),
        ("http://example.com:080/x", False, "fuehrende Null"), ("http://example.com:00080/x", False, "fuehrende Nullen"),
        ("http://example.com:65536/x", False, "Port zu gross"), ("http://example.com:99999/x", False, "Port zu gross"),
        ("http://example.com:123456/x", False, "sechs Ziffern"), ("http://example.com:1a/x", False, "Port mit Buchstabe"),
        ("http://example.com:+80/x", False, "Port mit Vorzeichen"), ("http://[2001:4860::1]:/x", False, "IPv6 Doppelpunkt ohne Port"),
        ("http://[2001:4860::1]:0/x", False, "IPv6 Port 0"),
        # IPv4-Sperrliste (je Bereich ein Treffer, dazu Grenzen)
        ("http://0.1.2.3/x", False, "0.0.0.0/8"), ("http://10.0.0.5/x", False, "10.0.0.0/8"),
        ("http://10.255.255.255/x", False, "10/8 Ende"), ("http://100.64.0.1/x", False, "100.64.0.0/10"),
        ("http://100.127.255.255/x", False, "100.64/10 Ende"), ("http://127.0.0.1/x", False, "127.0.0.0/8"),
        ("http://127.255.255.254/x", False, "127/8 Ende"), ("http://169.254.169.254/latest", False, "169.254.0.0/16"),
        ("http://172.16.0.1/x", False, "172.16.0.0/12"), ("http://172.31.255.255/x", False, "172.16/12 Ende"),
        ("http://192.0.0.1/x", False, "192.0.0.0/24"), ("http://192.0.2.1/x", False, "192.0.2.0/24"),
        ("http://192.88.99.1/x", False, "192.88.99.0/24"), ("http://192.168.1.1/x", False, "192.168.0.0/16"),
        ("http://198.18.0.1/x", False, "198.18.0.0/15"), ("http://198.19.255.255/x", False, "198.18/15 Ende"),
        ("http://198.51.100.7/x", False, "198.51.100.0/24"), ("http://203.0.113.9/x", False, "203.0.113.0/24"),
        ("http://224.0.0.1/x", False, "224.0.0.0/4 Multicast"), ("http://239.255.255.250/x", False, "Multicast Ende"),
        ("http://240.0.0.1/x", False, "240.0.0.0/4"), ("http://255.255.255.255/x", False, "Broadcast"),
        ("http://0.0.0.0/x", False, "unspezifiziert"),
        # IPv4-Schreibweisen
        ("http://2130706433/x", False, "Dezimal-IP"), ("http://0x7f.1/x", False, "Hex-IP"), ("http://127.1/x", False, "Kurz-IP"),
        ("http://010.0.0.1/x", False, "fuehrende Null"), ("http://8.8.8.256/x", False, "Oktett > 255"),
        ("http://1.2.3/x", False, "drei Oktette"), ("http://8.8.8.8.8/x", False, "fuenf Oktette"),
        # IPv6-Sperrliste
        ("http://[::]/x", False, "::/128"), ("http://[::1]/x", False, "::1/128"),
        ("http://[::808:808]/x", False, "::/96 IPv4-kompatibel"), ("http://[::ffff:8.8.8.8]/x", False, "::ffff:0:0/96 gemappt, oeffentlich"),
        ("http://[::ffff:127.0.0.1]/x", False, "gemappt Loopback"), ("http://[::ffff:7f00:1]/x", False, "gemappt hex"),
        ("http://[64:ff9b::808:808]/x", False, "NAT64"), ("http://[64:ff9b:1::1]/x", False, "64:ff9b:1::/48"),
        ("http://[100::1]/x", False, "100::/64"), ("http://[2001::1]/x", False, "Teredo 2001::/32"),
        ("http://[2001:db8::1]/x", False, "Dokumentation"), ("http://[2002:808:808::1]/x", False, "6to4"),
        ("http://[fc00::1]/x", False, "fc00::/7"), ("http://[fd12::1]/x", False, "ULA"),
        ("http://[fe80::1]/x", False, "Link-Local"), ("http://[febf::1]/x", False, "Link-Local Ende"),
        ("http://[ff02::1]/x", False, "Multicast"),
        ("http://[fec0::1]/x", False, "fec0::/10 Site-Local"), ("http://[2001:10::1]/x", False, "2001:10::/28"),
        ("http://[2001:1f::1]/x", False, "2001:10::/28 Ende"), ("http://[2001:20::1]/x", True, "knapp ausserhalb 2001:10::/28"),
        ("http://[::ffff:0:0:1]/x", False, "::ffff:0:0:0/96 (SIIT)"),
        ("http://Example.COM/x.png", True, "Host gross geschrieben"), ("http://X.TEST/x", False, "Host gross: .TEST"),
        ("http://LOCALHOST/x", False, "Host gross: LOCALHOST"),
        # Hostnamen
        ("http://localhost/x", False, "localhost"), ("http://a.localhost/x", False, "Unterdomain von localhost"),
        ("http://nas/x", False, "ein Label"), ("http://x.test/x", False, ".test"), ("http://x.invalid/x", False, ".invalid"),
        ("http://x.example/x", False, ".example"), ("http://printer.local/x", False, ".local"),
        ("http://host.internal/x", False, ".internal"), ("http://x.lan/x", False, ".lan"),
        ("http://x.home.arpa/x", False, ".home.arpa"), ("http://x.localdomain/x", False, ".localdomain"),
        ("http://x.corp/x", False, ".corp"), ("http://a.b.test/x", False, "tiefe Unterdomaene von .test"),
        # Query-Namen
        (E + "?username=a", False, "username"), (E + "?user=a", False, "user"), (E + "?usr=a", False, "usr"),
        (E + "?login=a", False, "login"), (E + "?uid=1", False, "uid"), (E + "?user_name=a", False, "user_name"),
        (E + "?User-Name=a", False, "User-Name"), (E + "?password=a", False, "password"), (E + "?pass=a", False, "pass"),
        (E + "?passwd=a", False, "passwd"), (E + "?pw=a", False, "pw"), (E + "?pwd=a", False, "pwd"),
        (E + "?token=a", False, "token"), (E + "?accesstoken=a", False, "accesstoken"), (E + "?access_token=a", False, "access_token"),
        (E + "?access-token=a", False, "access-token"), (E + "?key=a", False, "key"), (E + "?apikey=a", False, "apikey"),
        (E + "?api_key=a", False, "api_key"), (E + "?auth=a", False, "auth"), (E + "?authorization=a", False, "authorization"),
        (E + "?secret=a", False, "secret"), (E + "?sig=a", False, "sig"), (E + "?signature=a", False, "signature"),
        (E + "?X-Amz-Signature=a", False, "X-Amz-Signature"), (E + "?session=a", False, "session"), (E + "?sid=a", False, "sid"),
        (E + "?xamzcredential=a", False, "xamzcredential"), (E + "?X-Amz-Credential=a", False, "X-Amz-Credential"),
        (E + "?x-amz-security-token=a", False, "x-amz-security-token"), (E + "?sessionid=a", False, "sessionid"),
        (E + "?session_id=a", False, "session_id"), (E + "?Bearer=a", False, "Bearer"),
        (E + "?ticket=a", False, "ticket"), (E + "?credential=a", False, "credential"), (E + "?Token=a", False, "Gross-/Kleinschreibung"),
        (E + "?a=1&API_KEY=2", False, "zweiter Parameter"), (E + "?a=1;token=2", False, "Semikolon-Trenner"),
        (E + "?to+ken=1", False, "Plus wird Leerzeichen und entfernt"), (E + "?%74oken=1", False, "Prozent-kodierter Name"),
        (E + "?%70assword=1", False, "Prozent-kodierter Name"), (E + "?user", False, "Name ohne Wert"),
        (E + "?a=%zz", False, "ungueltige %-Folge im Wert"), (E + "?a=%", False, "einzelnes Prozentzeichen"),
        (E + "?a=%0", False, "halbe %-Folge"), (E + "?a=%00", False, "NUL"), (E + "?a=%0A", False, "LF dekodiert"),
        (E + "?%00=1", False, "NUL im Namen"), (E + "?a=%ff", False, "ungueltiges UTF-8"), (E + "?a%zz=1", False, "ungueltige %-Folge im Namen"),
        # Pfad
        ("https://example.com/Movie/a.png", False, "Segment gross: Movie"), ("https://example.com/LIVE/a.png", False, "Segment gross: LIVE"),
        ("https://example.com/a/x.MP4", False, "Endung gross: .MP4"), ("https://example.com/a/x.M3U8", False, "Endung gross"),
        ("https://example.com/a%2Flive/x.jpg", False, "%2F vor live"), ("https://example.com/a%2fx.ts", False, "%2f vor Endung .ts"),
        ("https://example.com/%2Fmovie/x.jpg", False, "%2F vor movie"), ("https://example.com/a%2Fb/x.jpg", True, "%2F, harmlose Segmente"),
        ("https://example.com/live/a.png", False, "Segment live"), ("https://example.com/movie/u/p/1.jpg", False, "Xtream-Muster movie"),
        ("https://example.com/series/1.jpg", False, "Segment series"), ("https://example.com/vod/1.jpg", False, "Segment vod"),
        ("https://example.com/stream/1.jpg", False, "Segment stream"), ("https://example.com/hls/1.jpg", False, "Segment hls"),
        ("https://example.com/%6Cive/1.jpg", False, "kodiertes live"), ("https://example.com/a/x.ts", False, "Endung .ts"),
        ("https://example.com/a/x.m3u8", False, "Endung .m3u8"), ("https://example.com/a/x.m3u", False, "Endung .m3u"),
        ("https://example.com/a/x.mp4", False, "Endung .mp4"), ("https://example.com/a/x.mkv", False, "Endung .mkv"),
        ("https://example.com/a/x.avi", False, "Endung .avi"), ("https://example.com/a/x.mp3", False, "Endung .mp3"),
        ("https://example.com/a%zz", False, "ungueltige %-Folge im Pfad"), ("https://example.com/a%00b", False, "NUL im Pfad"),
    ]
    v["picture_urls"] = {
        "note": "Erwartungen von Hand eingetragen, nicht aus picture_ok erzeugt. picture_ok: nur oeffentliche http(s)-Adressen, siehe PROTOCOL.md 5.2a. Die Integration prueft ohne Zugangsdaten; die App zusaetzlich app_credential_cases.",
        "cases": [{"url": u, "valid": ok, "why": why} for u, ok, why in pic_cases]}
    def cc(url, user, pw, drop, why):
        return {"url": url, "username": user, "password": pw, "drop": drop, "why": why}

    I = "https://img.example.com"
    v["app_credential_cases"] = {
        "note": "App-seitig (Erwartungen von Hand): nur Pfad und Query, nicht Schema/Host; gross/klein egal; unter 4 Zeichen nur als ganzes Pfadsegment oder ganzer Query-Wert, ab 4 als Teilzeichenkette (roh oder einmal dekodiert); leer/null zaehlt nicht.",
        "cases": [
            cc(I + "/covers/a.jpg", "alice", "hunter2", False, "harmlos"),
            cc(I + "/alice/a.jpg", "alice", "hunter2", True, "Benutzername als Segment"),
            cc(I + "/covers/alice.jpg", "alice", "hunter2", True, "Benutzername als Teilstring (>= 4)"),
            cc(I + "/covers/a.jpg?x=hunter2", "alice", "hunter2", True, "Passwort als Query-Wert"),
            cc(I + "/covers/a.jpg?x=pre-hunter2-post", "alice", "hunter2", True, "Passwort als Teilstring in Query"),
            cc(I + "/covers/a%6Cice.jpg", "alice", "hunter2", True, "einfach kodiert"),
            cc(I + "/ALICE/a.jpg", "alice", "hunter2", True, "Grossbuchstaben in URL"),
            cc(I + "/alice/a.jpg", "ALICE", "x", True, "Grossbuchstaben im Namen"),
            cc(I + "/M%C3%BCller/a.jpg", "M\u00fcller", "x", True, "Umlaut, einfach kodiert"),
            cc(I + "/m%C3%9CLLER/a.jpg", "M\u00fcller", "x", True, "Umlaut, Gross/Klein gemischt"),
            cc(I + "/p%40ss/a.jpg", "u", "p@ss", True, "Sonderzeichen @, 4 Zeichen"),
            cc(I + "/x/a%20b/y.jpg", "a b", "x", True, "kurz mit Leerzeichen als ganzes Segment"),
            cc(I + "/a%20b.jpg", "a b", "x", False, "kurz mit Leerzeichen nur Teilstring"),
            cc(I + "/x.jpg?k=a+b", "a+b", "x", True, "kurz mit Plus als ganzer Query-Wert, roh"),
            cc(I + "/x.jpg?k=a%2Bb", "a+b", "x", True, "kurz mit Plus, kodiert"),
            cc(I + "/a/x.jpg", "a", "x", True, "kurz als ganzes Segment"),
            cc(I + "/data/x.jpg", "a", "x", False, "kurz nur als Teilstring: kein Treffer"),
            cc(I + "/x.jpg?k=a", "a", "x", True, "kurz als ganzer Query-Wert"),
            cc(I + "/x.jpg?k=abc", "a", "x", False, "kurz nur Teilstring in Query"),
            cc(I + "/x.jpg", "x", "com", False, "com steht nur im Host"),
            cc("https://img.example.com/x.jpg", "x", "http", False, "http steht nur im Schema"),
            cc(I + "/x.jpg?u=http", "x", "http", True, "http als Query-Wert"),
            cc("https://alice.example.com/x.jpg", "alice", "x", False, "Name nur im Host"),
            cc(I + "/x.jpg", "", None, False, "leer und null"),
            cc(I + "/x.jpg?k=", "", "", False, "leere Werte zaehlen nicht"),
            cc(I + "/%2568unter2/x.jpg", "x", "hunter2", False, "Restrisiko: doppelt kodiert wird nicht erkannt"),
            cc(I + "/hun/ter2/x.jpg", "x", "hunter2", False, "Restrisiko: ueber Segmente verteilt")]}
    strip_cases = [
        {"name": "state", "input": {"v": 1, "type": "state", "rev": 2, "status": "playing", "foo": 1,
                                    "picture": "https://img.example.com/c.jpg",
                                    "media": {"kind": "movie", "title": "T", "x": 5}},
         "expect": {"v": 1, "type": "state", "rev": 2, "status": "playing",
                    "picture": "https://img.example.com/c.jpg", "media": {"kind": "movie", "title": "T"}}},
        {"name": "event", "input": {"v": 1, "type": "event", "name": "playlist_failed", "error": "other", "z": 1},
         "expect": {"v": 1, "type": "event", "name": "playlist_failed", "error": "other"}},
        {"name": "unknown_type", "input": {"v": 1, "type": "future", "a": 1}, "expect": {}},
        {"name": "unknown_event_name", "input": {"v": 1, "type": "event", "name": "something_new", "a": 1}, "expect": {}},
        {"name": "unpair", "input": {"v": 1, "type": "unpair", "a": 1}, "expect": {"v": 1, "type": "unpair"}}]
    v["strip_unknown"] = {
        "note": "Integration verwirft unbekannte Felder in allen Objekten.",
        "cases": strip_cases,
        "input": {"v": 1, "type": "heartbeat", "app_version": "0.3.0", "platform": "tizen", "state_rev": 1,
                  "extra": 1, "sub": {"expires": None, "x": 1},
                  "playlist": {"live": 5, "address": "https://secret.example/p", "error": "none"}},
        "expect": {"v": 1, "type": "heartbeat", "app_version": "0.3.0", "platform": "tizen", "state_rev": 1,
                   "sub": {"expires": None}, "playlist": {"live": 5, "error": "none"}}}
    v["payloads"] = {"note": "expect null = gueltig; sonst Grundcode (bei HA: bad_payload bzw. unsupported_version).",
                     "cases": vcs}

    # WebSocket
    na, nh = b64u(T("ws-na")[:16]), b64u(T("ws-nh")[:16])
    sid = na + "." + nh
    n1, n2 = b64u(T("ws-n1")[:16]), b64u(T("ws-n2")[:16])
    c1, c2 = b64u(T("ws-id1")[:16]), b64u(T("ws-id2")[:16])

    def cmd(cid, nonce, c, arg, key=key_h2a):
        return {"type": "command", "id": cid, "nonce": nonce, "cmd": c, "arg": arg,
                "sig": ws_cmd_sig(key, device_id, sid, nonce, cid, c, arg)}

    def wcase(name, desc, msg, pending, seen, control=True, idle=False):
        stt = {"key_h2a": key_h2a, "device_id": device_id, "sid": sid, "pending_nonce": pending,
               "seen_ids": list(seen), "control_enabled": control, "nothing_playing": idle}
        res = app_check_command(msg, stt)
        return {"name": name, "description": desc, "message": msg, "pending_nonce": pending,
                "seen_ids": list(seen), "control_enabled": control, "nothing_playing": idle,
                "expect": {"result": res[0], "reason": res[1], "ack_id": res[2], "nonce_consumed": res[3]}}

    def mkack(cid, result, reason, nn, key=key_a2h):
        return {"type": "ack", "id": cid, "result": result, "reason": reason, "next_nonce": nn,
                "mac": ws_ack_mac(key, device_id, sid, cid, result, reason, nn)}

    def acase(name, desc, msg, sent_id):
        r = ha_check_ack(msg, {"key_a2h": key_a2h, "device_id": device_id, "sid": sid, "sent_id": sent_id})
        return {"name": name, "description": desc, "message": msg, "sent_id": sent_id, "expect": r}

    good_ack = mkack(c1, "ok", "", n2)
    ack_cases = [
        acase("ack_ok", "Gueltiger ack", good_ack, c1),
        acase("ack_rejected_ok", "Abgelehnter Befehl, gueltig", mkack(c1, "rejected", "control_disabled", n2), c1),
        acase("ack_empty_id_bad_sig", "Leere id bei bad_sig ist erlaubt", mkack("", "rejected", "bad_sig", n1), c1),
        acase("ack_empty_id_ok_bad", "Leere id nur bei bad_request/bad_sig", mkack("", "ok", "", n1), c1),
        acase("ack_bad_mac", "MAC mit fremdem Schluessel", mkack(c1, "ok", "", n2, key=other_key), c1),
        acase("ack_unknown_id", "id gehoert nicht zum ausstehenden Befehl", mkack(c2, "ok", "", n2), c1),
        acase("ack_result_reason_mismatch", "ok mit Grund", mkack(c1, "ok", "error", n2), c1),
        acase("ack_unknown_reason", "Unbekannter Grund", mkack(c1, "failed", "boom", n2), c1),
        acase("ack_short_next_nonce", "next_nonce nicht 22 Zeichen", mkack(c1, "ok", "", n2[:20]), c1),
        acase("ack_field_missing", "Feld fehlt", {k: val for k, val in good_ack.items() if k != "mac"}, c1),
    ]
    ack_ok_mac = ws_ack_mac(key_a2h, device_id, sid, c1, "ok", "", n2)
    v["websocket"] = {
        "device_id": device_id, "sid": sid,
        "handshake": {
            "hello": {"type": "hello", "v": 1, "device_id": device_id, "nonce": na},
            "challenge": {"type": "challenge", "v": 1, "nonce": nh,
                          "proof": ws_hello_proof_h(key_h2a, device_id, na, nh)},
            "auth": {"type": "auth", "proof": ws_auth_proof_a(key_a2h, device_id, na, nh)},
            "ready": {"type": "ready", "v": 1},
            "nonce_message": {"type": "nonce", "value": n1,
                              "mac": ws_nonce_mac(key_a2h, device_id, sid, n1)}},
        "ack_example": {"type": "ack", "id": c1, "result": "ok", "reason": "", "next_nonce": n2,
                        "mac": ack_ok_mac},
        "ack_cases": ack_cases,
        "command_cases": [
            wcase("play_ok", "Gueltiger Befehl", cmd(c1, n1, "play", ""), n1, []),
            wcase("seek_plus_ok", "+10 s", cmd(c1, n1, "seek_relative", "10000"), n1, []),
            wcase("seek_minus_ok", "-10 s", cmd(c1, n1, "seek_relative", "-10000"), n1, []),
            wcase("seek_arg_bad", "Nur +-10000 erlaubt", cmd(c1, n1, "seek_relative", "60000"), n1, []),
            wcase("bad_sig", "Mit fremdem Schluessel signiert", cmd(c1, n1, "play", "", key=other_key), n1, []),
            wcase("stale_nonce", "Nonce nicht (mehr) aktuell", cmd(c1, n1, "play", ""), n2, []),
            wcase("no_pending_nonce", "Keine Nonce ausgegeben", cmd(c1, n1, "play", ""), None, []),
            wcase("duplicate_id", "Befehls-ID schon gesehen", cmd(c1, n1, "play", ""), n1, [c1]),
            wcase("control_disabled", "Steuerung in der App aus", cmd(c1, n1, "pause", ""), n1, [], control=False),
            wcase("nothing_playing", "Nichts laeuft", cmd(c1, n1, "pause", ""), n1, [], idle=True),
            wcase("bad_sig_keeps_nonce", "Falsche Signatur: Nonce bleibt, ack mit leerer id",
                  cmd(c1, n1, "play", "", key=other_key), n1, []),
            wcase("id_wrong_length", "id nicht 22 Zeichen", cmd(c1[:21], n1, "play", ""), n1, []),
            wcase("nonce_wrong_length", "nonce nicht 22 Zeichen", cmd(c1, n1 + "A", "play", ""), n1, []),
            wcase("field_not_string", "arg ist keine Zeichenkette", dict(cmd(c1, n1, "play", ""), arg=5), n1, []),
            wcase("unknown_command", "Unbekannter Befehl", cmd(c1, n1, "reboot", ""), n1, []),
            wcase("unpair_ok", "Trennen von HA aus, auch ohne Steuerung", cmd(c2, n1, "unpair", ""), n1, [], control=False),
        ],
    }
    return v


# ---------------------------------------------------------- Pruefung
FAILS = []


def expect(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("FEHLER: " + msg)


def check():
    # Bekannte Antworten (unabhaengig von dieser Datei)
    expect(hx(sha256(b"abc")) ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 abc")
    expect(hx(hmac256(bytes.fromhex("0b" * 20), b"Hi There")) ==
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "HMAC RFC 4231 TC1")
    expect(hx(hkdf_expand(hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"),
                                       bytes.fromhex("0b" * 22)),
                          bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)) ==
           "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
           "34007208d5b887185865", "HKDF RFC 5869 TC1")
    nhex = "%0768x" % N
    expect(nhex.startswith("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"), "N Anfang (RFC 3526)")
    expect(nhex.endswith("ffffffffffffffff"), "N Ende")
    expect(N.bit_length() == 3072, "N 3072 Bit")
    expect(is_probable_prime(N), "N ist (wahrscheinlich) prim")
    expect(is_probable_prime((N - 1) // 2), "(N-1)/2 ist (wahrscheinlich) prim (sichere Primzahl)")
    expect(srp_k() != 0, "k")

    if not os.path.exists(VECTORS):
        expect(False, "vectors.json fehlt (python3 reference.py --generate)")
        return
    with open(VECTORS, encoding="utf-8") as f:
        have = json.load(f)
    want = json.loads(json.dumps(build_vectors(), ensure_ascii=False))
    expect(have == want, "vectors.json weicht von der Neuberechnung ab")

    # Faelle aus der Datei mit den Eingaben aus der Datei erneut auswerten
    for s in have["encodings"]["valid"]:
        expect(b64u(bytes.fromhex(s["hex"])) == s["b64u"], "b64u " + s["hex"])
        expect(b64u_dec(s["b64u"]) == bytes.fromhex(s["hex"]), "b64u dec " + s["hex"])
    for s in have["encodings"]["invalid_b64u"]:
        try:
            b64u_dec(s)
            expect(False, "b64u sollte ungueltig sein: %r" % s)
        except ValueError:
            pass
    wh = have["webhook"]
    for c in wh["cases"]:
        dev = {"device_id": wh["device_id"], "key_a2h": bytes.fromhex(wh["K_a2h_hex"]),
               "key_h2a": bytes.fromhex(wh["K_h2a_hex"]), "last_seq": c["last_seq_before"],
               "ha_state_rev": c["ha_state_rev_before"]}
        res = receive(c["body"].encode("utf-8"), wh["webhook_id"], dev,
                      content_type=c.get("content_type", "text/plain;charset=UTF-8"))
        expect(res == c["expect"], "webhook-Fall " + c["name"])
        expect(dev["last_seq"] == c["last_seq_after"], "last_seq nach " + c["name"])
        if "signing_input_hex" in c:
            body = c["body"].encode("utf-8").split(b"\n", 4)
            si = signing_input("POST", wh["path"], wh["device_id"], int(body[2]), body[4])
            expect(hx(si) == c["signing_input_hex"], "Signatureingabe " + c["name"])
    for c in have["payloads"]["cases"]:
        expect(validate_payload(c["payload"]) == c["expect"], "Nutzlast " + c["name"])
    w = have["websocket"]
    for c in w["command_cases"]:
        stt = {"key_h2a": bytes.fromhex(wh["K_h2a_hex"]), "device_id": w["device_id"],
               "sid": w["sid"], "pending_nonce": c["pending_nonce"], "seen_ids": list(c["seen_ids"]),
               "control_enabled": c["control_enabled"], "nothing_playing": c["nothing_playing"]}
        r = app_check_command(c["message"], stt)
        expect({"result": r[0], "reason": r[1], "ack_id": r[2], "nonce_consumed": r[3]} == c["expect"],
               "WS-Befehl " + c["name"])
        if c["name"] in ("bad_sig", "bad_sig_keeps_nonce"):
            expect(stt["pending_nonce"] == c["pending_nonce"], "Nonce bleibt bei bad_sig")
    for c in w["ack_cases"]:
        r = ha_check_ack(c["message"], {"key_a2h": bytes.fromhex(wh["K_a2h_hex"]),
                                        "device_id": w["device_id"], "sid": w["sid"],
                                        "sent_id": c["sent_id"]})
        expect(r == c["expect"], "WS-ack " + c["name"])
    for c in have["app_credential_cases"]["cases"]:
        expect(picture_has_credentials(c["url"], c["username"], c["password"]) == c["drop"], "App-Zugangsdaten " + c["url"][:40])
    expect(strip_unknown(have["strip_unknown"]["input"]) == have["strip_unknown"]["expect"], "strip_unknown")
    for c in have["strip_unknown"]["cases"]:
        expect(strip_unknown(c["input"]) == c["expect"], "strip_unknown " + c["name"])
    for c in have["picture_urls"]["cases"]:
        expect(picture_ok(c["url"]) == c["valid"], "Bild-URL " + c["why"] + ": " + c["url"][:40])
    expect(any(c["valid"] for c in have["picture_urls"]["cases"]) and
           any(not c["valid"] for c in have["picture_urls"]["cases"]), "Bild-URL-Fälle gemischt")
    for c in have["srp_bounds"]["cases"]:
        expect(valid_public(int(c["value_hex"], 16)) == c["valid"], "SRP-Grenze " + c["name"])
    for c in have["names"]["cases"]:
        expect(valid_name(c["value"]) == c["valid"], "name " + c["name"])
    expect(have["length_prefix"]["lp_ab_c_hex"] != have["length_prefix"]["lp_a_bc_hex"], "lp trennt Felder")
    expect(G == 2 and have["srp_group"]["g"] == 2, "g = 2")
    p = have["pairing"]
    expect(p["lengths"]["A_b64u_chars"] == 512 and p["lengths"]["M_b64u_chars"] == 43 and
           p["lengths"]["device_id_chars"] == 22 and p["lengths"]["webhook_id_chars"] == 43,
           "Laengen")
    expect(p["wrong_code"]["M1_hex"] != p["derived"]["M1_hex"], "falscher Code gibt anderes M1")

    if FAILS:
        print("\n%d Fehler" % len(FAILS))
        sys.exit(1)
    print("OK: vectors.json stimmt (%d Webhook-Faelle, %d Nutzlast-Faelle, %d WS-Faelle, %d ack-Faelle)" % (
        len(wh["cases"]), len(have["payloads"]["cases"]), len(w["command_cases"]), len(w["ack_cases"])))


def generate():
    with open(VECTORS, "w", encoding="utf-8") as f:
        json.dump(build_vectors(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("geschrieben: " + VECTORS)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.generate:
        generate()
    if args.check or not args.generate:
        check()
