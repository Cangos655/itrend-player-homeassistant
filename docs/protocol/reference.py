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
import json
import os
import re
import sys

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
EVENTS = {"playback_started", "playback_stopped", "channel_changed", "trailer_opened"}
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
            return validate_media(o["media"])
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
                if not isinstance(e, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", e):
                    return "sub_expires"
                try:
                    datetime.date.fromisoformat(e)
                except ValueError:
                    return "sub_expires"
            for key in ("connections_active", "connections_max"):
                if key in s and not _is_int(s[key], 0, 99):
                    return "sub_" + key
        return None
    if t == "event":
        name = o.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z_]{1,32}", name):
            return "name"
        if name not in EVENTS:
            return None  # unbekannte Ereignisse: annehmen und ignorieren
        if "reason" in o and (name != "playback_stopped" or o["reason"] not in STOP_REASONS):
            return "reason"
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
    ]
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
