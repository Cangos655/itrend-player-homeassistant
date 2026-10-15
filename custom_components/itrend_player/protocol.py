"""Protokoll v1 von iTrend Player <-> Home Assistant: reine Funktionen.

Nur Standardbibliothek. Keine Geheimnisse in Logs. Siehe docs/protocol/PROTOCOL.md.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import re
from typing import Any

SRP_ID = "itrend-ha-pair-v1"
G = 2
NLEN = 384  # Bytes der 3072-Bit-Gruppe (RFC 3526, Gruppe 15)
MAX_SEQ = 2**53 - 1
MAX_BODY = 4096
MAX_PAYLOAD = 2048
MAX_PAIR_BODY = 4096
MAX_MS = 172_800_000

N = int(
    "".join(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33"
        "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
        "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864"
        "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2"
        "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"
    ),
    16,
)

# --------------------------------------------------------------- Grundlagen


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def lp(*fields: bytes | str) -> bytes:
    """Laengenpraefixierte Feldliste (4 Byte Big-Endian-Laenge je Feld)."""
    out = bytearray()
    for field in fields:
        raw = field.encode("utf-8") if isinstance(field, str) else field
        out += len(raw).to_bytes(4, "big") + raw
    return bytes(out)


def ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


_B64RE = re.compile(r"[A-Za-z0-9_-]*")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_dec(text: Any) -> bytes:
    """Streng: kein Padding, nur Alphabet, Laenge mod 4 != 1, kanonisch."""
    if not isinstance(text, str) or not _B64RE.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("bad base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


def b64u_fixed(text: Any, nbytes: int) -> bytes:
    """Streng dekodieren und auf feste Bytelaenge pruefen (ValueError sonst)."""
    raw = b64u_dec(text)
    if len(raw) != nbytes:
        raise ValueError("bad length")
    return raw


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac256(salt if salt else b"\x00" * 32, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac256(prk, block + info + bytes([i]))
        out += block
        i += 1
    return out[:length]


# --------------------------------------------------------------- SRP-6a


def pad(number: int) -> bytes:
    return number.to_bytes(NLEN, "big")


def srp_k() -> int:
    return int.from_bytes(sha256(pad(N) + pad(G)), "big")


def srp_x(salt: bytes, code: str) -> int:
    inner = sha256((SRP_ID + ":" + code).encode("ascii"))
    return int.from_bytes(sha256(salt + inner), "big")


def srp_u(a_pub: int, b_pub: int) -> int:
    return int.from_bytes(sha256(pad(a_pub) + pad(b_pub)), "big")


def srp_verifier(salt: bytes, code: str) -> int:
    return pow(G, srp_x(salt, code), N)


def srp_server_public(verifier: int, b: int) -> int:
    return (srp_k() * verifier + pow(G, b, N)) % N


def srp_server_secret(a_pub: int, verifier: int, b: int, u: int) -> int:
    return pow(a_pub * pow(verifier, u, N) % N, b, N)


def valid_public(x: Any) -> bool:
    """Randwerte: 1 < x < N-1 (gilt fuer A und B)."""
    return isinstance(x, int) and not isinstance(x, bool) and 1 < x < N - 1


def ctx_bytes(name: str, platform: str, app_version: str) -> bytes:
    return lp(name, platform, app_version)


def derive_keys(
    secret: int,
    a_pub: int,
    b_pub: int,
    ctx: bytes,
    device_id: str,
    webhook_id: str,
) -> dict[str, bytes]:
    k_srp = sha256(pad(secret))
    th = sha256(lp("ITP1-TH", pad(a_pub), pad(b_pub), ctx))
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


def proof_m1(k_proof: bytes, a_pub: int, b_pub: int, ctx: bytes) -> bytes:
    return hmac256(k_proof, lp("ITP1-M1", pad(a_pub), pad(b_pub), ctx))


def proof_m2(
    k_proof: bytes,
    a_pub: int,
    b_pub: int,
    m1: bytes,
    device_id: str,
    webhook_id: str,
) -> bytes:
    return hmac256(
        k_proof, lp("ITP1-M2", pad(a_pub), pad(b_pub), m1, device_id, webhook_id)
    )


# ------------------------------------------------- Signatur (App -> HA)


def signing_input(
    method: str, path: str, device_id: str, seq: int | str, payload: bytes
) -> bytes:
    return lp("ITP1-REQ", method, path, device_id, str(seq), payload)


def request_signature(
    key_a2h: bytes, path: str, device_id: str, seq: int | str, payload: bytes
) -> bytes:
    return hmac256(key_a2h, signing_input("POST", path, device_id, seq, payload))


def build_body(
    key_a2h: bytes, path: str, device_id: str, seq: int, payload: bytes
) -> bytes:
    sig = b64u(request_signature(key_a2h, path, device_id, seq, payload))
    return f"ITP/1\n{device_id}\n{seq}\n{sig}\n".encode("ascii") + payload


def resp_proof(
    key_h2a: bytes,
    device_id: str,
    seq: int,
    req_sig: str,
    code: str,
    last_seq: int,
    resync: bool,
) -> str:
    return b64u(
        hmac256(
            key_h2a,
            lp(
                "ITP1-RESP",
                device_id,
                str(seq),
                req_sig,
                code,
                str(last_seq),
                "1" if resync else "0",
            ),
        )
    )


# ------------------------------------------------------ Strenges JSON


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def loads_strict(data: bytes) -> Any:
    """JSON lesen; doppelte Schluessel, NaN/Infinity, ungueltiges UTF-8 -> ValueError."""
    try:
        text = data.decode("utf-8")
        return json.loads(
            text, object_pairs_hook=_no_dupes, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, RecursionError, json.JSONDecodeError) as err:
        raise ValueError("bad json") from err


# ------------------------------------------------- Feldpruefung

KINDS = frozenset({"live", "movie", "episode", "trailer", "other"})
STATUSES = frozenset({"idle", "buffering", "playing", "paused", "closed"})
EVENTS = frozenset(
    {
        "playback_started",
        "playback_stopped",
        "channel_changed",
        "trailer_opened",
        "playlist_refreshed",
        "playlist_failed",
    }
)
STOP_REASONS = frozenset({"ended", "user", "error"})
PLAYLIST_ERRORS = ("none", "no_network", "unauthorized", "server_error", "connection_lost", "storage", "other")
PLATFORMS = frozenset({"android", "tizen"})
KNOWN_TYPES = frozenset({"state", "heartbeat", "event", "unpair"})
# fullmatch statt match mit $: "$" liesse ein nachgestelltes LF durch.
VERSION_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(-[A-Za-z0-9.]{1,16})?")
DATE_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
DATETIME_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
EVENT_NAME_RE = re.compile(r"[a-z_]{1,32}")


def is_int(x: Any, lo: int, hi: int) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and lo <= x <= hi


def is_text(x: Any, lo: int, hi: int) -> bool:
    """Codepunkte zaehlen, keine Steuerzeichen (U+0000-U+001F, U+007F), kein Surrogat."""
    if not isinstance(x, str) or not lo <= len(x) <= hi:
        return False
    try:
        x.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return all(ord(c) >= 0x20 and ord(c) != 0x7F for c in x)


def valid_name(name: Any) -> bool:
    return is_text(name, 1, 40) and len(name.encode("utf-8")) <= 160


def valid_app_version(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 32 and bool(VERSION_RE.fullmatch(value))


def parse_date(text: Any) -> datetime.date | None:
    if not isinstance(text, str) or not (m := DATE_RE.fullmatch(text)):
        return None
    try:
        return datetime.date(*(int(g) for g in m.groups()))
    except ValueError:
        return None


def parse_utc_datetime(text: Any) -> datetime.datetime | None:
    """Genau YYYY-MM-DDTHH:MM:SSZ (ASCII), gueltiges Datum und gueltige Uhrzeit (Sekunde 0-59)."""
    if not isinstance(text, str) or not (m := DATETIME_RE.fullmatch(text)):
        return None
    try:
        return datetime.datetime(*(int(g) for g in m.groups()), tzinfo=datetime.UTC)
    except ValueError:
        return None


# ------------------------------------------------- picture (PROTOCOL.md 5.2a)
PICTURE_MAX = 512
SECRET_QUERY_NAMES = frozenset(
    {
        "username", "user", "usr", "login", "uid", "password", "pass", "passwd", "pw", "pwd",
        "token", "accesstoken", "key", "apikey", "auth", "authorization", "secret", "sig",
        "signature", "xamzsignature", "session", "sid", "ticket", "credential", "xamzcredential",
        "xamzsecuritytoken", "sessionid", "bearer",
    }
)  # fmt: skip
BLOCKED_SUFFIXES = (
    ".test", ".invalid", ".example", ".local", ".localhost", ".internal", ".lan",
    ".home.arpa", ".localdomain", ".corp", ".home", ".intranet", ".private",
)  # fmt: skip
BLOCKED_PATH_SEGMENTS = frozenset({"live", "movie", "series", "vod", "stream", "hls"})
BLOCKED_EXTENSIONS = (".ts", ".m3u8", ".m3u", ".mp4", ".mkv", ".avi", ".mp3")


def _v4_table(cidrs: tuple[str, ...]) -> tuple[tuple[int, int], ...]:
    out = []
    for cidr in cidrs:
        addr, bits = cidr.split("/")
        a, b, c, d = (int(x) for x in addr.split("."))
        out.append(((a << 24 | b << 16 | c << 8 | d), int(bits)))
    return tuple(out)


def _v6_table(cidrs: tuple[str, ...]) -> tuple[tuple[int, int], ...]:
    out = []
    for cidr in cidrs:
        addr, bits = cidr.split("/")
        out.append((_parse_ipv6(addr), int(bits)))  # type: ignore[arg-type]
    return tuple(out)


_V4_RE = re.compile(r"(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}")
_HEX_GROUP_RE = re.compile(r"[0-9A-Fa-f]{1,4}")
_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_PORT_RE = re.compile(r"[1-9][0-9]{0,4}")
_PICTURE_RE = re.compile(r"(https?)://([^/?]*)([^?]*)(?:\?(.*))?")
_BRACKET_RE = re.compile(r"\[([0-9A-Fa-f:.]+)\](?::(.*))?")


def _parse_ipv4(text: str) -> int | None:
    """Strikt dezimal a.b.c.d (kein fuehrendes Null, je <= 255)."""
    if not _V4_RE.fullmatch(text):
        return None
    octets = [int(x) for x in text.split(".")]
    if any(o > 255 for o in octets):
        return None
    return octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]


def _hex_groups(text: str) -> list[int] | None:
    if text == "":
        return []
    out = []
    for g in text.split(":"):
        if not _HEX_GROUP_RE.fullmatch(g):
            return None
        out.append(int(g, 16))
    return out


def _parse_ipv6(text: str) -> int | None:
    """Eigener IPv6-Parser (unabhaengig von der Python-Version): '::' hoechstens einmal, IPv4-Endstueck strikt."""
    if not text:
        return None
    tail: list[int] = []
    if "." in text:
        idx = text.rfind(":")
        if idx < 0:
            return None
        v4 = _parse_ipv4(text[idx + 1 :])
        if v4 is None:
            return None
        tail = [v4 >> 16, v4 & 0xFFFF]
        text = text[: idx + 1]
        if not text.endswith("::"):
            text = text[:-1]
    parts = text.split("::")
    if len(parts) > 2:
        return None
    if len(parts) == 2:
        left, right = _hex_groups(parts[0]), _hex_groups(parts[1])
        if left is None or right is None:
            return None
        right += tail
        if len(left) + len(right) > 7:
            return None
        groups = left + [0] * (8 - len(left) - len(right)) + right
    else:
        head = _hex_groups(parts[0])
        if head is None:
            return None
        groups = head + tail
        if len(groups) != 8:
            return None
    value = 0
    for g in groups:
        value = value << 16 | g
    return value


def _in_table(value: int, width: int, table: tuple[tuple[int, int], ...]) -> bool:
    return any(value >> (width - bits) == net >> (width - bits) for net, bits in table)


BLOCKED_V4 = _v4_table((
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
))  # fmt: skip
BLOCKED_V6 = _v6_table((
    "::/128", "::1/128", "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001::/32", "2001:10::/28", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10",
    "ff00::/8", "::ffff:0:0:0/96",
))  # fmt: skip

_PCT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_BAD_PCT = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _pct_decode_once(text: str) -> str | None:
    """Genau einmal dekodieren; ungueltige %-Folge, ungueltiges UTF-8, NUL/Steuerzeichen -> None."""
    if _BAD_PCT.search(text):
        return None
    try:
        out = _PCT_RUN.sub(lambda m: bytes.fromhex(m.group(0).replace("%", "")).decode("utf-8"), text)
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in out):
        return None
    return out


def _norm_name(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(" ", "")


def picture_ok(url: Any) -> bool:
    """Strenge Pruefung der Bild-URL (PROTOCOL.md 5.2a), ohne DNS, ohne ipaddress/urllib."""
    if not isinstance(url, str) or not 1 <= len(url) <= PICTURE_MAX:
        return False
    if any(not 0x21 <= ord(c) <= 0x7E or c == "\\" for c in url) or "#" in url:
        return False
    m = _PICTURE_RE.fullmatch(url)
    if not m:
        return False
    _scheme, auth, path, query = m.groups()
    if not auth or "@" in auth:
        return False
    if auth.startswith("["):
        mm = _BRACKET_RE.fullmatch(auth)
        if not mm:
            return False
        host_s, port_s = mm.group(1), mm.group(2)
        ip6 = _parse_ipv6(host_s)
        if ip6 is None or _in_table(ip6, 128, BLOCKED_V6):
            return False
    else:
        if "[" in auth or "]" in auth:
            return False
        host_s, sep, port_s = auth.partition(":")
        if not sep:
            port_s = None  # type: ignore[assignment]
        host = host_s.lower()
        if not host or not re.fullmatch(r"[a-z0-9.-]+", host):
            return False
        if _V4_RE.fullmatch(host):
            ip4 = _parse_ipv4(host)
            if ip4 is None or _in_table(ip4, 32, BLOCKED_V4):
                return False
        else:
            last = host.rsplit(".", 1)[-1]
            if last.isdigit() or last.startswith("0x"):
                return False
            if host == "localhost" or host.endswith(BLOCKED_SUFFIXES) or "." not in host:
                return False
            if len(host) > 253 or not all(_LABEL_RE.fullmatch(label) for label in host.split(".")):
                return False
    if port_s is not None and (not _PORT_RE.fullmatch(port_s) or int(port_s) > 65535):
        return False
    dpath = _pct_decode_once(path)
    if dpath is None:
        return False
    for seg in dpath.lower().split("/"):
        if seg in BLOCKED_PATH_SEGMENTS or seg.endswith(BLOCKED_EXTENSIONS):
            return False
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


# ------------------------------------------------- Nutzlast
KNOWN_FIELDS: dict[str, frozenset[str]] = {
    "state": frozenset({"v", "type", "rev", "status", "media", "picture"}),
    "heartbeat": frozenset({"v", "type", "app_version", "platform", "state_rev", "ws", "sub", "playlist"}),
    "event": frozenset({"v", "type", "name", "reason", "error", "media"}),
    "unpair": frozenset({"v", "type"}),
    "media": frozenset({"kind", "title", "channel", "series", "season", "episode", "duration_ms", "position_ms"}),
    "sub": frozenset({"expires", "connections_active", "connections_max"}),
    "playlist": frozenset({"updated", "live", "movies", "series", "error"}),
}


def strip_unknown(o: dict[str, Any]) -> dict[str, Any]:
    """Nach erfolgreicher Pruefung unbekannte Felder in allen Objekten verwerfen.

    Unbekannter Typ oder unbekanntes Ereignis: komplett verwerfen ({})."""
    t = o.get("type")
    if t not in ("state", "heartbeat", "event", "unpair"):
        return {}
    if t == "event" and o.get("name") not in EVENTS:
        return {}
    out = {k: o[k] for k in o if k in KNOWN_FIELDS[t]}
    for key in ("media", "sub", "playlist"):
        if isinstance(out.get(key), dict):
            out[key] = {k: out[key][k] for k in out[key] if k in KNOWN_FIELDS[key]}
    return out


def validate_media(m: Any) -> str | None:
    if not isinstance(m, dict):
        return "media_not_object"
    if m.get("kind") not in KINDS:
        return "media_kind"
    for key, lo, hi in (("title", 1, 120), ("channel", 1, 80), ("series", 1, 120)):
        if key in m and not is_text(m[key], lo, hi):
            return "media_" + key
    for key, lo, hi in (
        ("season", 0, 999),
        ("episode", 0, 9999),
        ("duration_ms", 0, MAX_MS),
        ("position_ms", 0, MAX_MS),
    ):
        if key in m and not is_int(m[key], lo, hi):
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


def validate_payload(o: Any) -> str | None:
    """None = gueltig, sonst kurzer Grundcode (wie reference.py)."""
    if not isinstance(o, dict):
        return "not_object"
    if not is_int(o.get("v"), 1, 1000):
        return "v"
    if o["v"] != 1:
        return "unsupported_version"
    t = o.get("type")
    if t == "state":
        if o.get("status") not in STATUSES:
            return "status"
        if not is_int(o.get("rev"), 0, MAX_SEQ):
            return "rev"
        if "media" in o:
            if o["status"] not in ("buffering", "playing", "paused"):
                return "media_not_allowed_in_status"
            if r := validate_media(o["media"]):
                return r
        if "picture" in o:
            if "media" not in o:
                return "picture_without_media"
            if not picture_ok(o["picture"]):
                return "picture"
        return None
    if t == "heartbeat":
        if not valid_app_version(o.get("app_version")):
            return "app_version"
        if o.get("platform") not in PLATFORMS:
            return "platform"
        if not is_int(o.get("state_rev"), 0, MAX_SEQ):
            return "state_rev"
        if "ws" in o and not isinstance(o["ws"], bool):
            return "ws"
        if "sub" in o:
            s = o["sub"]
            if not isinstance(s, dict):
                return "sub"
            if "expires" in s and s["expires"] is not None and parse_date(s["expires"]) is None:
                return "sub_expires"
            for key in ("connections_active", "connections_max"):
                if key in s and not is_int(s[key], 0, 99):
                    return "sub_" + key
        if "playlist" in o:
            pl = o["playlist"]
            if not isinstance(pl, dict):
                return "playlist"
            if "updated" in pl and pl["updated"] is not None and parse_utc_datetime(pl["updated"]) is None:
                return "playlist_updated"
            for key in ("live", "movies", "series"):
                if key in pl and not is_int(pl[key], 0, 999999):
                    return "playlist_" + key
            if "error" in pl and pl["error"] not in PLAYLIST_ERRORS:
                return "playlist_error"
        return None
    if t == "event":
        name = o.get("name")
        if not isinstance(name, str) or not EVENT_NAME_RE.fullmatch(name):
            return "name"
        if name not in EVENTS:
            return None
        if "reason" in o and (name != "playback_stopped" or o["reason"] not in STOP_REASONS):
            return "reason"
        if name == "playlist_failed" and (o.get("error") not in PLAYLIST_ERRORS or o["error"] == "none"):
            return "error"
        if name != "playlist_failed" and "error" in o:
            return "error"
        if "media" in o:
            return validate_media(o["media"])
        return None
    return None  # unpair und unbekannter Typ: annehmen


def is_known_type(o: dict[str, Any]) -> bool:
    return o.get("type") in KNOWN_TYPES


def is_ignored(o: dict[str, Any]) -> bool:
    """Unbekannter Typ oder unbekanntes Ereignis -> Antwort mit ignored:true."""
    return not is_known_type(o) or (o.get("type") == "event" and o.get("name") not in EVENTS)
