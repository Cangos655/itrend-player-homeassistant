"""Reine Protokollfunktionen gegen vectors.json und reference.py."""

from __future__ import annotations

import pytest

from custom_components.itrend_player import protocol as p

import reference as ref


def test_group_matches_vectors(vectors):
    g = vectors["srp_group"]
    assert "%0768x" % p.N == g["N_hex"]
    assert "%064x" % p.srp_k() == g["k_hex"]
    assert p.G == g["g"] == 2
    assert p.NLEN == g["N_bytes"]
    assert p.N == ref.N


def test_primitives(vectors):
    pr = vectors["primitives"]
    tc = pr["hmac_sha256_rfc4231_tc1"]
    assert p.hmac256(bytes.fromhex(tc["key_hex"]), tc["data_utf8"].encode()).hex() == tc["mac_hex"]
    h = pr["hkdf_sha256_rfc5869_tc1"]
    okm = p.hkdf_expand(
        p.hkdf_extract(bytes.fromhex(h["salt_hex"]), bytes.fromhex(h["ikm_hex"])),
        bytes.fromhex(h["info_hex"]), h["length"])
    assert okm.hex() == h["okm_hex"]
    assert p.sha256(b"abc").hex() == pr["sha256_abc_hex"]


def test_encodings(vectors):
    for case in vectors["encodings"]["valid"]:
        assert p.b64u(bytes.fromhex(case["hex"])) == case["b64u"]
        assert p.b64u_dec(case["b64u"]) == bytes.fromhex(case["hex"])
    for bad in vectors["encodings"]["invalid_b64u"]:
        with pytest.raises(ValueError):
            p.b64u_dec(bad)
    # nachgestelltes LF darf nicht durchrutschen
    with pytest.raises(ValueError):
        p.b64u_dec("AAAA\n")


def test_length_prefix(vectors):
    lp = vectors["length_prefix"]
    assert p.lp("ab", "c").hex() == lp["lp_ab_c_hex"]
    assert p.lp("a", "bc").hex() == lp["lp_a_bc_hex"]
    assert p.lp("ab", "c") != p.lp("a", "bc")


def test_pairing_vector(vectors):
    pv = vectors["pairing"]
    i, d = pv["inputs"], pv["derived"]
    salt = bytes.fromhex(i["salt_hex"])
    a, b = int(i["a_hex"], 16), int(i["b_hex"], 16)
    ver = p.srp_verifier(salt, i["code"])
    assert "%064x" % p.srp_x(salt, i["code"]) == d["x_hex"]
    assert "%0768x" % ver == d["verifier_v_hex"]
    big_a = pow(p.G, a, p.N)
    big_b = p.srp_server_public(ver, b)
    assert "%0768x" % big_a == d["A_hex"]
    assert "%0768x" % big_b == d["B_hex"]
    u = p.srp_u(big_a, big_b)
    assert "%064x" % u == d["u_hex"]
    s = p.srp_server_secret(big_a, ver, b, u)
    assert "%0768x" % s == d["S_hex"]
    ctx = p.ctx_bytes(i["name"], i["platform"], i["app_version"])
    assert ctx.hex() == d["ctx_utf8_hex"]
    keys = p.derive_keys(s, big_a, big_b, ctx, i["device_id"], i["webhook_id"])
    assert keys["K_srp"].hex() == d["K_srp_hex"]
    assert keys["transcript_hash"].hex() == d["transcript_hash_hex"]
    assert keys["PRK"].hex() == d["PRK_hex"]
    assert keys["K_proof"].hex() == d["K_proof_hex"]
    assert keys["K_a2h"].hex() == d["K_a2h_hex"]
    assert keys["K_h2a"].hex() == d["K_h2a_hex"]
    m1 = p.proof_m1(keys["K_proof"], big_a, big_b, ctx)
    assert m1.hex() == d["M1_hex"]
    assert p.proof_m2(keys["K_proof"], big_a, big_b, m1, i["device_id"], i["webhook_id"]).hex() \
        == d["M2_hex"]
    assert pv["wrong_code"]["M1_hex"] != d["M1_hex"]


def test_srp_bounds(vectors):
    for case in vectors["srp_bounds"]["cases"]:
        assert p.valid_public(int(case["value_hex"], 16)) is case["valid"], case["name"]
    assert p.valid_public(True) is False


def test_names(vectors):
    for case in vectors["names"]["cases"]:
        assert p.valid_name(case["value"]) is case["valid"], case["name"]
    assert p.valid_name("a\u007f") is False
    assert p.valid_name("\ud800") is False  # einzelnes Surrogat
    assert p.valid_name("ä" * 40) is True
    assert p.valid_name("😀" * 40) is True  # 160 Byte


def test_payload_cases(vectors):
    for case in vectors["payloads"]["cases"]:
        assert p.validate_payload(case["payload"]) == case["expect"], case["name"]


@pytest.mark.parametrize("ver", ["0.3.0\n", "0.3.0 ", "0.3", "1.2.3-"])
def test_app_version_strict(ver):
    assert not p.valid_app_version(ver)


def test_event_name_and_date_strict():
    base = {"v": 1, "type": "event"}
    assert p.validate_payload({**base, "name": "channel_changed\n"}) == "name"
    hb = {"v": 1, "type": "heartbeat", "app_version": "0.3.0", "platform": "tizen", "state_rev": 0}
    assert p.validate_payload({**hb, "sub": {"expires": "٢٠٢٧-٠٣-٣١"}}) == "sub_expires"
    assert p.validate_payload({**hb, "app_version": "0.3.0\n"}) == "app_version"


def test_strict_json():
    for bad in (b'{"a":1,"a":2}', b"NaN", b"[Infinity]", b"\xff", b"{" * 5000 + b"}" * 5000, b""):
        with pytest.raises(ValueError):
            p.loads_strict(bad)
    assert p.loads_strict(b'{"a":[1,2]}') == {"a": [1, 2]}


def test_picture_urls_vectors(vectors):
    cases = vectors["picture_urls"]["cases"]
    assert len(cases) >= 204
    for case in cases:
        assert p.picture_ok(case["url"]) is case["valid"], (case["url"], case.get("why"))
        assert ref.picture_ok(case["url"]) is case["valid"]


def test_strip_unknown_vectors(vectors):
    for case in vectors["strip_unknown"]["cases"]:
        assert p.strip_unknown(case["input"]) == case["expect"], case["name"]


def test_picture_ok_non_strings():
    for bad in (None, 5, b"https://a.example.org/x.jpg", ["https://a.org/x"], "", "https://" + "a" * 600 + ".org/"):
        assert p.picture_ok(bad) is False
    assert p.picture_ok("https://img.example.org/x.jpg\n") is False


def test_ipv6_parser_matches_stdlib_on_samples():
    import ipaddress
    samples = ["::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1::8",
               "::ffff:1.2.3.4", "::1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4",
               "1:2:3:4:5:6:7", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "1::2::3", ":::", "1:::2",
               "12345::", "g::", "::1.2.3", "::01.2.3.4", "::256.1.1.1", "2001:db8::1", "64:ff9b::1.2.3.4",
               "1:2:3:4:5:6:7:8:9", "::1:", "1.2.3.4", "2001:DB8::A"]
    for text in samples:
        try:
            expected = int(ipaddress.IPv6Address(text))
        except ValueError:
            expected = None
        assert p._parse_ipv6(text) == expected, text
