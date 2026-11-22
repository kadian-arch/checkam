"""Two-step sign-in for the administrator: a password alone never opens the account."""
import base64
import time

from fastapi.testclient import TestClient

from checkam import security, store, totp
from checkam.app import app

client = TestClient(app)
EMAIL, PASSWORD = "owner@example.org", "an-owner-password-123"


def fresh_admin():
    store.add_analyst(EMAIL, PASSWORD, "Owner", "CheckAm", role="admin")
    store.twofa_clear(EMAIL)
    security._hits.clear()


def login():
    security._hits.clear()
    return client.post("/auth/login", json={"email": EMAIL, "password": PASSWORD})


def test_the_code_generator_matches_the_rfc_6238_test_vectors():
    # RFC 6238 appendix B, SHA-1, shared secret "12345678901234567890": 6-digit codes are the last 6 digits of the 8-digit ones
    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    for at, expected in ((59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (1234567890, "005924"), (2000000000, "279037")):
        assert totp.code_at(secret, at) == expected


def test_a_code_works_once_and_only_in_its_window():
    secret = totp.new_secret()
    now = 1_700_000_000.0
    code = totp.code_at(secret, now)
    step = totp.verify(secret, code, 0, now)
    assert step == int(now // 30)
    assert totp.verify(secret, code, step, now) is None, "the same code cannot be used twice"
    assert totp.verify(secret, code, 0, now + 300) is None, "a code from five minutes ago is refused"
    assert totp.verify(secret, "12345", 0, now) is None and totp.verify(secret, "abcdef", 0, now) is None


def test_a_challenge_is_for_one_purpose_and_expires():
    c = totp.challenge("a@b.co", "code")
    assert totp.read_challenge(c, "code") == "a@b.co"
    assert totp.read_challenge(c, "setup") is None
    assert totp.read_challenge(totp.challenge("a@b.co", "code", ttl=-1), "code") is None
    assert totp.read_challenge(c[:-3] + "xyz", "code") is None
    assert totp.read_challenge("garbage", "code") is None


def test_the_password_alone_never_gives_an_administrator_session():
    fresh_admin()
    r = login().json()
    assert r["step"] == "setup" and "token" not in r
    # the challenge is not a session: admin routes refuse it
    assert client.get("/admin/overview", headers={"Authorization": "Bearer " + r["challenge"]}).status_code == 401


def test_set_up_then_every_sign_in_needs_a_code_and_recovery_codes_work_once():
    fresh_admin()
    challenge = login().json()["challenge"]
    start = client.post("/auth/2fa/start", json={"challenge": challenge}).json()
    secret = start["secret"]
    assert start["uri"].startswith("otpauth://totp/CheckAm:") and secret in start["uri"]
    assert client.post("/auth/2fa/setup", json={"challenge": challenge, "code": "000000"}).status_code == 401
    done = client.post("/auth/2fa/setup", json={"challenge": challenge, "code": totp.code_at(secret)})
    assert done.status_code == 200
    body = done.json()
    assert body["analyst"]["role"] == "admin" and len(body["recovery_codes"]) == 8
    assert client.get("/admin/overview", headers={"Authorization": "Bearer " + body["token"]}).status_code == 200
    assert "secret_enc" in store.twofa_get(EMAIL) and secret not in store.twofa_get(EMAIL)["secret_enc"], "the secret is stored encrypted"

    # next sign-in: password, then a code
    nxt = login().json()
    assert nxt["step"] == "code"
    assert client.post("/auth/2fa/start", json={"challenge": nxt["challenge"]}).status_code == 401, "set-up cannot be reopened from a code challenge"
    # the code used at set-up is spent; a later one in the window works, an old one does not
    spent = totp.code_at(secret)
    assert client.post("/auth/2fa/verify", json={"challenge": nxt["challenge"], "code": spent}).status_code == 401
    later = totp.code_at(secret, time.time() + 30)
    ok = client.post("/auth/2fa/verify", json={"challenge": nxt["challenge"], "code": later})
    assert ok.status_code == 200 and "token" in ok.json()
    assert client.post("/auth/2fa/verify", json={"challenge": nxt["challenge"], "code": later}).status_code == 401, "no replay"

    # a recovery code signs in once
    rc = body["recovery_codes"][0]
    again = login().json()
    assert client.post("/auth/2fa/verify", json={"challenge": again["challenge"], "code": rc}).status_code == 200
    again = login().json()
    assert client.post("/auth/2fa/verify", json={"challenge": again["challenge"], "code": rc}).status_code == 401
    assert [a["action"] for a in store.admin_audit(10)].count("recovery_code_used") >= 1


def test_guessing_codes_is_throttled():
    fresh_admin()
    challenge = login().json()["challenge"]
    secret = client.post("/auth/2fa/start", json={"challenge": challenge}).json()["secret"]
    client.post("/auth/2fa/setup", json={"challenge": challenge, "code": totp.code_at(secret)})
    code_challenge = login().json()["challenge"]
    security._hits.clear()
    codes = [client.post("/auth/2fa/verify", json={"challenge": code_challenge, "code": "000000"}).status_code for _ in range(9)]
    assert codes[0] == 401 and 429 in codes, codes
    security._hits.clear()


def test_analysts_sign_in_exactly_as_before():
    store.add_analyst("plain.analyst@example.org", "plain-analyst-password", "Plain", "Org", role="analyst")
    security._hits.clear()
    r = client.post("/auth/login", json={"email": "plain.analyst@example.org", "password": "plain-analyst-password"}).json()
    assert "token" in r and r["analyst"]["role"] == "analyst" and "step" not in r


def test_the_host_can_clear_a_lost_phone():
    fresh_admin()
    challenge = login().json()["challenge"]
    secret = client.post("/auth/2fa/start", json={"challenge": challenge}).json()["secret"]
    client.post("/auth/2fa/setup", json={"challenge": challenge, "code": totp.code_at(secret)})
    assert login().json()["step"] == "code"
    store.twofa_clear(EMAIL)  # what CHECKAM_ADMIN_RESET_2FA does at start-up
    assert login().json()["step"] == "setup"
