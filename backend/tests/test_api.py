import secrets

import pytest

from .conftest import SHARED_SPKI, b64, create_account, make_spki, registration_payload


def send_payload(recipients, ciphertext=None):
    return {
        "recipients": [{"username": u, "wrapped_key": b64(b"k" * 256 + b"0" * 128)} for u in recipients],
        "ciphertext": ciphertext or b64(secrets.token_bytes(64)),
        "iv": b64(b"\x00" * 12),
    }


# ---------- registration / validation ----------


@pytest.mark.parametrize(
    "mutation",
    [
        {"username": "ab"},  # too short
        {"username": "Bad Name!"},  # illegal characters
        {"username": "x" * 33},  # too long
        {"auth_secret": "short"},
        {"auth_secret": "!" * 43},
        {"enc_public_key": "not base64!!"},
        {"enc_public_key": b64(b"garbage")},  # base64 but not a key
        {"sig_public_key": make_spki(1024)},  # RSA too small
        {"wrapped_private_keys": {"iv": "AAAA", "ct": "AAAA"}},
        {"unexpected": "field"},
    ],
)
def test_register_rejects_bad_input(client, mutation):
    payload = registration_payload(f"valid{secrets.token_hex(4)}")
    payload.update(mutation)
    assert client.post("/register", json=payload).status_code == 422


def test_register_duplicate_username(client):
    payload = registration_payload("dupuser")
    assert client.post("/register", json=payload).status_code == 201
    assert client.post("/register", json=payload).status_code == 409


def test_username_is_case_insensitive(client):
    assert client.post("/register", json=registration_payload("MixedCase")).status_code == 201
    assert client.post("/register", json=registration_payload("mixedcase")).status_code == 409


# ---------- login / 2FA ----------


def test_full_login_flow_and_keys(client, account):
    r = client.get("/keys/me", headers=account.headers)
    assert r.status_code == 200
    assert r.json()["enc_public_key"] == SHARED_SPKI


def test_login_requires_activation(client):
    acc = create_account(client, activate=False)
    r = client.post("/login", json={"username": acc.username, "auth_secret": acc.auth_secret})
    assert r.status_code == 403


def test_failed_logins_are_indistinguishable(client, account):
    wrong = secrets.token_urlsafe(32)
    r_unknown = client.post("/login", json={"username": "nosuchuser", "auth_secret": wrong})
    r_wrong = client.post("/login", json={"username": account.username, "auth_secret": wrong})
    assert r_unknown.status_code == r_wrong.status_code == 401
    assert r_unknown.json() == r_wrong.json()


def test_account_lockout_hides_state(client):
    acc = create_account(client)
    bad = {"username": acc.username, "auth_secret": secrets.token_urlsafe(32)}
    good = {"username": acc.username, "auth_secret": acc.auth_secret}
    for _ in range(5):
        assert client.post("/login", json=bad).status_code == 401
    locked = client.post("/login", json=good)
    assert locked.status_code == 401  # even the right secret is refused...
    assert locked.json() == client.post("/login", json=bad).json()  # ...with the same message


def test_totp_replay_is_rejected(client):
    acc = create_account(client, login=False)
    r = client.post("/login", json={"username": acc.username, "auth_secret": acc.auth_secret})
    pre = {"Authorization": f"Bearer {r.json()['pre_2fa_token']}"}
    code = acc.code(+1)  # valid, and newer than the code used to enable 2FA
    assert client.post("/login/verify-2fa", json={"code": code}, headers=pre).status_code == 200
    # same code again (a second login attempt inside the same window)
    assert client.post("/login/verify-2fa", json={"code": code}, headers=pre).status_code == 401


def test_2fa_lockout(client):
    acc = create_account(client, login=False)
    r = client.post("/login", json={"username": acc.username, "auth_secret": acc.auth_secret})
    pre = {"Authorization": f"Bearer {r.json()['pre_2fa_token']}"}
    for _ in range(5):
        assert client.post("/login/verify-2fa", json={"code": "000000"}, headers=pre).status_code == 401
    r = client.post("/login/verify-2fa", json={"code": acc.code(+1)}, headers=pre)  # a VALID code is refused while locked
    assert r.status_code == 429


def test_malformed_totp_code_rejected(client, account):
    r = client.post("/login", json={"username": account.username, "auth_secret": account.auth_secret})
    pre = {"Authorization": f"Bearer {r.json()['pre_2fa_token']}"}
    for bad in ["12345", "abcdef", "1234567", ""]:
        assert client.post("/login/verify-2fa", json={"code": bad}, headers=pre).status_code == 422


# ---------- authorisation of every protected endpoint ----------

PROTECTED = [
    ("get", "/keys/me"),
    ("get", "/users/someone/public-keys"),
    ("post", "/messages/send"),
    ("get", "/messages"),
    ("patch", "/messages/1/read"),
    ("delete", "/messages/1"),
    ("get", "/account/activity"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_endpoints_require_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401
    r = getattr(client, method)(path, headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED)
def test_pre_2fa_token_is_not_an_access_token(client, method, path):
    acc = create_account(client)
    r = client.post("/login", json={"username": acc.username, "auth_secret": acc.auth_secret})
    pre = {"Authorization": f"Bearer {r.json()['pre_2fa_token']}"}
    assert getattr(client, method)(path, headers=pre).status_code == 401


def test_access_token_cannot_be_used_for_2fa_step(client, account):
    r = client.post("/login/verify-2fa", json={"code": "123456"}, headers=account.headers)
    assert r.status_code == 401


# ---------- messages ----------


def test_multi_recipient_message_lifecycle(client):
    alice, bob, carol, mallory = (create_account(client) for _ in range(4))
    r = client.post(
        "/messages/send", json=send_payload([bob.username, carol.username]), headers=alice.headers
    )
    assert r.status_code == 201
    mid = r.json()["id"]

    bob_inbox = client.get("/messages", headers=bob.headers).json()
    carol_inbox = client.get("/messages", headers=carol.headers).json()
    assert [m["id"] for m in bob_inbox] == [mid] == [m["id"] for m in carol_inbox]
    assert bob_inbox[0]["sender_username"] == alice.username
    assert bob_inbox[0]["recipients"] == sorted([bob.username, carol.username])
    assert client.get("/messages", headers=mallory.headers).json() == []
    assert client.get("/messages", headers=alice.headers).json() == []  # sender is not a recipient

    # read flag is per recipient
    assert client.patch(f"/messages/{mid}/read", headers=bob.headers).status_code == 200
    assert client.get("/messages", headers=bob.headers).json()[0]["is_read"] is True
    assert client.get("/messages", headers=carol.headers).json()[0]["is_read"] is False

    # outsiders can neither read-mark nor delete (same 404 as a missing message)
    assert client.patch(f"/messages/{mid}/read", headers=mallory.headers).status_code == 404
    assert client.delete(f"/messages/{mid}", headers=mallory.headers).status_code == 404
    assert client.delete("/messages/999999", headers=mallory.headers).status_code == 404

    # bob deleting does not affect carol
    assert client.delete(f"/messages/{mid}", headers=bob.headers).status_code == 200
    assert client.get("/messages", headers=bob.headers).json() == []
    assert len(client.get("/messages", headers=carol.headers).json()) == 1
    assert client.delete(f"/messages/{mid}", headers=carol.headers).status_code == 200


def test_send_validation(client):
    alice, bob = create_account(client), create_account(client)
    h = alice.headers
    assert client.post("/messages/send", json=send_payload(["ghostuser"]), headers=h).status_code == 404
    assert client.post("/messages/send", json=send_payload([bob.username, "ghostuser"]), headers=h).status_code == 404
    assert client.post("/messages/send", json=send_payload([]), headers=h).status_code == 422
    assert client.post("/messages/send", json=send_payload([bob.username] * 2), headers=h).status_code == 422
    too_many = [f"user{i:03d}" for i in range(11)]
    assert client.post("/messages/send", json=send_payload(too_many), headers=h).status_code == 422
    bad = send_payload([bob.username])
    bad["ciphertext"] = "<script>alert(1)</script>"
    assert client.post("/messages/send", json=bad, headers=h).status_code == 422
    bad = send_payload([bob.username])
    bad["extra"] = 1
    assert client.post("/messages/send", json=bad, headers=h).status_code == 422


def test_cannot_send_to_unactivated_account(client, account):
    ghost = create_account(client, activate=False)
    r = client.post("/messages/send", json=send_payload([ghost.username]), headers=account.headers)
    assert r.status_code == 404
    assert client.get(f"/users/{ghost.username}/public-keys", headers=account.headers).status_code == 404


def test_public_key_lookup(client):
    alice, bob = create_account(client), create_account(client)
    r = client.get(f"/users/{bob.username}/public-keys", headers=alice.headers)
    assert r.status_code == 200 and r.json()["sig_public_key"] == SHARED_SPKI
    assert client.get("/users/Not Valid!/public-keys", headers=alice.headers).status_code == 422


def test_activity_log_records_logins(client, account):
    client.post("/login", json={"username": account.username, "auth_secret": secrets.token_urlsafe(32)})
    events = [e["event_type"] for e in client.get("/account/activity", headers=account.headers).json()]
    assert "login_success" in events and "login_failed" in events


def test_api_docs_are_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_responses_not_cacheable(client):
    assert client.get("/health").headers["cache-control"] == "no-store"
