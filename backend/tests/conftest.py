import os
import sys
import tempfile

# Configure the app BEFORE it is imported.
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["AUTH_FAILURE_DELAY"] = "0"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import base64  # noqa: E402
import itertools  # noqa: E402
import secrets  # noqa: E402

import pyotp  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

_counter = itertools.count()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def make_spki(bits: int = 2048) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return b64(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


# Generating RSA keys is slow; reuse one pair for every test user.
SHARED_SPKI = make_spki()


def registration_payload(username: str, auth_secret: str | None = None) -> dict:
    return {
        "username": username,
        "auth_secret": auth_secret or secrets.token_urlsafe(32),
        "enc_public_key": SHARED_SPKI,
        "sig_public_key": SHARED_SPKI,
        "wrapped_private_keys": {"iv": b64(b"\x01" * 12), "ct": b64(b"\x02" * 200)},
    }


@pytest.fixture(scope="session")
def client():
    with TestClient(main.app) as c:
        yield c


class Account:
    def __init__(self, client, username, auth_secret, totp_secret):
        self.client, self.username = client, username
        self.auth_secret, self.totp_secret = auth_secret, totp_secret
        self.token = None

    def code(self, offset: int = 0) -> str:
        import time

        return pyotp.TOTP(self.totp_secret).at(time.time() + offset * 30)

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}


def create_account(client, activate: bool = True, login: bool = True) -> Account:
    username = f"user{next(_counter)}"
    payload = registration_payload(username)
    r = client.post("/register", json=payload)
    assert r.status_code == 201, r.text
    acc = Account(client, username, payload["auth_secret"], r.json()["secret"])
    if activate:
        r = client.post(
            "/2fa/enable",
            json={"username": username, "auth_secret": acc.auth_secret, "code": acc.code()},
        )
        assert r.status_code == 200, r.text
    if activate and login:
        r = client.post("/login", json={"username": username, "auth_secret": acc.auth_secret})
        assert r.status_code == 200, r.text
        pre = r.json()["pre_2fa_token"]
        # the code used for enabling 2FA is consumed: use the next time step
        r = client.post(
            "/login/verify-2fa",
            json={"code": acc.code(+1)},
            headers={"Authorization": f"Bearer {pre}"},
        )
        assert r.status_code == 200, r.text
        acc.token = r.json()["access_token"]
    return acc


@pytest.fixture()
def account(client):
    return create_account(client)
