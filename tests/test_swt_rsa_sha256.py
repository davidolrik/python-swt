from swt import SWT_RSA_SHA256
from pathlib import Path
import pytest
import time


class MySWT(SWT_RSA_SHA256):
    # Override standard claim names
    exp_claim = "exp"
    iss_claim = "iss"

    # Implement key locators
    def get_public_key(self):
        return Path(f"tests/keys/{self.issuer}-public.pem").read_text()

    def get_private_key(self):
        return Path(f"tests/keys/{self.issuer}-private.pem").read_text()


# Allow generated token to be saved between tests
def pytest_configure():
    pytest.test_token_str = None


def test_sign_swt_rsa_sha256_without_key_locators():
    token = SWT_RSA_SHA256()
    token.issuer = "test-issuer"
    token.ttl = 360
    token.set_claim("sub", 42)
    token.set_claim("foo", "bar")
    with pytest.raises(NotImplementedError):
        token.sign()


def test_sign_swt_rsa_sha256():
    token = MySWT()
    token.issuer = "test-issuer"
    token.ttl = 360
    token.set_claim("sub", 42)
    token.set_claim("foo", "bar")
    test_token_str = token.sign()
    pytest.test_token_str = str(token)

    assert token.is_expired == False, "Token is not expired"
    assert token.is_signed, "Token is signed"
    assert token.is_valid, "Token is valid (both signed and not expired)"
    assert type(pytest.test_token_str) is str, f"We have a token as a string {token}"
    assert (
        str(pytest.test_token_str) == test_token_str
    ), "sign() returns token as string"
    assert token.ttl == 360, "TTL for token is set to 360"
    with pytest.raises(ValueError):
        token.ttl = 0


def test_expired_swt_rsa_sha256():
    token = MySWT()
    token.issuer = "test-issuer"
    token.ttl = 1
    token.set_claim("sub", 42)
    token.set_claim("foo", "bar")
    token_str = token.sign()
    time.sleep(2)

    assert token.is_expired == True, "Token is expired"
    assert token.is_signed, "Token is signed"
    assert token.is_valid == False, "Token is invalid (signed but expired)"
    assert type(token.token_str) == str, "Token serialization is a string (from object)"
    assert type(token_str) == str, "Token serialization is a string (from sign method)"


def test_valid_swt_from_string_without_key_locators():
    token = SWT_RSA_SHA256(pytest.test_token_str)
    with pytest.raises(NotImplementedError):
        assert token.is_valid == False, "Token is invalid"


def test_valid_swt_from_string():
    token = MySWT(pytest.test_token_str)

    assert token.is_expired == False, "Token is not expired"
    assert token.is_signed, "Token is signed"
    assert token.is_valid, "Token is valid (both signed and not expired)"
    assert bool(token) == True, "Token with valid signature has a boolean value of True"
    assert token.get_claim("foo") == "bar", "Token has claim foo with value of bar"
    assert token.token_str == str(token), "Token has string value"


def test_swt_broken_signature():
    # Remove one character from token signature
    broken_token_str = (
        pytest.test_token_str[0 : len(pytest.test_token_str) - 5]
        + pytest.test_token_str[-4:]
    )

    token = MySWT()
    token.token_str = broken_token_str
    assert token.is_signed == False, "Token has broken signed (we broke it on purpose)"
    assert (
        bool(token) == False
    ), "Token with invalid signature has a boolean value of False"
    assert token.is_expired == True, "Token is expired, even if date is ok"
    assert token.is_valid == False, "Token is invalid"


def test_swt_no_signature():
    # Remove signature from valid token, and create new invalid token
    token = MySWT()
    broken_token_str, _ = pytest.test_token_str.rsplit(f"&{token.algorithm}=")
    token.token_str = broken_token_str

    assert token.is_signed == False, "Token has broken signed (we broke it on purpose)"
    assert (
        bool(token) == False
    ), "Token with invalid signature has a boolean value of False"
    assert token.is_expired == True, "Token is expired, even if date is ok"
    assert token.is_valid == False, "Token is invalid"
