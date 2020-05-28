__version__ = '0.1.0'

import time
import typing
from base64 import b64decode, b64encode
from os import getcwd, listdir
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import binascii

class SWT:
    # Supported algorithm constants
    ALGORITHM_RSA_SHA256  = 'RSASHA256'
    ALGORITHM_HMAC_SHA256 = 'HMACSHA256'

    # Internals to override Selected algorithm
    default_ttl = 3600

    # Standard claim names
    iss_claim = 'Issuer'
    exp_claim = 'ExpiresOn'
    aud_claim = 'Audience'

    # Extra claim names modeled after JWT claim names
    sub_claim = 'sub'
    iat_claim = 'iat'
    sid_claim = 'sid'

    def __init__(self, token_str: typing.Optional[str] = None):
        # Internal data
        self._token_str = None
        self._token_claims = {}
        self._ttl = SWT.default_ttl

        self._token_signature = None

        # If called with a token, set and verify
        if token_str is not None:
            self.token(token_str)

    @property
    def is_valid(self):
        return self.is_signed and not self.is_expired

    @property
    def is_expired(self):
        if self._token_signature is None:
            return True
        return int(self._token_claims.get(self.__class__.exp_claim, 0)) < int(time.time())

    @property
    def issuer(self):
        return self._token_claims.get(self.__class__.iss_claim, None)

    @issuer.setter
    def issuer(self, value):
        self._token_claims[self.__class__.iss_claim] = value

    @property
    def ttl(self):
        return self._ttl

    @ttl.setter
    def ttl(self, value):
        if value < 1:
            raise ValueError("A TTL less than 1 makes no sense")
        self._ttl = value
        return self._ttl

    def __bool__(self):
        return self.is_valid

    def __str__(self):
        return self._token_str

    def get_public_key(self):
        raise NotImplementedError("Please implement your own get_public_key() method")

    def get_private_key(self):
        raise NotImplementedError("Please implement your own get_public_key() method")

    def set_claim(self, claim, value):
        self._token_claims[claim] = value

    def get_claim(self, claim):
        return self._token_claims[claim]

    def token(self, token: str):
        # Allow caller to take http header and parse it directly to us
        self._token_str = str(token).replace('Bearer ', '')

        # Split token into claims and signature
        try:
            self._token_claims_str, self._token_signature_str = self._token_str.rsplit(f'&{self.algorithm}=')
        except ValueError:
            return

        # Decode signature to internal format
        try:
            self._token_signature = b64decode(unquote(self._token_signature_str))
        except binascii.Error:
            self._token_signature = None

        # Parse claims string into key value
        self._token_claims = dict(parse_qsl(self._token_claims_str))

    @property
    def algorithm(self):
        raise NotImplementedError("Please implement algorithm specific algorithm @property method")

    def sign(self):
        raise NotImplementedError("Please implement algorithm specific sign() method")

    @property
    def is_signed(self):
        raise NotImplementedError("Please implement algorithm specific is_signed @property method")

class SWT_RSA_SHA256(SWT):
    @property
    def algorithm(self):
        return SWT.ALGORITHM_RSA_SHA256

    def sign(self):
        self._token_claims[self.__class__.exp_claim] = int(time.time()) + self._ttl
        self._token_claims_str = urlencode(self._token_claims)
        key = RSA.importKey(self.get_private_key())
        digest = SHA256.new(self._token_claims_str.encode('utf8'))
        signer = PKCS1_v1_5.new(key)
        self._token_signature = signer.sign(digest)
        self._token_signature_str = quote(b64encode(self._token_signature))
        self._token_str = self._token_claims_str + f'&{self.algorithm}=' + self._token_signature_str

    @property
    def is_signed(self):
        # Give on beforehand if we don't have a signature
        if not self._token_signature:
            return False

        # Validate signature
        key = RSA.importKey(self.get_public_key())
        signature = PKCS1_v1_5.new(key)
        digest = SHA256.new(self._token_claims_str.encode('utf8'))
        return signature.verify(digest, self._token_signature)


class SWT_HMAC_SHA256(SWT):
    algorithm = SWT.ALGORITHM_HMAC_SHA256

    def sign(self):
        raise NotImplementedError()

    @property
    def is_signed(self):
        raise NotImplementedError()
