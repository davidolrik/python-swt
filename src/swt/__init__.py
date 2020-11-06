import binascii
import time
import typing
from base64 import b64decode, b64encode
from typing import Dict, Optional
from urllib.parse import parse_qsl, quote, unquote, urlencode

import poetry_version
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

__version__ = poetry_version.extract(source_file=__file__)


class SWT:
    """Simple Web Token base class

    To use this library, you must choose which algorithm you want to use, and
    extend the algorithm specific sub class. Currently only RSA SHA256 is implemented.
    """

    # Supported algorithm constants
    ALGORITHM_RSA_SHA256: str = "RSASHA256"
    ALGORITHM_HMAC_SHA256: str = "HMACSHA256"

    # Internals to override Selected algorithm
    default_ttl: int = 3600

    # Standard claim names
    iss_claim: str = "Issuer"
    exp_claim: str = "ExpiresOn"
    aud_claim: str = "Audience"

    # Extra claim names modeled after JWT claim names
    sub_claim: str = "sub"
    iat_claim: str = "iat"
    sid_claim: str = "sid"

    def __init__(self, token_str: typing.Optional[str] = None):
        """Create new SWT"""
        # Internal data
        self._token_str = None
        self._token_claims: Dict[str, str] = {}
        self._ttl = SWT.default_ttl

        self._token_signature = None

        # If called with a token, set and verify
        if token_str is not None:
            self.token_str = token_str

    @property
    def is_valid(self):
        """Check if the SWT is both sign and not expired

        Returns:
            bool: token validity
        """
        return self.is_signed and not self.is_expired

    @property
    def is_expired(self):
        """Check if the SWT is expired

        Returns:
            bool: is expired
        """
        if not self.is_signed:
            return True
        return int(self._token_claims.get(self.__class__.exp_claim, 0)) < int(
            time.time()
        )

    @property
    def issuer(self):
        """Issuer of token"""
        return self._token_claims.get(self.__class__.iss_claim, None)

    @issuer.setter
    def issuer(self, value):
        self._token_claims[self.__class__.iss_claim] = value

    @property
    def ttl(self):
        """Time to live in seconds"""
        return self._ttl

    @ttl.setter
    def ttl(self, value):
        if value < 1:
            raise ValueError("A TTL less than 1 makes no sense")
        self._ttl = value
        return self._ttl

    def __bool__(self):
        """SWT in bool context will return is_valid"""
        return self.is_valid

    def __str__(self):
        return self._token_str

    def get_public_key(self) -> str:
        """Implement this in your own subclass to find and load the public key by issuer"""
        raise NotImplementedError("Please implement your own get_public_key() method")

    def get_private_key(self) -> str:
        """Implement this in your own subclass to find and load the private key by issuer"""
        raise NotImplementedError("Please implement your own get_public_key() method")

    def set_claim(self, claim: str, value: str):
        self._token_claims[claim] = value

    def get_claim(self, claim: str) -> str:
        if claim not in self._token_claims:
            raise KeyError(f"claim {claim} not found in token")
        return self._token_claims[claim]

    @property
    def token_str(self) -> Optional[str]:
        """Token as serialized string"""
        return self._token_str

    @token_str.setter
    def token_str(self, token: str):
        """Token as string"""

        # Allow caller to take http header and parse it directly to us
        self._token_str = str(token).replace("Bearer ", "")

        # Split token into claims and signature
        try:
            self._token_claims_str, self._token_signature_str = self._token_str.rsplit(
                f"&{self.algorithm}="
            )
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
        """The algorithm used for the SWT"""
        raise NotImplementedError(
            "Please implement algorithm specific algorithm @property method"
        )

    def sign(self) -> str:
        """Algorithm specific sign() method

        Returns:
            str: signed token
        """
        raise NotImplementedError("Please implement algorithm specific sign() method")

    @property
    def is_signed(self):
        """Algorithm specific is_signed() property

        Returns:
            bool: signed status
        """
        raise NotImplementedError(
            "Please implement algorithm specific is_signed @property method"
        )


class SWT_RSA_SHA256(SWT):
    """SWT using RSA and SHA256

    Extend this class and implement the key locater methods
    """

    @property
    def algorithm(self):
        return SWT.ALGORITHM_RSA_SHA256

    def sign(self) -> str:
        self._token_claims[self.__class__.exp_claim] = str(int(time.time()) + self._ttl)
        self._token_claims_str = urlencode(self._token_claims)
        key = RSA.importKey(self.get_private_key())
        digest = SHA256.new(self._token_claims_str.encode("utf8"))
        signer = PKCS1_v1_5.new(key)
        self._token_signature = signer.sign(digest)
        self._token_signature_str = quote(b64encode(self._token_signature))
        self._token_str = (
            f"{self._token_claims_str}&{self.algorithm}={self._token_signature_str}"
        )

        return self._token_str

    @property
    def is_signed(self) -> bool:
        # Give on beforehand if we don't have a signature
        if not self._token_signature:
            return False

        # Validate signature
        key = RSA.importKey(self.get_public_key())
        signature = PKCS1_v1_5.new(key)
        digest = SHA256.new(self._token_claims_str.encode("utf8"))
        return signature.verify(digest, self._token_signature)


class SWT_HMAC_SHA256(SWT):
    """Not yet implemented"""

    @property
    def algorithm(self):
        return SWT.ALGORITHM_HMAC_SHA256  # pragma: no cover

    def sign(self):
        raise NotImplementedError()

    @property
    def is_signed(self):
        raise NotImplementedError()
