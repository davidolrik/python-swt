Python SWT
==========

To use this module, simply implement and use your own algorithm specific SWT class.

More [1]_ info about *Simple Web Tokens* can be found at
`Microsoft <https://docs.microsoft.com/en-us/previous-versions/azure/azure-services/hh781551(v=azure.100)?redirectedfrom=MSDN>`_
who originated the spec. back in 2009.

.. [1] Although not a lot

Using RSA SHA256
----------------

Create your own token class that extends from ``SWT_RSA_SHA256``, and implement
the key locators you need.

If you only want to verify tokens, then you can skip implementing the
``get_private_key()`` method.

.. code:: python

  class MySWT(SWT_RSA_SHA256):

      def get_public_key(self):
          return Path(f'/keys/{self.issuer}-public.pem').read_text()

      def get_private_key(self):
          return Path(f'/keys/{self.issuer}-private.pem').read_text()

Creating token objects from existing token strings, e.g. directly from http
headers or similar.

.. code:: python

  # You can pass a full bearer token value directly from the request header
  # no need to strip out the Bearer part first
  token = MySWT(http_header_value)

  if token.is_valid:
      # Token has both a valid signature and is not expired

  if token.is_signed:
      # Token has a valid signature

  if token.is_expired:
      # Token is signed and expired, or token is not signed
      # We only trust data in the token if it is signed

Creating and signing new tokens

.. code:: python

  # Create token
  token = MySWT()

  # Set issuer, you must have a key locator that can find the private key based
  # upon the issuer
  token.issuer = 'my-issuer'

  # Set time to live
  token.ttl = 3600

  # Set claims
  token.set_claim('sub', 42)
  token.set_claim('foo', 'bar')

  # Sign token with private key, and get serialized token back
  token_str = token.sign()

  # You can also get the serialized token from the token objectt by accessing
  # the token_str property
  token_str = token.token_str

As a convenience, if you use the token object in string or boolean context it
will do *the right thing™*.

.. code:: python

  # Token in string context gives you the serialized token
  token_str = str(token)

  # Token in boolean context gives you the validity of the token
  is_valid = bool(token)

  # Parse token from string, and do stuff with it, if it is valid
  token = MySWT(http_header_value)
  if token:
      # Do stuff with the valid token

API Reference
-------------

.. automodule:: swt
   :members:

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
