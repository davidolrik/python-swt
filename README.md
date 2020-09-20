# Python SWT Library

![Python version](https://img.shields.io/pypi/pyversions/swt)
![PyPI version](https://img.shields.io/pypi/v/swt)
![format](https://img.shields.io/pypi/format/swt)
![status](https://img.shields.io/pypi/status/swt)
![license](https://img.shields.io/pypi/l/swt)

Python library for handling `Simple Web Tokens`.

## Documentation

You can find the docs [here](https://python-swt.readthedocs.io/).

## Caveats

- Please use `pycryptodome` and not `pycrypto` as the later is unmaintained and
  broken on python 3.8+
- Currently only supports RSA-SHA256

## TODO

- Add support HMAC SHA256
- Add  Raises: KeyNotFoundError to sign()
