# UPKIT Common X.509

This crate provides Public Key Infrastructure (PKI) utility functions for
building, parsing and validation of X.509-related objects.

## Covered PKI objects

* X.509 certificate
* OCSP request and response
* Certificate Revocation List (CRL)
* Time-Stamp request and response

...and more.

## Sample code

[`tests/`](upkit-common-x509/tests/) has several examples of how the library can
be used.

## Core dependencies

The [TYST Cryptographic Provider](https://github.com/mydriatech/tyst) is used from
cryptographic operations.

The great [`rasn` ASN.1 Codec Framework](https://github.com/librasn/rasn) is
used for low level ASN.1 encoding and decoding.
