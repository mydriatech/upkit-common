# UPKIT Common utility library

Opinionated [Public Key Infrastructure (PKI)](https://en.wikipedia.org/wiki/Public_key_infrastructure)
utility library for [Rust](https://www.rust-lang.org/).


## UPKIT

This repository is part of the Ultimate Public Key Infrastructure Toolkit
(UPKIT).

The complexity of Public Key Infrastructures (PKIs), digital certificates and
applied cryptography can be complicated to work with.

UPKIT reduces the exposed complexity so you can focus on what you really wanted
to do instead. See the "Limitations" section below for additional details.


## Quick start

Add the following to `Cargo.toml`:

```text
[dependencies]
upkit_common = { git = "https://github.com/mydriatech/upkit-common.git", branch = "main" }
```

See [`test_cert_paths.rs`](upkit-common-x509/tests/test_cert_paths.rs) for an
example of X.509 certificate parsing from PEM and certificate chain validation.


## Limitations

Reducing complexity might have excluded your favorite feature.
Open a new Issue and state your case.

### Examples of reduced complexity

* Support any signature algorithm (including Post-Quantum Crypto) that [TYST](https://github.com/mydriatech/tyst) supports.
* UTF-8 everywhere when allowed and objects are de-/serializable from/to JSON.
* Extensive list of well-known `Attribute`s and `GeneralName`s (encode/decode/validate).
* Always generate 159 bits CSPRNG X.509 certificate serial numbers.
* Set `critical` of X.509 certificate extensions according to best practices.
* Prefer URIs over directory names.
* Indirect CRLs are not supported due to lack of real-world support.
* ...

## License

[Apache License 2.0 with Free world makers exception 1.0.0](LICENSE-Apache-2.0-with-FWM-Exception-1.0.0)

The intent of this license to

* Allow makers, innovators, integrators and engineers to do what they do best without blockers.
* Give commercial and non-commercial entities in the free world a competitive advantage.
* Support a long-term sustainable business model where no "open core" or "community edition" is ever needed.

## Governance model

This projects uses the [Benevolent Dictator Governance Model](http://oss-watch.ac.uk/resources/benevolentdictatorgovernancemodel) (site only seem to support plain HTTP).

See also [Code of Conduct](CODE_OF_CONDUCT.md) and [Contributing](CONTRIBUTING.md).
