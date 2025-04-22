/*
    Copyright 2025 MydriaTech AB

    Licensed under the Apache License 2.0 with Free world makers exception
    1.0.0 (the "License"); you may not use this file except in compliance with
    the License. You should have obtained a copy of the License with the source
    or binary distribution in file named

        LICENSE-Apache-2.0-with-FWM-Exception-1.0.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

//! ASN.1 module for [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986).

// TODO: Re-license and contribute this upstream to `rasn`.

use rasn::prelude::*;
use rasn::{AsnType, Decode, Encode};

/** Certification request information.

[RFC 2986 4.1](https://www.rfc-editor.org/rfc/rfc2986#section-4):

```text
   CertificationRequestInfo ::= SEQUENCE {
        version       INTEGER { v1(0) } (v1,...),
        subject       Name,
        subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
        attributes    [0] Attributes{{ CRIAttributes }}
   }

   ...

   CRIAttributes  ATTRIBUTE  ::= {
        ... -- add any locally defined attributes here -- }
```

Example attributes:

* [RFC 2985 5.4.1](https://www.rfc-editor.org/rfc/rfc2985#section-5) `challengePassword`
* [RFC 2985 5.4.2](https://www.rfc-editor.org/rfc/rfc2985#section-5) `extensionRequest`
* [RFC 7894.html 3.1](https://www.rfc-editor.org/rfc/rfc7894.html#section-3.1) `otpChallenge`

*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertificationRequestInfo {
    /// Version number. It shall be 0 for RFC 2986.
    pub version: Integer,
    /// The distinguished name of the certificate subject (the entity whose
    /// public key is to be certified).
    pub subject: rasn_pkix::Name,
    /// Contains information about the public key being certified.
    ///
    /// The information identifies the entity's public-key algorithm (and any
    /// associated parameters).
    pub subject_pk_info: rasn_pkix::SubjectPublicKeyInfo,
    /// A collection of attributes providing additional information about the
    /// subject of the certificate.
    ///
    /// Some attribute types that might be useful here are defined in PKCS #9.
    ///
    /// An example is the challenge-password attribute, which specifies a
    /// password by which the entity may request certificate revocation.
    /// Another example is information to appear in X.509 certificate extensions
    /// (e.g. the extensionRequest attribute from PKCS #9).
    #[rasn(tag(0))]
    pub attributes: SetOf<rasn_pkix::Attribute>,
}

/** Certificate request.

A certification request consists of a distinguished name, a public key, and
optionally a set of attributes, collectively signed by the entity requesting
certification.


[RFC 2986 4.2](https://www.rfc-editor.org/rfc/rfc2986#section-4):

```text
   CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertificationRequest {
    /// See [CertificationRequestInfo].
    pub certification_request_info: CertificationRequestInfo,
    /// The signature algorithm (and any associated parameters) under which the
    /// certification-request information is signed.
    pub signature_algorithm: rasn_pkix::AlgorithmIdentifier,
    /// The result of signing the DER encoded [CertificationRequestInfo] with
    /// the certification request subject's private key.
    pub signature: BitString,
}
