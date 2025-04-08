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

//! OCSP response status.

/** OCSP response status.

For an individual certificate's revocation status, see
[CertStatus](super::CertStatus).

Defined in:

* [RFC 6960 2.3](https://www.rfc-editor.org/rfc/rfc6960#section-2.3) Exception Cases
* [RFC 6960 4.2.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1) ASN.1 Specification of the OCSP Response

```text
OCSPResponseStatus ::= ENUMERATED {
    successful            (0),  -- Response has valid confirmations
    malformedRequest      (1),  -- Illegal confirmation request
    internalError         (2),  -- Internal error in issuer
    tryLater              (3),  -- Try again later
                                -- (4) is not used
    sigRequired           (5),  -- Must sign the request
    unauthorized          (6)   -- Request unauthorized
}
```
*/
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspResponseStatus {
    /// Response has valid confirmations.
    Successful,
    /// Illegal confirmation request.
    MalformedRequest,
    /// Internal error in issuer.
    InternalError,
    /// Try again later.
    TryLater,
    /// Must sign the request.
    SigRequired,
    /// Request unauthorized.
    Unauthorized,
}

impl OcspResponseStatus {
    /// Return the numeric status code.
    pub fn value(&self) -> usize {
        match self {
            Self::Successful => 0,
            Self::MalformedRequest => 1,
            Self::InternalError => 2,
            Self::TryLater => 3,
            Self::SigRequired => 5,
            Self::Unauthorized => 6,
        }
    }

    /// Return a new instance from the numeric status code.
    pub fn from_value(value: usize) -> Self {
        match value {
            0 => Self::Successful,
            1 => Self::MalformedRequest,
            2 => Self::InternalError,
            3 => Self::TryLater,
            5 => Self::SigRequired,
            6 => Self::Unauthorized,
            unknown => panic!("Unable to interpret OCSP response status code '{unknown}'."),
        }
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(value: &rasn_ocsp::OcspResponseStatus) -> Self {
        match value {
            rasn_ocsp::OcspResponseStatus::Successful => Self::Successful,
            rasn_ocsp::OcspResponseStatus::MalformedRequest => Self::MalformedRequest,
            rasn_ocsp::OcspResponseStatus::InternalError => Self::InternalError,
            rasn_ocsp::OcspResponseStatus::TryLater => Self::TryLater,
            rasn_ocsp::OcspResponseStatus::SigRequired => Self::SigRequired,
            rasn_ocsp::OcspResponseStatus::Unauthorized => Self::Unauthorized,
        }
    }
}
