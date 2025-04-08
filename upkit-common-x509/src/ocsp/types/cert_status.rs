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

//! OCSP response certificate revocation status.

use crate::crl::crl_entry_extensions::ReasonCode;

/** OCSP response certificate revocation status.

For the overall OCSP response's status, see
[OcspResponseStatus](super::OcspResponseStatus).

[RFC 6960 4.2.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1):

```text
CertStatus ::= CHOICE {
    good        [0]     IMPLICIT NULL,
    revoked     [1]     IMPLICIT RevokedInfo,
    unknown     [2]     IMPLICIT UnknownInfo }

RevokedInfo ::= SEQUENCE {
    revocationTime              GeneralizedTime,
    revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }

UnknownInfo ::= NULL
```
*/
#[derive(Clone)]
pub enum CertStatus {
    /// Certificate is not revoked.
    Good,
    /// Certificate is revoked for a reason or has never been issued when the
    /// Extended Revoked Definition is used.
    ///
    /// See [RFC 6960 4.4.8](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.8).
    Revoked {
        /// Time of revocation in epoch seconds.
        revocation_time_epoch_seconds: u64,
        /// Reason for the revocation.
        revocation_reason: Option<ReasonCode>,
    },
    /// The responder does not know about the certificate and recommends another
    /// source of revocation info to be tried.
    Unknown,
}

impl CertStatus {
    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(value: &rasn_ocsp::CertStatus) -> Self {
        match value {
            rasn_ocsp::CertStatus::Good => Self::Good,
            rasn_ocsp::CertStatus::Revoked(revoked_info) => Self::Revoked {
                revocation_time_epoch_seconds: u64::try_from(
                    revoked_info.revocation_time.timestamp(),
                )
                .unwrap(),
                revocation_reason: revoked_info
                    .revocation_reason
                    .map(|crl_reason| ReasonCode::from_rasn_type(&crl_reason)),
            },
            rasn_ocsp::CertStatus::Unknown(_) => Self::Unknown,
        }
    }
}
