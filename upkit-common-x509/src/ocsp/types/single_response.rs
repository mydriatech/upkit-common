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

//! OCSP Single Response.

use super::CertId;
use super::CertStatus;
use crate::crl::crl_entry_extensions::CrlEntryExtensions;
use crate::crl::crl_entry_extensions::ReasonCode;

/** OCSP Single Response.

[RFC 6960 4.2.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1):

```text
   SingleResponse ::= SEQUENCE {
      certID                       CertID,
      certStatus                   CertStatus,
      thisUpdate                   GeneralizedTime,
      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
```

Unsupported extensions:

* [RFC 6960 4.4.2](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.2) CRL References
* [RFC 6960 4.4.4](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.4) Archive Cutoff
*/
#[derive(Clone)]
pub struct SingleResponse {
    cert_id: CertId,
    cert_status: CertStatus,
    this_update: u64,
    next_update: Option<u64>,
    single_extensions_reason: Option<ReasonCode>,
    single_extensions_invalidity_date: Option<u64>,
}
impl SingleResponse {
    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(single_response: &rasn_ocsp::SingleResponse) -> Self {
        // https://www.rfc-editor.org/rfc/rfc6960#section-4.4.5 CRL entry extensions reasonCode and invalidityDate
        let single_extensions =
            CrlEntryExtensions::from_rasn_type(&single_response.single_extensions);
        Self {
            cert_id: CertId::from_rasn_type(&single_response.cert_id),
            cert_status: CertStatus::from_rasn_type(&single_response.cert_status),
            this_update: u64::try_from(single_response.this_update.timestamp()).unwrap(),
            next_update: single_response
                .next_update
                .map(|next_update| u64::try_from(next_update.timestamp()).unwrap()),
            single_extensions_reason: single_extensions
                .as_ref()
                .map(|single_extensions| single_extensions.get_reason_code()),
            single_extensions_invalidity_date: single_extensions.as_ref().and_then(
                |single_extensions| single_extensions.get_invalidity_date_epoch_seconds(),
            ),
        }
    }

    /// Return the identifier for the certificate.
    pub fn get_cert_id(&self) -> &CertId {
        &self.cert_id
    }

    /// Return high level revocation status of the certificate.
    pub fn get_cert_status(&self) -> &CertStatus {
        &self.cert_status
    }

    /// Return the most recent time at which the status being indicated is known
    /// by the responder to have been correct in epoch seconds.
    ///
    /// See [RFC 6960 2.4](https://www.rfc-editor.org/rfc/rfc6960#section-2.4).
    pub fn get_this_update(&self) -> u64 {
        self.this_update
    }

    /// Return the time at or before which newer information will be available
    /// about the status of the certificate in epoch seconds.
    ///
    /// See [RFC 6960 2.4](https://www.rfc-editor.org/rfc/rfc6960#section-2.4).
    pub fn get_next_update(&self) -> Option<u64> {
        self.next_update
    }

    /// Return revocation reason of the certificate when it is revoked.
    pub fn get_reason_code(&self) -> &Option<ReasonCode> {
        &self.single_extensions_reason
    }

    /// Return the invalidity date if present.
    pub fn get_invalidity_date(&self) -> Option<u64> {
        self.single_extensions_invalidity_date
    }

    /// Return true if the OCSP Response is valid at `point_in_time_epoch_seconds`.
    ///
    /// The CA is required to have published the next OCSP Response at `nextUpdate`.
    ///
    /// In practice this means that CAs generate the OCSP Response well before this point
    /// in time and `nextUpdate` is used as expiration date for a OCSP Response.
    pub fn is_valid_at(&self, point_in_time_epoch_seconds: u64) -> bool {
        if let Some(next_update) = self.get_next_update()
            && point_in_time_epoch_seconds >= next_update
        {
            return false;
        }
        if point_in_time_epoch_seconds < self.get_this_update() {
            return false;
        }
        true
    }

    /// Return the revocation reason and invalidity date for revoked
    /// certificates.
    ///
    /// An OCSP responser that isn't using the Extended Revocation Definition
    /// might still respond with "Unknown" status. If so, we follow
    /// [RFC 6960 2.2](https://www.rfc-editor.org/rfc/rfc6960#section-2.2)
    /// and treat this as lack of information to allow other methods (e.g. CRL
    /// check)
    pub fn get_certificate_status(&self) -> Option<(ReasonCode, u64)> {
        match &self.cert_status {
            CertStatus::Good => None,
            CertStatus::Unknown => None,
            CertStatus::Revoked {
                revocation_time_epoch_seconds,
                revocation_reason,
            } => {
                let reason = revocation_reason
                    .as_ref()
                    .unwrap_or(&ReasonCode::Unspecified);
                let invalid_from_epoch_seconds = self
                    .get_invalidity_date()
                    .unwrap_or(*revocation_time_epoch_seconds);
                Some((reason.to_owned(), invalid_from_epoch_seconds))
            }
        }
    }
}
