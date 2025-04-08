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

//! X.509 Certificate Revocation List (CRL) Entry extensions.

mod invalidity_date;
mod reason_code;

pub use invalidity_date::*;
pub use reason_code::*;

/// CRL Entry extensions.
pub struct CrlEntryExtensions {
    extensions: rasn_pkix::Extensions,
}

impl CrlEntryExtensions {
    /// Return a new instance.
    pub fn from_rasn_type(extensions: &Option<rasn_pkix::Extensions>) -> Option<Self> {
        extensions.as_ref().map(|extensions| Self {
            extensions: extensions.to_owned(),
        })
    }

    /// Return the revocation reason or [ReasonCode::Unspecified] if the
    /// extension is not present.
    ///
    /// See [RFC5280 5.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.3).
    pub fn get_reason_code(&self) -> ReasonCode {
        crate::encdec::rasn::first_extension_by_oid(&self.extensions, ReasonCode::OID)
            .and_then(|extension| {
                rasn::der::decode::<rasn_pkix::CrlReason>(&extension.extn_value).ok()
            })
            .map(|crl_reason| ReasonCode::from_rasn_type(&crl_reason))
            .unwrap_or_default()
    }

    /// Return the invalidity date if the extension is present.
    ///
    /// See [RFC5280 5.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.3).
    pub fn get_invalidity_date_epoch_seconds(&self) -> Option<u64> {
        crate::encdec::rasn::first_extension_by_oid(&self.extensions, InvalidityDate::OID)
            .and_then(|extension| {
                rasn::der::decode::<rasn_pkix::InvalidityDate>(&extension.extn_value).ok()
            })
            .as_ref()
            .map(InvalidityDate::from_rasn_type)
            .map(|invalidity_date| invalidity_date.get_invalidity_date_epoch_seconds())
    }
}
