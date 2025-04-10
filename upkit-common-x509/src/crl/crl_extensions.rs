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

//! X.509 Certificate Revocation List (CRL) extensions.

mod crl_number;
mod issuing_distribution_point;

use super::parse::CrlParsingError;
use crate::cert::extensions::AlternativeName;
use crate::cert::extensions::AuthorityInfoAccessDescription;
use crate::cert::extensions::AuthorityKeyIdentifier;
use crate::cert::extensions::CrlDistributionPoint;
use crate::cert::types::WellKnownGeneralName;
pub use crl_number::*;
pub use issuing_distribution_point::*;

/// CRL extensions.
pub struct CrlExtensions {
    extensions: rasn_pkix::Extensions,
}

impl CrlExtensions {
    /// Return a new instance.
    pub fn from_rasn_type(extensions: &Option<rasn_pkix::Extensions>) -> Option<Self> {
        extensions.as_ref().map(|extensions| Self {
            extensions: extensions.to_owned(),
        })
    }

    /// Return the [AuthorityKeyIdentifier] `key_identifier` bytes if present.
    pub fn get_authority_key_identifier_kid(&self) -> Option<Vec<u8>> {
        crate::encdec::rasn::first_extension_by_oid(&self.extensions, AuthorityKeyIdentifier::OID)
            .map(AuthorityKeyIdentifier::from_rasn_extension)
            .as_ref()
            .and_then(AuthorityKeyIdentifier::get_key_identifier)
    }

    /// Return the all [WellKnownGeneralName] if present.
    pub fn get_issuer_alternative_name(&self) -> Vec<(WellKnownGeneralName, String)> {
        crate::encdec::rasn::first_extension_by_oid(
            &self.extensions,
            AlternativeName::OID_ISSUER_AN,
        )
        .map(AlternativeName::from_rasn_extension)
        .unwrap_or_default()
    }

    /// Return the [CrlNumber] if present.
    pub fn get_crl_number(&self) -> Option<CrlNumber> {
        crate::encdec::rasn::first_extension_by_oid(&self.extensions, CrlNumber::OID_CRL_NUMBER)
            .map(CrlNumber::from_rasn_extension)
    }

    /// Return the Delta CRL indicator base [CrlNumber] if present.
    pub fn get_delta_crl_indicator(&self) -> Option<CrlNumber> {
        crate::encdec::rasn::first_extension_by_oid(
            &self.extensions,
            CrlNumber::OID_DELTA_CRL_INDICATOR,
        )
        .map(CrlNumber::from_rasn_extension)
    }

    /// Return the [IssuingDistributionPoint] if present. Return an Err when present in an unsupported format.
    pub fn get_issuing_distribution_point(&self) -> Result<Option<String>, CrlParsingError> {
        crate::encdec::rasn::first_extension_by_oid(&self.extensions, IssuingDistributionPoint::OID)
            .map(IssuingDistributionPoint::from_rasn_extension)
            .map(|value| value.map(Some))
            .unwrap_or(Ok(None))
    }

    /// Return freshest/delta CRL distribution point. Preferr http over ldap. The scope etc is implied by the full CRL.
    pub fn get_crl_distribution_point(&self) -> Option<String> {
        crate::encdec::rasn::first_extension_by_oid(
            &self.extensions,
            CrlDistributionPoint::OID_DELTA_CDP,
        )
        .and_then(CrlDistributionPoint::from_rasn_extension)
    }

    /// Return the `id-ad-caIssuers` [AuthorityInfoAccessDescription] if present.
    pub fn get_authority_information_access(&self) -> Option<AuthorityInfoAccessDescription> {
        crate::encdec::rasn::first_extension_by_oid(
            &self.extensions,
            AuthorityInfoAccessDescription::OID,
        )
        .map(AuthorityInfoAccessDescription::from_rasn_extension)
        .and_then(|access_descriptions| {
            access_descriptions.into_iter().find(|aiad| {
                matches!(
                    aiad,
                    AuthorityInfoAccessDescription::CaIssuers { access_location: _ }
                )
            })
        })
    }
}
