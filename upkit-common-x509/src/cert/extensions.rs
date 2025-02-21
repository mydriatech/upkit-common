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

//! X.509 Certificate extensions.

mod alternative_name;
mod authority_information_access;
mod basic_constraints;
mod certificate_policies;
mod crl_distribution_points;
mod extended_key_usage;
mod key_identifier;
mod key_usage;

pub use self::alternative_name::AlternativeName;
pub use self::authority_information_access::AuthorityInfoAccessDescription;
pub use self::basic_constraints::BasicConstraints;
pub use self::certificate_policies::CertificatePolicy;
pub use self::certificate_policies::WellKnownCertificatePolicy;
pub use self::crl_distribution_points::CrlDistributionPoint;
pub use self::extended_key_usage::ExtendedKeyUsage;
pub use self::key_identifier::AuthorityKeyIdentifier;
pub use self::key_identifier::SubjectKeyIdentifier;
pub use self::key_usage::KeyUsage;
use super::types::WellKnownGeneralName;
use rasn::error::EncodeError;
use rasn::types::ObjectIdentifier;
use rasn::types::OctetString;

// TODO
// PrivateKeyUsagePeriod
// MS Templates certificate extension 1.3.6.1.4.1.311.20.2
// Certificate template v2            1.3.6.1.4.1.311.21.7
// MS app policies extension          1.3.6.1.4.1.311.21.10
// MS objectSid OtherName             1.3.6.1.4.1.311.25.2.1 szOID_NTDS_OBJECTSID
// CT (Certificate Transparency) specific extensions   1.3.6.1.4.1.11129.2.4.6
// CT (Certificate Transparency) precert poisoning ext 1.3.6.1.4.1.11129.2.4.3

/// X.509 Certificate extensions.
#[derive(Default)]
pub struct Extensions {
    extensions: Vec<rasn_pkix::Extension>,
}

impl Extensions {
    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> Option<rasn_pkix::Extensions> {
        if self.extensions.is_empty() {
            None
        } else {
            // Extensions(SequenceOf<Extension>)
            Some(rasn_pkix::Extensions::from(self.extensions.clone()))
        }
    }

    fn add_extension<T: rasn::Encode>(
        &mut self,
        oid: &'static [u32],
        critical: bool,
        rasn_type: &T,
    ) -> Result<(), EncodeError> {
        let bytes = rasn::der::encode(rasn_type).unwrap();
        self.extensions.push(rasn_pkix::Extension {
            extn_id: ObjectIdentifier::new_unchecked(oid.into()),
            critical,
            extn_value: OctetString::from(bytes),
        });
        Ok(())
    }

    /// See [BasicConstraints] for details.
    pub fn add_basic_constraints(&mut self, basic_constraints: &BasicConstraints) {
        self.add_extension(
            BasicConstraints::OID,
            basic_constraints.is_ca(),
            &basic_constraints.to_rasn_type(),
        )
        .unwrap();
    }

    /// See [KeyUsage] for details.
    pub fn add_key_usage(&mut self, key_usages: &[KeyUsage]) {
        if !key_usages.is_empty() {
            self.add_extension(KeyUsage::OID, true, &KeyUsage::to_rasn_type(key_usages))
                .unwrap();
        }
    }

    /// See [AuthorityInfoAccessDescription] for details.
    pub fn add_authority_information_access(
        &mut self,
        access_descriptions: &[AuthorityInfoAccessDescription],
    ) {
        if !access_descriptions.is_empty() {
            self.add_extension(
                AuthorityInfoAccessDescription::OID,
                false,
                &AuthorityInfoAccessDescription::to_rasn_type(access_descriptions),
            )
            .unwrap();
        }
    }

    /// See [CertificatePolicy] for details.
    pub fn add_certificate_policies(&mut self, certificate_policies: &[CertificatePolicy]) {
        if !certificate_policies.is_empty() {
            self.add_extension(
                CertificatePolicy::OID,
                false,
                &CertificatePolicy::to_rasn_type(certificate_policies),
            )
            .unwrap();
        }
    }

    /// See [CrlDistributionPoint] for details.
    pub fn add_crl_distribution_points(&mut self, crl_distribution_point_uri: &str) {
        self.add_extension(
            CrlDistributionPoint::OID,
            false,
            &CrlDistributionPoint::to_rasn_type(crl_distribution_point_uri),
        )
        .unwrap();
    }

    /// See [AuthorityKeyIdentifier] for details.
    pub fn add_authority_key_identifier(
        &mut self,
        authority_key_identifier: &AuthorityKeyIdentifier,
    ) {
        self.add_extension(
            AuthorityKeyIdentifier::OID,
            false,
            authority_key_identifier.to_rasn_type(),
        )
        .unwrap();
    }

    /// See [SubjectKeyIdentifier] for details.
    pub fn add_subject_key_identifier(&mut self, subject_key_identifier: &SubjectKeyIdentifier) {
        self.add_extension(
            SubjectKeyIdentifier::OID,
            false,
            subject_key_identifier.to_rasn_type(),
        )
        .unwrap();
    }

    /// See [ExtendedKeyUsage] for details.
    pub fn add_extended_key_usage(&mut self, extended_key_usages: &[ExtendedKeyUsage]) {
        if !extended_key_usages.is_empty() {
            self.add_extension(
                ExtendedKeyUsage::OID,
                false,
                &ExtendedKeyUsage::to_rasn_type(extended_key_usages),
            )
            .unwrap();
        }
    }

    /// See [AlternativeName] for details.
    ///
    /// RFC 5280 4.2.1.6:
    ///
    /// "If the subject field contains an empty sequence, then the
    /// issuing CA MUST include a subjectAltName extension that is marked
    /// as critical."
    pub fn add_subject_alternative_name(
        &mut self,
        subject_alternative_names: &[(WellKnownGeneralName, String)],
        subject_dn_empty: bool,
    ) {
        if !subject_alternative_names.is_empty() {
            self.add_extension(
                AlternativeName::OID_SUBJECT_AN,
                subject_dn_empty,
                &AlternativeName::to_rasn_type(subject_alternative_names),
            )
            .unwrap();
        }
    }

    /// See [AlternativeName] for details.
    pub fn add_issuer_alternative_name(
        &mut self,
        issuer_alternative_names: &[(WellKnownGeneralName, String)],
    ) {
        if !issuer_alternative_names.is_empty() {
            self.add_extension(
                AlternativeName::OID_ISSUER_AN,
                false,
                &AlternativeName::to_rasn_type(issuer_alternative_names),
            )
            .unwrap();
        }
    }
}
