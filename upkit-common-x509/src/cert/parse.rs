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

//! X.509 Certificate parser.

/* From https://www.rfc-editor.org/rfc/rfc5280

Certificate  ::=  SEQUENCE  {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signature            BIT STRING  }


TBSCertificate  ::=  SEQUENCE  {
    version         [0]  Version DEFAULT v1,
    serialNumber         CertificateSerialNumber,
    signature            AlgorithmIdentifier,
    issuer               Name,
    validity             Validity,
    subject              Name,
    subjectPublicKeyInfo SubjectPublicKeyInfo,
    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                         -- If present, version MUST be v2 or v3
    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                         -- If present, version MUST be v2 or v3
    extensions      [3]  Extensions OPTIONAL
                         -- If present, version MUST be v3 --  }
*/

mod parsing_error;

pub use self::parsing_error::CertificateParsingError;
pub use self::parsing_error::CertificateParsingErrorKind;
use super::extensions::AlternativeName;
use super::extensions::AuthorityInfoAccessDescription;
use super::extensions::AuthorityKeyIdentifier;
use super::extensions::BasicConstraints;
use super::extensions::CertificatePolicy;
use super::extensions::CrlDistributionPoint;
use super::extensions::ExtendedKeyUsage;
use super::extensions::KeyUsage;
use super::extensions::OcspNoCheck;
use super::extensions::PrivateKeyUsagePeriod;
use super::extensions::SubjectKeyIdentifier;
use super::types::DistinguishedName;
use super::types::SerialNumber;
use super::types::Validity;
use super::types::WellKnownGeneralName;

/// Certificate parser.
#[derive(Clone)]
pub struct CertificateParser {
    certificate: rasn_pkix::Certificate,
    fingerprint: String,
}
impl CertificateParser {
    /// Create a new instance from `encoded_certificate` bytes.
    pub fn from_bytes(encoded_certificate: &[u8]) -> Result<Self, CertificateParsingError> {
        let fingerprint = crate::fingerprint_data(encoded_certificate);
        rasn::der::decode::<rasn_pkix::Certificate>(encoded_certificate)
            .map_err(|e|{
                let msg = format!("Error while decoding data with fingerprint '{fingerprint}'. kind: '{:?}', codec: '{:?}'", e.kind, e.codec);
                CertificateParsingErrorKind::CertificateDecodingError.error_with_msg(&msg)
            })
            .map(|certificate| {
                Self {
                    certificate,
                    fingerprint,
                }
            })
    }

    /// Return the DER encoded certificate.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CertificateParsingError> {
        rasn::der::encode(&self.certificate)
            .map_err(|e|{
                let msg = format!("Error while encoding certificate with fingerprint '{}'. kind: '{:?}', codec: '{:?}'", self.fingerprint ,e.kind, e.codec);
                CertificateParsingErrorKind::CertificateDecodingError.error_with_msg(&msg)
            })
    }

    /// Return [fingerprint](crate::fingerprint_data) of the encoded certificate.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Return certificate valdity (in Unix Epoch seconds).
    pub fn get_validity(&self) -> Validity {
        Validity::from_rasn_type(&self.certificate.tbs_certificate.validity)
    }

    /// Return the part of the certificate that is covered by the signature
    /// as DER encoded bytes.
    pub fn get_encoded_tbs_certificate(&self) -> Vec<u8> {
        rasn::der::encode(&self.certificate.tbs_certificate).unwrap()
    }

    /// Return the certificate serial number.
    pub fn get_serial_number(&self) -> SerialNumber {
        SerialNumber::from_rasn_type(&self.certificate.tbs_certificate.serial_number)
    }

    /// Return the subject distinguished name.
    pub fn get_subject(&self) -> Result<DistinguishedName, CertificateParsingError> {
        DistinguishedName::from_rasn_type(&self.certificate.tbs_certificate.subject).map_err(|e| {
            CertificateParsingErrorKind::CertificateDecodingError.error_with_msg(&format!(
                "Failed to parse Subject Distinguished Name of certifiate: {e:?}"
            ))
        })
    }

    /// Return the issuer distinguished name.
    pub fn get_issuer(&self) -> Result<DistinguishedName, CertificateParsingError> {
        DistinguishedName::from_rasn_type(&self.certificate.tbs_certificate.issuer).map_err(|e| {
            CertificateParsingErrorKind::CertificateDecodingError.error_with_msg(&format!(
                "Failed to parse Issuer Distinguished Name of certifiate: {e:?}"
            ))
        })
    }

    /// Return the subject distinguished name as DER encoded bytes.
    pub fn get_encoded_subject(&self) -> Vec<u8> {
        rasn::der::encode(&self.certificate.tbs_certificate.subject).unwrap()
    }

    /// Return the issuer distinguished name as DER encoded bytes.
    pub fn get_encoded_issuer(&self) -> Vec<u8> {
        rasn::der::encode(&self.certificate.tbs_certificate.issuer).unwrap()
    }

    /// Return [fingerprint](crate::fingerprint_data) of subject distinguished
    /// name as DER encoded bytes.
    pub fn get_subject_fingerprint(&self) -> String {
        crate::fingerprint_data(&self.get_encoded_subject())
    }

    /// Return [fingerprint](crate::fingerprint_data) of issuer distinguished
    /// name as DER encoded bytes.
    pub fn get_issuer_fingerprint(&self) -> String {
        crate::fingerprint_data(&self.get_encoded_issuer())
    }

    /// Return the Subject Public Key Info as DER encoded bytes.
    pub fn get_encoded_subject_public_key_info(&self) -> Vec<u8> {
        rasn::der::encode(&self.certificate.tbs_certificate.subject_public_key_info).unwrap()
    }

    /// Return the signature OID and data as DER encoded bytes.
    ///
    /// NOTE: This currently ignores the signature parameters.
    pub fn get_encoded_signature(&self) -> (String, Vec<u8>) {
        let oid =
            crate::encdec::rasn::algorithm_identifier_as_oid(&self.certificate.signature_algorithm);
        let oid_string = tyst::encdec::oid::as_string(&oid);
        (
            oid_string,
            self.certificate.signature_value.as_raw_slice().to_vec(),
        )
    }

    /// Return a vector of OIDs of all the critical extensions.
    pub fn get_critical_extension_oids(&self) -> Vec<Vec<u32>> {
        self.certificate
            .tbs_certificate
            .extensions
            .as_ref()
            .map(|x509extension| {
                x509extension
                    .iter()
                    .filter(|extension| extension.critical)
                    .map(|extension| extension.extn_id.to_vec())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    fn first_extension_by_oid(&self, oid: &[u32]) -> Option<rasn_pkix::Extension> {
        self.certificate
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|extensions| crate::encdec::rasn::first_extension_by_oid(extensions, oid))
    }

    /// Return Basic Constraints (when present)
    pub fn get_basic_constraints(&self) -> Option<BasicConstraints> {
        self.first_extension_by_oid(BasicConstraints::OID)
            .map(BasicConstraints::from_rasn_extension)
    }

    /// Returns one of the possible [KeyUsage]s.
    pub fn get_key_usage(&self) -> Option<Vec<KeyUsage>> {
        self.first_extension_by_oid(KeyUsage::OID)
            .map(KeyUsage::from_rasn_extension)
    }

    /// Return the all [ExtendedKeyUsage]s if present.
    pub fn get_extended_key_usage(&self) -> Vec<ExtendedKeyUsage> {
        self.first_extension_by_oid(ExtendedKeyUsage::OID)
            .map(ExtendedKeyUsage::from_rasn_extension)
            .unwrap_or_default()
    }

    /// Return the [AuthorityKeyIdentifier] `key_identifier` bytes if present.
    pub fn get_authority_key_identifier_kid(&self) -> Option<Vec<u8>> {
        self.first_extension_by_oid(AuthorityKeyIdentifier::OID)
            .map(AuthorityKeyIdentifier::from_rasn_extension)
            .as_ref()
            .and_then(AuthorityKeyIdentifier::get_key_identifier)
    }

    /// Return the [SubjectKeyIdentifier] `key_identifier` bytes if present.
    pub fn get_subject_key_identifier_kid(&self) -> Option<Vec<u8>> {
        self.first_extension_by_oid(SubjectKeyIdentifier::OID)
            .map(SubjectKeyIdentifier::from_rasn_extension)
            .as_ref()
            .map(SubjectKeyIdentifier::get_key_identifier)
    }

    /// Return the all [CertificatePolicy] if present.
    pub fn get_certificate_policies(&self) -> Vec<CertificatePolicy> {
        self.first_extension_by_oid(CertificatePolicy::OID)
            .map(CertificatePolicy::from_rasn_extension)
            .unwrap_or_default()
    }

    /// Return a CA issued CDP URI for all revocation reasons if present. Preferr http over ldap.
    pub fn get_crl_distribution_point(&self) -> Option<String> {
        self.first_extension_by_oid(CrlDistributionPoint::OID)
            .and_then(CrlDistributionPoint::from_rasn_extension)
    }

    /// Return the all [AuthorityInfoAccessDescription] if present.
    pub fn get_authority_information_access(&self) -> Vec<AuthorityInfoAccessDescription> {
        self.first_extension_by_oid(AuthorityInfoAccessDescription::OID)
            .map(AuthorityInfoAccessDescription::from_rasn_extension)
            .unwrap_or_default()
    }

    /// Return the all [WellKnownGeneralName] if present.
    pub fn get_issuer_alternative_name(&self) -> Vec<(WellKnownGeneralName, String)> {
        self.get_alternative_name(AlternativeName::OID_ISSUER_AN)
    }

    /// Return the all [WellKnownGeneralName] if present.
    pub fn get_subject_alternative_name(&self) -> Vec<(WellKnownGeneralName, String)> {
        self.get_alternative_name(AlternativeName::OID_SUBJECT_AN)
    }

    fn get_alternative_name(&self, oid: &[u32]) -> Vec<(WellKnownGeneralName, String)> {
        self.first_extension_by_oid(oid)
            .map(AlternativeName::from_rasn_extension)
            .unwrap_or_default()
    }

    /// Return `true` if the
    /// [RFC 6960 4.2.2.2.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2.1)
    /// extension is present in the certificate.
    pub fn is_ocsp_no_check(&self) -> bool {
        self.first_extension_by_oid(OcspNoCheck::OID).is_some()
    }

    /// Return the [PrivateKeyUsagePeriod] if present.
    pub fn get_private_key_usage_period(&self) -> Option<PrivateKeyUsagePeriod> {
        self.first_extension_by_oid(PrivateKeyUsagePeriod::OID)
            .map(PrivateKeyUsagePeriod::from_rasn_extension)
    }
}
