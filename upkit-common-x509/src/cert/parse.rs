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

use rasn::types::ObjectIdentifier;
use rasn::types::SequenceOf;

pub use self::parsing_error::CertificateParsingError;
pub use self::parsing_error::CertificateParsingErrorKind;

use super::extensions::AlternativeName;
use super::extensions::AuthorityInfoAccessDescription;
use super::extensions::AuthorityKeyIdentifier;
use super::extensions::BasicConstraints;
use super::extensions::CertificatePolicy;
use super::extensions::ExtendedKeyUsage;
use super::extensions::KeyUsage;
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

    /// Return the subject distinguished name.
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
        let alg_id = &self.certificate.signature_algorithm;
        let oid = alg_id
            .algorithm
            .iter()
            .map(|part| part.to_string())
            .collect::<Vec<_>>()
            .join(".")
            .to_owned();
        // TODO: This is too simplified to support every alg, but its good enough for now...
        //let params = &alg_id.parameters;
        (
            oid,
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

    fn extensions_by_oid(&self, oid: &[u32]) -> Vec<rasn_pkix::Extension> {
        self.certificate
            .tbs_certificate
            .extensions
            .as_ref()
            .map(|x509extension| {
                x509extension
                    .iter()
                    .filter_map(|extension| {
                        if rasn::types::ObjectIdentifier::new_unchecked(oid.to_vec().into())
                            .eq(&extension.extn_id)
                        {
                            Some(extension.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<rasn_pkix::Extension>>()
            })
            .unwrap_or_default()
    }

    /// Return Basic Constraints (when present)
    pub fn get_basic_constraints(&self) -> Option<BasicConstraints> {
        self.extensions_by_oid(BasicConstraints::OID)
            .first()
            .map(|extension| {
                rasn::der::decode::<rasn_pkix::BasicConstraints>(&extension.extn_value).unwrap()
            })
            .as_ref()
            .map(BasicConstraints::from_rasn_type)
    }

    /** Returns bit array with `[0]` as `DigitalSignature` to `[8]` as `DecipherOnly`

    ```text
    [0]: DigitalSignature,
    [1]: NonRepudiation,
    [2]: KeyEncipherment,
    [3]: DataEncipherment,
    [4]: KeyAgreement,
    [5]: KeyCertSign,
    [6]: CRLSign,
    [7]: EncipherOnly,
    [8]: DecipherOnly,
    ```
     */
    pub fn get_key_usage(&self) -> Option<[bool; 9]> {
        if let Some(extension) = self.extensions_by_oid(KeyUsage::OID).first() {
            let key_usage =
                rasn::der::decode::<rasn_pkix::KeyUsage>(&extension.extn_value).unwrap();
            let mut ret = [false; 9];
            for (i, b) in key_usage.into_iter().enumerate() {
                ret[i] = b;
            }
            Some(ret)
        } else {
            None
        }
    }

    /// Return the all [ExtendedKeyUsage]s if present.
    pub fn get_extended_key_usage(&self) -> Vec<ExtendedKeyUsage> {
        if let Some(extension) = self.extensions_by_oid(ExtendedKeyUsage::OID).first() {
            let ekus =
                rasn::der::decode::<SequenceOf<ObjectIdentifier>>(&extension.extn_value).unwrap();
            ekus.iter()
                .map(|oid| ExtendedKeyUsage::from_oid(oid))
                .collect()
        } else {
            Vec::default()
        }
    }

    /// Return the [AuthorityKeyIdentifier] `key_identifier` bytes if present.
    pub fn get_authority_key_identifier_kid(&self) -> Option<Vec<u8>> {
        if let Some(extension) = self.extensions_by_oid(AuthorityKeyIdentifier::OID).first() {
            let aki = rasn::der::decode::<rasn_pkix::AuthorityKeyIdentifier>(&extension.extn_value)
                .unwrap();
            if let Some(kid) = aki.key_identifier {
                return Some(kid.to_vec());
            }
        }
        None
    }

    /// Return the [SubjectKeyIdentifier] `key_identifier` bytes if present.
    pub fn get_subject_key_identifier_kid(&self) -> Option<Vec<u8>> {
        if let Some(extension) = self.extensions_by_oid(SubjectKeyIdentifier::OID).first() {
            let ski = rasn::der::decode::<rasn_pkix::SubjectKeyIdentifier>(&extension.extn_value)
                .unwrap();
            return Some(ski.to_vec());
        }
        None
    }

    /// Return the all [CertificatePolicy] if present.
    pub fn get_certificate_policies(&self) -> Vec<CertificatePolicy> {
        if let Some(extension) = self.extensions_by_oid(CertificatePolicy::OID).first() {
            let policies = rasn::der::decode::<SequenceOf<rasn_pkix::PolicyInformation>>(
                &extension.extn_value,
            )
            .unwrap();
            CertificatePolicy::from_rasn_type(&policies)
        } else {
            Vec::default()
        }
    }

    /// Return the all [CertificatePolicy] if present.
    pub fn get_authority_information_access(&self) -> Vec<AuthorityInfoAccessDescription> {
        if let Some(extension) = self
            .extensions_by_oid(AuthorityInfoAccessDescription::OID)
            .first()
        {
            let access_descriptions =
                rasn::der::decode::<SequenceOf<rasn_pkix::AccessDescription>>(
                    &extension.extn_value,
                )
                .unwrap();
            AuthorityInfoAccessDescription::from_rasn_type(&access_descriptions)
        } else {
            Vec::default()
        }
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
        if let Some(extension) = self.extensions_by_oid(oid).first() {
            let general_names =
                rasn::der::decode::<SequenceOf<rasn_pkix::GeneralName>>(&extension.extn_value)
                    .unwrap();
            AlternativeName::from_rasn_type(&general_names)
        } else {
            Vec::default()
        }
    }
}
