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

//! PKCS#10 Certification request parsing.

use tyst::traits::se::ToPublicKey;
use tyst::Tyst;

use super::CertificationRequestParsingError;
use super::CertificationRequestParsingErrorKind;
use crate::cert::extensions::ExtendedKeyUsage;
use crate::cert::types::DistinguishedName;
use crate::cert::types::WellKnownGeneralName;
use crate::pkcs10::pkcs10_asn1 as asn1;
use crate::pkcs10::types::CertificationRequestInfoAttributes;
use crate::pkcs10::types::ExtensionRequestAttribute;

/** PKCS#10 Certification Request parser.

[RFC 2986 4](https://www.rfc-editor.org/rfc/rfc2986#section-4):

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

   CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }
```
*/
#[derive(Clone)]
pub struct CertificationRequestParser {
    certification_request: asn1::CertificationRequest,
}

impl CertificationRequestParser {
    /// Create a new instance from `encoded_certificate_request` bytes.
    pub fn from_bytes(
        encoded_certificate_request: &[u8],
    ) -> Result<Self, CertificationRequestParsingError> {
        rasn::der::decode::<asn1::CertificationRequest>(encoded_certificate_request)
            .map_err(|e| {
                let msg = format!(
                    "Error while decoding data. kind: '{:?}', codec: '{:?}'",
                    e.kind, e.codec
                );
                CertificationRequestParsingErrorKind::DecodingError.error_with_msg(&msg)
            })
            .map(|certification_request| Self {
                certification_request,
            })
    }

    /// Return the DER encoded certification_request info that covered by the
    /// signature.
    fn get_encoded_certification_request_info(&self) -> Vec<u8> {
        rasn::der::encode(&self.certification_request.certification_request_info).unwrap()
    }

    /// Return the signature OID and data as DER encoded bytes.
    ///
    /// NOTE: This currently ignores the signature parameters.
    fn get_encoded_signature(&self) -> (String, Vec<u8>) {
        let oid = crate::encdec::rasn::algorithm_identifier_as_oid(
            &self.certification_request.signature_algorithm,
        );
        let oid_string = tyst::encdec::oid::as_string(&oid);
        let signature = self.certification_request.signature.as_raw_slice().to_vec();
        (oid_string, signature)
    }

    /// Return the subject distinguished name.
    pub fn get_subject(&self) -> Result<DistinguishedName, CertificationRequestParsingError> {
        DistinguishedName::from_rasn_type(
            &self
                .certification_request
                .certification_request_info
                .subject,
        )
        .map_err(|e| {
            CertificationRequestParsingErrorKind::DecodingError.error_with_msg(&format!(
                "Failed to parse Subject Distinguished Name of PKCS#10 Certificate Request: {e:?}"
            ))
        })
    }

    /// Return the Subject Public Key Info as DER encoded bytes.
    pub fn get_encoded_subject_public_key_info(&self) -> Vec<u8> {
        rasn::der::encode(
            &self
                .certification_request
                .certification_request_info
                .subject_pk_info,
        )
        .unwrap()
    }

    fn get_attributes(&self) -> CertificationRequestInfoAttributes {
        CertificationRequestInfoAttributes::from_rasn_type(
            &self
                .certification_request
                .certification_request_info
                .attributes,
        )
    }

    /// Return the all requested [ExtendedKeyUsage]s if present.
    pub fn get_extended_key_usage(&self) -> Vec<ExtendedKeyUsage> {
        self.get_attributes()
            .get_extension_request()
            .as_ref()
            .map(ExtensionRequestAttribute::get_extended_key_usage)
            .unwrap_or_default()
    }

    /// Return the all requested [WellKnownGeneralName] if present.
    pub fn get_subject_alternative_name(&self) -> Vec<(WellKnownGeneralName, String)> {
        self.get_attributes()
            .get_extension_request()
            .as_ref()
            .map(ExtensionRequestAttribute::get_subject_alternative_name)
            .unwrap_or_default()
    }

    /// Validate the proof of possession signature.
    pub fn validate_signature(&self) -> Result<(), CertificationRequestParsingError> {
        let spki = self.get_encoded_subject_public_key_info();
        let public_key = spki.to_public_key();
        let tbs_response_data = self.get_encoded_certification_request_info();
        let (oid, signature) = self.get_encoded_signature();
        if let Some(mut se) = Tyst::instance().ses().by_oid(&oid) {
            if !se.verify(public_key.as_ref(), &signature, &tbs_response_data) {
                Err(
                    CertificationRequestParsingErrorKind::InvalidSignature.error_with_msg(
                        "CertificationRequest signature could not be validated with embedded public key.",
                    ),
                )?
            }
            return Ok(());
        }
        Err(
            CertificationRequestParsingErrorKind::InvalidSignature.error_with_msg(
                &format!("CertificationRequest was signed with an unknown/unsupported signature algorithm: '{oid}'")
            ),
        )
    }
}
