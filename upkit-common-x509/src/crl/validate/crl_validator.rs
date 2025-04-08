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

//! CRL validation.

use crate::cert::parse::CertificateParser;
use crate::cert::validate::{CertificateValidationError, CertificateValidationErrorKind};
use crate::crl::crl_entry_extensions::ReasonCode;
use crate::crl::parse::CrlParser;
use tyst::traits::se::ToPublicKey;
use tyst::Tyst;

/** Certificate CRL validator.

Validate that:

* The AKI of the CRL matches the issuer SKI.
* The CRL is signed by the issuer.
* The CRL is valid at the requested epoch point in time.
* The CDP of the leaf matches the IDP of the CRL.
* Return the revocation status of the leaf certificate by checking if the serial number is present in the CRL.

*/
pub struct CertificateCrlValidator {}

impl CertificateCrlValidator {
    /// Return the `leaf`'s [ReasonCode] if the certficate is present in the CRL.
    /// Error out if the certificate or CRL was not trusted or malformed.
    pub fn validate(
        issuer: &CertificateParser,
        leaf: &CertificateParser,
        crl: &CrlParser,
        point_in_time_epoch_seconds: u64,
    ) -> Result<Option<ReasonCode>, CertificateValidationError> {
        Self::validate_crl_issuance(issuer, leaf.get_crl_distribution_point(), crl)?;
        // The CRL is valid at the requested epoch point in time.
        if !crl.is_valid_at(point_in_time_epoch_seconds) {
            Err(CertificateValidationErrorKind::InvalidLifeSpan
                .error_with_msg("CRL is not valid at requested point in time."))?
        }
        // Return the revocation status of the leaf certificate by checking if the serial number is present in the CRL.
        Ok(crl
            .get_certificate_status(leaf.get_serial_number())
            .and_then(|(reason, invalid_from_epoch_seconds)| {
                if point_in_time_epoch_seconds >= invalid_from_epoch_seconds {
                    Some(reason)
                } else {
                    None
                }
            }))
    }

    /// Error out if the certificate or CRL was not trusted or malformed.
    pub fn validate_crl_issuance(
        issuer: &CertificateParser,
        cdp: Option<String>,
        crl: &CrlParser,
    ) -> Result<(), CertificateValidationError> {
        // The AKI of the CRL matches the issuer SKI.
        if let Some(crl_aki) = crl.get_authority_key_identifier_kid() {
            if let Some(issuer_ski) = issuer.get_subject_key_identifier_kid() {
                if !crl_aki.eq(&issuer_ski) {
                    Err(CertificateValidationErrorKind::CertificateParsingError
                        .error_with_msg("Issuer SKI does not match CRL AKI."))?
                }
            } else {
                Err(CertificateValidationErrorKind::CertificateParsingError
                    .error_with_msg("Issuer SKI is missing while CRL AKI exists."))?
            }
        }
        // The CDP of the leaf matches the IDP of the CRL.
        if let Some(cdp) = cdp {
            match crl.get_issuing_distribution_point() {
                Ok(Some(idp)) => {
                    if !cdp.eq(&idp) {
                        Err(CertificateValidationErrorKind::CertificateParsingError
                            .error_with_msg("CRL IDP does not match certificate CDP."))?
                    }
                }
                Ok(None) => {}
                Err(e) => Err(CertificateValidationErrorKind::CertificateParsingError
                    .error_with_msg(&format!("Failed to parse CRL for certificate: {e:?}")))?,
            }
        }
        // Validate signature of CRL
        let spki = issuer.get_encoded_subject_public_key_info();
        let public_key = spki.to_public_key();
        let tbs_cert_list = crl.get_encoded_tbs_cert_list();
        let (oid, signature) = crl.get_encoded_signature();
        if let Some(mut se) = Tyst::instance().ses().by_oid(&oid) {
            if !se.verify(public_key.as_ref(), &signature, &tbs_cert_list) {
                Err(
                    CertificateValidationErrorKind::InvalidSignature.error_with_msg(
                        "CRL signature could not be validated with issuer certificate.",
                    ),
                )?
            }
        }
        Ok(())
    }
}
