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

//! OCSP response validation.

use std::sync::Arc;

use crate::cert::parse::CertificateParser;
use crate::cert::validate::checkers::OcspNoCheckChecker;
use crate::cert::validate::CertificatePathValidator;
use crate::cert::validate::CertificateValidationError;
use crate::cert::validate::CertificateValidationErrorKind;
use crate::crl::crl_entry_extensions::ReasonCode;
use crate::ocsp::parse::OcspRequestParser;
use crate::ocsp::parse::OcspResponseParser;
use crate::ocsp::types::OcspResponseStatus;
use tyst::encdec::hex::ToHex;
use tyst::traits::se::ToPublicKey;
use tyst::Tyst;

/// Certificate validation using an OCSP response.
pub struct CertificateOcspValidator {}

impl CertificateOcspValidator {
    /// Return the `leaf`'s [ReasonCode] if the certficate is present in the
    /// OCSP response.
    /// Error out if the certificate or OCSP response was not trusted or
    /// malformed.
    pub fn validate(
        issuer: &CertificateParser,
        leaf: &CertificateParser,
        ocsp_response: &OcspResponseParser,
        point_in_time_epoch_seconds: u64,
    ) -> Result<Option<ReasonCode>, CertificateValidationError> {
        Self::validate_issuance(issuer, ocsp_response)?;
        let single_response = ocsp_response.get_single_response_by_serial_number(
            &issuer.get_encoded_subject(),
            &leaf.get_serial_number(),
        );
        if let Some(single_response) = single_response {
            // Assert that the OCSP response is valid at the requested epoch point in time.
            if !single_response.is_valid_at(point_in_time_epoch_seconds) {
                Err(CertificateValidationErrorKind::InvalidLifeSpan
                    .error_with_msg("OCSP Response is not valid at requested point in time."))?
            }
            // Return the revocation status of the leaf certificate by checking if the serial number is present in the CRL.
            Ok(single_response.get_certificate_status().and_then(
                |(reason, invalid_from_epoch_seconds)| {
                    if point_in_time_epoch_seconds >= invalid_from_epoch_seconds {
                        Some(reason)
                    } else {
                        None
                    }
                },
            ))
        } else {
            todo!()
        }
    }

    /// Error out if the certificate or OCSP response was not trusted or
    /// malformed.
    pub fn validate_issuance(
        issuer: &CertificateParser,
        ocsp_response: &OcspResponseParser,
    ) -> Result<(), CertificateValidationError> {
        // Validate that we have successful response
        if !OcspResponseStatus::Successful.eq(&ocsp_response.get_response_status()) {
            Err(CertificateValidationErrorKind::IncompleteData
                .error_with_msg("OCSP response was unsuccessful."))?
        }
        // Is delegated OCSP signing in use? If, so validate path first..
        // If there are cert, ther should be exactly one OCSP signing cert and this should have been issued by the "issuer"
        let ocsp_signing_certificates = ocsp_response
            .get_certificates()
            .iter()
            .map(|encoded_cert| CertificateParser::from_bytes(encoded_cert).unwrap())
            .filter(|cp| {
                cp.get_extended_key_usage()
                    .contains(&crate::cert::extensions::ExtendedKeyUsage::PkixOcspSigning)
                    && cp
                        .get_basic_constraints()
                        .is_none_or(|basic_constraints| basic_constraints.is_leaf())
            })
            .collect::<Vec<_>>();
        let mut ocsp_issuer = issuer;
        match ocsp_signing_certificates.len().cmp(&1) {
            std::cmp::Ordering::Less => {
                // All good. OCSP Response is supposedly signed directly by CA cert.
            },
            std::cmp::Ordering::Equal => {
                // Verify that the OCSP signing cert is trusted
                let cpv = CertificatePathValidator::new(vec![issuer.to_bytes().unwrap()])
                    .unwrap()
                    .add_standard_extension_checkers()
                    .add_extension_checkers(vec![Arc::new(OcspNoCheckChecker::default())])
                    ;
                let ocsp_signing_cert = ocsp_signing_certificates.first().unwrap();
                cpv.validate(
                    vec![ocsp_signing_cert.to_bytes().unwrap()],
                    ocsp_response.get_produced_at().unwrap(),
                    vec![],
                )?;
                ocsp_issuer = ocsp_signing_cert;
            },
            std::cmp::Ordering::Greater => {
                Err(
                    CertificateValidationErrorKind::InvalidSignature.error_with_msg(
                        "OCSP response contains more than one leaf OCSP signing certificate. Not sure how to handle this.",
                    ),
                )?
            }
        }
        // Validate signature of OCSP Response
        let spki = ocsp_issuer.get_encoded_subject_public_key_info();
        let public_key = spki.to_public_key();
        if let Some(tbs_response_data) = ocsp_response.get_encoded_tbs_response_data() {
            if let Some((oid, signature)) = ocsp_response.get_encoded_signature() {
                if let Some(mut se) = Tyst::instance().ses().by_oid(&oid) {
                    if !se.verify(public_key.as_ref(), &signature, &tbs_response_data) {
                        Err(
                            CertificateValidationErrorKind::InvalidSignature.error_with_msg(
                                "OCSP response signature could not be validated with issuer certificate.",
                            ),
                        )?
                    }
                }
            } else {
                Err(CertificateValidationErrorKind::InvalidSignature
                    .error_with_msg("OCSP response is missing signature."))?
            }
        } else {
            Err(CertificateValidationErrorKind::InvalidSignature
                .error_with_msg("OCSP response is missing TBSResponseData."))?
        }
        Ok(())
    }

    /// Validate that the OCSP response was for the provided OCSP request.
    pub fn validate_response_to_request(
        ocsp_request: &OcspRequestParser,
        ocsp_response: &OcspResponseParser,
    ) -> Result<(), CertificateValidationError> {
        if let Some(nonce_resp) = ocsp_response.get_nonce() {
            if let Some(nonce_req) = ocsp_request.get_nonce() {
                if !nonce_req.eq(&nonce_resp) {
                    Err(CertificateValidationErrorKind::InvalidSignature
                        .error_with_msg("OCSP request and response nonces do not match."))?
                }
            } else {
                Err(CertificateValidationErrorKind::InvalidSignature
                    .error_with_msg("OCSP response has a nonce that is not present in request."))?
            }
        }
        let single_responses = ocsp_response.get_responses();
        let single_requests = ocsp_request.get_request_list();
        let cert_ids_in_response = single_responses
            .into_iter()
            .map(|single_response| single_response.get_cert_id().to_owned())
            .collect::<Vec<_>>();
        let cert_ids_in_request = single_requests
            .into_iter()
            .map(|single_request| single_request.get_req_cert().to_owned())
            .collect::<Vec<_>>();
        let missing_request = cert_ids_in_request.iter().find(|requested_cert_id| {
            !cert_ids_in_response
                .iter()
                .any(|responded_cert_id| responded_cert_id.eq(requested_cert_id))
        });
        if let Some(missing_request) = missing_request {
            Err(CertificateValidationErrorKind::IncompleteData
                .error_with_msg(&format!(
                    "OCSP request for issuerNameHash '{}' and serialNumber '{:?}' is missing in response.",
                    missing_request.get_issuer_name_hash().to_hex(),
                    missing_request.get_serial_number()
                )))?
        }
        Ok(())
    }
}
