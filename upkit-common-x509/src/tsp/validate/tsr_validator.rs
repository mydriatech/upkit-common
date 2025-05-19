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

//! Time-Stamp response validation.

use crate::cert::extensions::ExtendedKeyUsage;
use crate::cert::parse::CertificateParser;
use crate::cert::validate::CertificatePathValidator;
use crate::cert::validate::CertificateValidationError;
use crate::cert::validate::CertificateValidationErrorKind;
use crate::cert::validate::checkers::ExtendedKeyUsageChecker;
use crate::crl::crl_entry_extensions::ReasonCode;
use crate::crl::parse::CrlParser;
use crate::crl::validate::CertificateCrlValidator;
use crate::ocsp::parse::OcspResponseParser;
use crate::ocsp::validate::CertificateOcspValidator;
use crate::tsp::parse::{TimeStampReqParser, TimeStampRespParser};
use std::sync::Arc;

/// Time-Stamp response validator.
pub struct TimeStampResponseValidator {}

impl TimeStampResponseValidator {
    /// Validate the time stamp response at the time claimed in the time-stamp.
    ///
    /// Validates that any bundled certificates can build a chain from TS
    /// signature to trust anchor.
    ///
    /// All certificates and any bundlded revocation info is evaluated at the
    /// time of the time-stamp.
    ///
    /// NOTE: It is recommended by
    /// [RFC 3161 4](https://www.rfc-editor.org/rfc/rfc3161#section-4) to also
    /// check the revocation status to detect a later discovered key compromize.
    /// This function will not try to  retrieve additional revocation info.
    pub fn validate_at_point_of_timestamp(
        trusted_anchors_der: Vec<Vec<u8>>,
        encoded_time_stamp_resp: &[u8],
    ) -> Result<(), CertificateValidationError> {
        // Parse timestamp
        let time_stamp_resp = TimeStampRespParser::from_bytes(encoded_time_stamp_resp).unwrap();
        let time_stamp_token = time_stamp_resp.get_time_stamp_token().ok_or(
            CertificateValidationErrorKind::IncompleteData
                .error_with_msg("Missing TimeStampToken in response."),
        )?;
        let tst_info = time_stamp_token.get_tst_info().ok_or(
            CertificateValidationErrorKind::IncompleteData
                .error_with_msg("Missing TSTInfo in response."),
        )?;
        let at_epoch_seconds = (tst_info.get_epoch_time_micros().0 + 500_000) / 1_000_000;
        //  Get certs
        let encoded_ts_certs = time_stamp_token.get_certificates();
        //let ts_certs = time_stamp_resp.get_certificates().iter().map(|encoded_certificate|CertificateParser::from_bytes(encoded_certificate).unwrap()).collect::<Vec<_>>();
        // Sort out chain from trust anchor to leaf and
        // validate that this is a trusted chain and with an TSU signing leaf
        let cpv = CertificatePathValidator::new(trusted_anchors_der)?
            .add_standard_extension_checkers()
            .add_extension_checkers(vec![Arc::new(ExtendedKeyUsageChecker::new(&[
                ExtendedKeyUsage::PkixTimeStamping,
            ]))]);
        //let cert_chain = CertificatePathValidator::get_trusted_certificate_chain(&ts_certs, &trusted_anchors)?;
        let ts_cert_chain = cpv.validate(encoded_ts_certs, at_epoch_seconds, vec![])?;
        // Validate that the TS is signed by the leaf
        Self::validate_signatures_of_ts(ts_cert_chain.first().unwrap(), &time_stamp_resp)?;
        //  Get revocation infos
        let (encoded_crls, encoded_ocsp_responses) = time_stamp_token.get_revocation_infos();
        let crls = encoded_crls
            .iter()
            .map(|encoded_crl| CrlParser::from_bytes(encoded_crl).unwrap())
            .collect::<Vec<_>>();
        let ocsp_responses = encoded_ocsp_responses
            .iter()
            .map(|encoded_ocsp_response| {
                OcspResponseParser::from_bytes(encoded_ocsp_response).unwrap()
            })
            .collect::<Vec<_>>();
        // Match revocation info to each item in the chain
        // Validate each revocation info and check status of cert it is for
        for cert in &ts_cert_chain {
            let mut updates = vec![];
            for crl in &crls {
                if crl.get_encoded_issuer().eq(&cert.get_encoded_issuer()) {
                    if let Some(issuer) = ts_cert_chain.iter().find(|chain_cert| {
                        crl.get_encoded_issuer()
                            .eq(&chain_cert.get_encoded_subject())
                    }) {
                        let reason_code =
                            CertificateCrlValidator::validate(issuer, cert, crl, at_epoch_seconds)?;
                        updates.push((crl.get_this_update(), reason_code));
                    } else {
                        Err(CertificateValidationErrorKind::IncompleteData
                            .error_with_msg("CRL is present, but not the issuing certificate."))?
                    }
                }
            }
            for ocsp_response in &ocsp_responses {
                if let Some(single_response) = ocsp_response.get_single_response_by_serial_number(
                    &cert.get_encoded_issuer(),
                    &cert.get_serial_number(),
                ) {
                    if let Some(issuer) = ts_cert_chain.iter().find(|chain_cert| {
                        cert.get_encoded_issuer()
                            .eq(&chain_cert.get_encoded_subject())
                    }) {
                        let reason_code = CertificateOcspValidator::validate(
                            issuer,
                            cert,
                            ocsp_response,
                            at_epoch_seconds,
                        )?;
                        updates.push((single_response.get_this_update(), reason_code));
                    } else {
                        Err(CertificateValidationErrorKind::IncompleteData
                            .error_with_msg("CRL is present, but not the issuing certificate."))?
                    }
                }
            }
            // Stable sort of all updates with oldest first. Since OCSP was added last and we sort it stable, same second "unrevokes" will happen "after" the CRL update.
            updates.sort_by_key(|(this_update, _)| *this_update);
            let reason_codes_with_oldest_first = updates
                .iter()
                .map(|(_this_update, reason_code)| reason_code.to_owned())
                .collect::<Vec<_>>();
            if let Some(reason_code) =
                Self::derive_best_known_revocation_status(&reason_codes_with_oldest_first)
            {
                Err(CertificateValidationErrorKind::NotTrusted.error_with_msg(
                    &format!("Certificate with fingerprint '{}' was revoked with reason '{}' at the time of time stamp creation.",
                    cert.fingerprint(),
                    reason_code.name(),
                    )
                ))?
            }
        }
        Ok(())
    }

    /// Calculate that actual revocation state of a cert from known stats changes
    fn derive_best_known_revocation_status(
        reason_codes_with_oldest_first: &[Option<ReasonCode>],
    ) -> Option<ReasonCode> {
        let mut ret = None;
        for reason_code in reason_codes_with_oldest_first {
            match reason_code {
                Some(ReasonCode::CertificateHold) => {
                    // Certificate was put on hold
                    ret = reason_code.to_owned();
                }
                Some(ReasonCode::RemoveFromCrl) | None => {
                    // Certificate is no longer revoked
                    ret = None;
                }
                Some(_permant_reason) => {
                    // Certificate was permanently revoked
                    ret = reason_code.to_owned();
                    break;
                }
            }
        }
        ret
    }

    /// Validate signatures in chain.
    ///
    /// The signature of the last position in the chain is assumed to be trusted.
    fn validate_signatures_of_ts(
        ts_certificate: &CertificateParser,
        time_stamp_resp: &TimeStampRespParser,
    ) -> Result<(), CertificateValidationError> {
        let time_stamp_token = time_stamp_resp.get_time_stamp_token().ok_or(
            CertificateValidationErrorKind::IncompleteData
                .error_with_msg("Missing TimeStampToken in response."),
        )?;
        if !time_stamp_token.is_signed_by_certificate(ts_certificate) {
            Err(
                CertificateValidationErrorKind::InvalidSignature.error_with_msg(&format!(
                    "Unable to verify TS signature using signing cert with fp '{}'.",
                    ts_certificate.fingerprint(),
                )),
            )?;
        }
        Ok(())
    }

    /// Check that the response matches the request.
    pub fn validate_response_to_request(
        encoded_time_stamp_req: &[u8],
        encoded_time_stamp_resp: &[u8],
    ) -> Result<(), CertificateValidationError> {
        let time_stamp_req =
            TimeStampReqParser::from_bytes(encoded_time_stamp_req).map_err(|e| {
                CertificateValidationErrorKind::IncompleteData
                    .error_with_msg(&format!("Unable to parse Time-Stamp response: {e:?}"))
            })?;
        let time_stamp_resp =
            TimeStampRespParser::from_bytes(encoded_time_stamp_resp).map_err(|e| {
                CertificateValidationErrorKind::IncompleteData
                    .error_with_msg(&format!("Unable to parse Time-Stamp response: {e:?}"))
            })?;
        let time_stamp_token = time_stamp_resp.get_time_stamp_token().ok_or(
            CertificateValidationErrorKind::IncompleteData
                .error_with_msg("Time-Stamp response is missing TimeStampToken."),
        )?;
        let tst_info = time_stamp_token.get_tst_info().ok_or(
            CertificateValidationErrorKind::IncompleteData
                .error_with_msg("TimeStampToken is missing TSTInfo."),
        )?;
        // The messageImprint should be the same in the request as in the response
        if !time_stamp_req
            .get_encoded_message_imprint()
            .eq(&tst_info.get_encoded_message_imprint())
        {
            Err(CertificateValidationErrorKind::IncompleteData
                    .error_with_msg("Time-Stamp response is for a different messageImprint than the Time-Stamp request."))?;
        }
        // If certReq should be respected
        if time_stamp_req.get_cert_req() {
            if time_stamp_token.get_certificates().is_empty() {
                Err(CertificateValidationErrorKind::IncompleteData
                    .error_with_msg("Time-Stamp response should have certificates as requested in Time-Stamp request."))?;
            }
        } else if !time_stamp_token.get_certificates().is_empty() {
            Err(CertificateValidationErrorKind::IncompleteData
                .error_with_msg("Time-Stamp response should not have certificates as requested in Time-Stamp request."))?;
        }
        // If a policy is requested, response MUST have the same or respond with rejected
        if time_stamp_req
            .get_req_policy_oid()
            .is_some_and(|policy_oid| {
                !policy_oid.eq(&tyst::encdec::oid::as_string(&tst_info.get_policy()))
            })
        {
            Err(CertificateValidationErrorKind::IncompleteData
                .error_with_msg("Time-Stamp request should have been rejected, since response policy OID is not the requested one."))?;
        }
        // If nonce is present in request, it MUST also be present in the response
        if let Some(nonce_req) = time_stamp_req.get_nonce() {
            if let Some(nonce_resp) = tst_info.get_nonce() {
                if !nonce_req.eq(nonce_resp) {
                    Err(
                        CertificateValidationErrorKind::IncompleteData.error_with_msg(
                            "Time-Stamp response is not for this requests: Nonces do no match.",
                        ),
                    )?;
                }
            } else {
                Err(CertificateValidationErrorKind::IncompleteData
                    .error_with_msg("Time-Stamp response is missing requested nonce."))?;
            }
        }
        Ok(())
    }
}
