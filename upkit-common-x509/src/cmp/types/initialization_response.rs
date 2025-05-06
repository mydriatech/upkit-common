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

use crate::cert::parse::CertificateParser;
use crate::cmp::asn1;
use crate::cmp::error::CmpProcessingError;
use crate::cmp::error::CmpProcessingErrorKind;

/// Single certificate initialization response.
pub struct InitializationResponse {
    first_certificate: CertificateParser,
    ca_certs: Vec<CertificateParser>,
}

impl InitializationResponse {
    /// Return the issued certificate.
    pub fn get_certificate(&self) -> &CertificateParser {
        &self.first_certificate
    }

    /** Get CA certificates.

    [RFC 4210 5.3.2](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.2):

    ```text
    If the PKI Message Protection is "shared secret information" ..., then any
    certificate transported in the caPubs field may be directly trusted as a
    root CA certificate by the initiator.
    ```
    */
    pub fn get_ca_certificates(&self) -> &[CertificateParser] {
        &self.ca_certs
    }

    /*
    pub fn from_pki_body(pki_body: &PkiBody) -> Option<Self> {
        if let PkiBody::Ip(cert_rep_message) = pki_body {
            Self::from_rasn_type(cert_rep_message)
        } else {
            panic!("Only init from 'ip' is possible here.")
        }
    }
    */

    /// Return a new instance from the provided `rasn` type.
    pub fn from_rasn_type(
        cert_rep_message: &asn1::CertRepMessage,
    ) -> Result<Self, CmpProcessingError> {
        let ca_pubs = cert_rep_message
            .ca_pubs
            .as_ref()
            .map(|ca_certs| {
                ca_certs
                    .iter()
                    .flat_map(|ca_cert| {
                        rasn::der::encode(ca_cert)
                            .map_err(|e| {
                                log::debug!("Failed to DER-encode CA certificate: {e:?}");
                            })
                            .ok()
                            .and_then(|encoded_certificate| {
                                if log::log_enabled!(log::Level::Trace) {
                                    log::trace!(
                                        "encoded_certificate: {}",
                                        tyst::encdec::base64::encode(&encoded_certificate)
                                    );
                                }
                                CertificateParser::from_bytes(&encoded_certificate)
                                    .map_err(|e| {
                                        log::debug!("Failed to parse CA certificate: {e:?}");
                                    })
                                    .ok()
                            })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if cert_rep_message.response.is_empty() {
            Err(CmpProcessingErrorKind::BadResponse.error_with_msg(
                "Initialization response should not contain an empty list of certificates.",
            ))?;
        }
        if cert_rep_message.response.len() > 1 {
            Err(CmpProcessingErrorKind::NotImplemented
                .error_with_msg("This implementation does not support batched requests."))?;
        }
        let cert_response = cert_rep_message.response.first().unwrap();
        let status_code = crate::encdec::rasn::integer_as_usize(
            &(cert_response.status.status.clone() as rasn::types::Integer),
        );
        if status_code == 0 || status_code == 1 {
            if let Some(certified_key_pair) = &cert_response.certified_key_pair {
                if let crate::cmp::asn1::CertOrEncCert::Certificate(cmp_certificate) =
                    &certified_key_pair.cert_or_enc_cert
                {
                    let encoded_certificate = rasn::der::encode(cmp_certificate.as_ref()).unwrap();
                    let first_certificate = CertificateParser::from_bytes(&encoded_certificate)
                        .map_err(|e| {
                            CmpProcessingErrorKind::BadResponse
                                .error_with_msg(&format!("Unable to parse CMP response: {e:?}"))
                        })?;
                    Ok(Self {
                        first_certificate,
                        ca_certs: ca_pubs,
                    })
                } else {
                    Err(CmpProcessingErrorKind::NotImplemented.error_with_msg(
                        "Only support for non-encrypted certificate are currently supported.",
                    ))
                }
            } else {
                Err(CmpProcessingErrorKind::BadResponse
                    .error_with_msg("Unable to get CertificateKeyPair from response."))
            }
        } else {
            Err(CmpProcessingErrorKind::BadResponse.error_with_msg("Unable to process initialization response that is not direct 'accepted' or 'grantedWithMods'."))
        }
    }
}
