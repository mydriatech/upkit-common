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

//! OCSP request builder.

use crate::cert::parse::CertificateParser;
use crate::ocsp::request_extensions::{AcceptableResponses, Nonce, PreferredSignatureAlgorithms};
use crate::ocsp::types::SingleRequest;
use tyst::Tyst;

/** OCSP request.

*/
pub struct OcspRequest {
    ocsp_request: Vec<u8>,
}

impl OcspRequest {
    /// Return a new instance.
    ///
    /// The `digest_algorithm_oid` is used to create the
    /// [CertId](crate::ocsp::types::CertId).
    pub fn new(
        leaf: &CertificateParser,
        issuer: &CertificateParser,
        digest_algorithm_oid: &[u32],
        include_nonce: bool,
    ) -> Self {
        let mut digest = Tyst::instance()
            .digests()
            .by_oid(&tyst::encdec::oid::as_string(digest_algorithm_oid))
            .unwrap();
        let issuer_name_hash = digest.hash(&leaf.get_encoded_issuer());
        let issuer_key_hash = digest.hash(&issuer.get_encoded_subject_public_key_info());
        let serial_number = leaf.get_serial_number();
        let mut request_extensions = vec![
            AcceptableResponses::default().to_rasn_extension(),
            // TODO: Grab signature algorithm used to issue leaf cert
            PreferredSignatureAlgorithms::default().to_rasn_extension(),
        ];
        if include_nonce {
            request_extensions.push(Nonce::generate(None).to_rasn_extension());
        }
        let request_extensions = if request_extensions.is_empty() {
            None
        } else {
            Some(request_extensions.into())
        };
        let ocsp_request = rasn_ocsp::OcspRequest {
            tbs_request: rasn_ocsp::TbsRequest {
                version: 1.into(),
                requestor_name: None,
                request_list: vec![
                    SingleRequest::new(
                        digest_algorithm_oid,
                        &issuer_name_hash,
                        &issuer_key_hash,
                        &serial_number,
                    )
                    .to_rasn_type(),
                ],
                request_extensions,
            },
            optional_signature: None,
        };
        Self {
            ocsp_request: rasn::der::encode(&ocsp_request).unwrap(),
        }
    }

    /// Return the DER encoded object as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.ocsp_request
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> rasn_ocsp::OcspRequest {
        rasn::der::decode(&self.ocsp_request).unwrap()
    }
}
