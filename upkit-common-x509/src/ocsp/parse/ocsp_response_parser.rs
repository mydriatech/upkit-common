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

//! OCSP response parsing.

use rasn::types::ObjectIdentifier;
use tyst::Tyst;

use crate::cert::types::SerialNumber;
use crate::ocsp::parse::OcspParsingError;
use crate::ocsp::parse::OcspParsingErrorKind;
use crate::ocsp::response_extensions::Nonce;
use crate::ocsp::types::OcspResponseStatus;
use crate::ocsp::types::ResponderId;
use crate::ocsp::types::SingleResponse;

/** OCSP Response parser.

[RFC 6960 4.2.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1):

```text
   OCSPResponse ::= SEQUENCE {
      responseStatus         OCSPResponseStatus,
      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }

   OCSPResponseStatus ::= ENUMERATED {
       successful            (0),  -- Response has valid confirmations
       malformedRequest      (1),  -- Illegal confirmation request
       internalError         (2),  -- Internal error in issuer
       tryLater              (3),  -- Try again later
                                   -- (4) is not used
       sigRequired           (5),  -- Must sign the request
       unauthorized          (6)   -- Request unauthorized
   }

   ResponseBytes ::=       SEQUENCE {
       responseType   OBJECT IDENTIFIER,
       response       OCTET STRING }

   For a basic OCSP responder, responseType will be id-pkix-ocsp-basic.

   id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
   id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }


   BasicOCSPResponse       ::= SEQUENCE {
      tbsResponseData      ResponseData,
      signatureAlgorithm   AlgorithmIdentifier,
      signature            BIT STRING,
      certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

   ResponseData ::= SEQUENCE {
      version              [0] EXPLICIT Version DEFAULT v1,
      responderID              ResponderID,
      producedAt               GeneralizedTime,
      responses                SEQUENCE OF SingleResponse,
      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
```

The following response extensions are (currently) not supported:

* [RFC 6960 4.4.2](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.2) CRL References. (Few OCSP responders serve data from CRLs.)
* [RFC 6960 4.4.4](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.4) Archive Cutoff. (Unclear if this is relevant.)

*/
#[derive(Clone)]
pub struct OcspResponseParser {
    ocsp_response: rasn_ocsp::OcspResponse,
    basic_ocsp_response: Option<rasn_ocsp::BasicOcspResponse>,
}

impl OcspResponseParser {
    // iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(48) id-ad-ocsp(1) id-pkix-ocsp-basic(1)
    const OID_PKIX_OCSP_BASIC: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1];

    /// Create a new instance from `encoded_ocsp_response` bytes.
    pub fn from_bytes(encoded_ocsp_response: &[u8]) -> Result<Self, OcspParsingError> {
        rasn::der::decode::<rasn_ocsp::OcspResponse>(encoded_ocsp_response)
            .map_err(|e| {
                let msg = format!(
                    "Error while decoding data. kind: '{:?}', codec: '{:?}'",
                    e.kind, e.codec
                );
                OcspParsingErrorKind::DecodingError.error_with_msg(&msg)
            })
            .map(|ocsp_response| {
                let basic_ocsp_response =
                    Self::extract_basic_ocsp_response(ocsp_response.bytes.as_ref());
                Self {
                    ocsp_response,
                    basic_ocsp_response,
                }
            })
    }

    /// Return the overall request status.
    pub fn get_response_status(&self) -> OcspResponseStatus {
        OcspResponseStatus::from_rasn_type(&self.ocsp_response.status)
    }

    fn extract_basic_ocsp_response(
        response_bytes: Option<&rasn_ocsp::ResponseBytes>,
    ) -> Option<rasn_ocsp::BasicOcspResponse> {
        response_bytes.as_ref().and_then(|response_bytes| {
            if response_bytes.r#type.eq(&ObjectIdentifier::new_unchecked(
                Self::OID_PKIX_OCSP_BASIC.to_vec().into(),
            )) {
                rasn::der::decode::<rasn_ocsp::BasicOcspResponse>(&response_bytes.response).ok()
            } else {
                None
            }
        })
    }

    /// Return the part of the OCSP Response that is covered by the signature
    /// as DER encoded bytes.
    pub fn get_encoded_tbs_response_data(&self) -> Option<Vec<u8>> {
        self.basic_ocsp_response
            .as_ref()
            .map(|basic_ocsp_response| {
                rasn::der::encode(&basic_ocsp_response.tbs_response_data).unwrap()
            })
    }

    /// Return the signature OID and data as DER encoded bytes.
    ///
    /// NOTE: This currently ignores the signature parameters.
    pub fn get_encoded_signature(&self) -> Option<(String, Vec<u8>)> {
        self.basic_ocsp_response
            .as_ref()
            .map(|basic_ocsp_response| {
                let oid = crate::encdec::rasn::algorithm_identifier_as_oid(
                    &basic_ocsp_response.signature_algorithm,
                );
                let oid_string = tyst::encdec::oid::as_string(&oid);
                (
                    oid_string,
                    basic_ocsp_response.signature.as_raw_slice().to_vec(),
                )
            })
    }

    /// Return the OCSP signing certificate chain if present (order is not guaranteed).
    pub fn get_certificates(&self) -> Vec<Vec<u8>> {
        self.basic_ocsp_response
            .as_ref()
            .and_then(|basic_ocsp_response| {
                basic_ocsp_response.certs.as_ref().map(|certs| {
                    certs
                        .iter()
                        .map(|cert| rasn::der::encode(cert).unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .unwrap_or_default()
    }

    fn get_response_data(&self) -> Option<&rasn_ocsp::ResponseData> {
        self.basic_ocsp_response
            .as_ref()
            .map(|basic_ocsp_response| &basic_ocsp_response.tbs_response_data)
    }

    /// Return the OCSP responder identifier.
    pub fn get_responder_id(&self) -> Option<ResponderId> {
        self.get_response_data()
            .map(|response_data| &response_data.responder_id)
            .map(ResponderId::from_rasn_type)
    }

    /// Return the time at which the OCSP responder signed this response in
    /// epoch seconds.
    ///
    /// See also [RFC 6960 2.4](https://www.rfc-editor.org/rfc/rfc6960#section-2.4).
    pub fn get_produced_at(&self) -> Option<u64> {
        self.get_response_data()
            .map(|response_data| u64::try_from(response_data.produced_at.timestamp()).unwrap())
    }

    /// Return the list of responses for all certificates that were requested.
    ///
    /// Additional responses could be present as stated in
    /// [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.3).
    pub fn get_responses(&self) -> Vec<SingleResponse> {
        self.get_response_data()
            .map(|response_data| {
                response_data
                    .responses
                    .iter()
                    .map(SingleResponse::from_rasn_type)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// If present, return the single response for the unique
    /// issuer and serial_number combination.
    pub fn get_single_response_by_serial_number(
        &self,
        encoded_issuer_subject_dn: &[u8],
        serial_number: &SerialNumber,
    ) -> Option<SingleResponse> {
        self.get_responses()
            .iter()
            .find(|single_respons| {
                let cert_id = single_respons.get_cert_id();
                // Hash DN and compare
                // It's a little inefficient if all responses are from the same issuer, but in reality there is usually
                // a single SingleResponse per OCSP Response..
                let digest_algorithm_oid = single_respons.get_cert_id().get_hash_algorithm();
                if let Some(mut digest) =                 Tyst::instance()
                .digests()
                .by_oid(&digest_algorithm_oid) {
                    let hash = digest.hash(encoded_issuer_subject_dn);
                    // Compare issuer, serial number
                    cert_id.get_issuer_name_hash().eq(&hash)
                        && cert_id.get_serial_number().eq(serial_number)
                } else {
                    log::warn!("Unsupported hash algorithm '{digest_algorithm_oid}' used to calculate issuerNameHash in OCSP response.");
                    false
                }
            })
            .cloned()
    }

    /// Return the first encountered response extension with a matching OID.
    fn get_first_response_extension_by_oid(&self, oid: &[u32]) -> Option<rasn_pkix::Extension> {
        self.get_response_data().and_then(|response_data| {
            response_data
                .response_extensions
                .as_ref()
                .and_then(|extensions| crate::encdec::rasn::first_extension_by_oid(extensions, oid))
        })
    }

    /// Return [Nonce] extension when present.
    pub fn get_nonce(&self) -> Option<Nonce> {
        self.get_first_response_extension_by_oid(Nonce::OID)
            .map(|extension| rasn::der::decode::<rasn_ocsp::Nonce>(&extension.extn_value).unwrap())
            .as_ref()
            .map(Nonce::from_rasn_type)
    }

    /// Return `true` if the OCSP responder will respond with "revoked" (with
    /// undefined reason) for non-issued certificates.
    ///
    /// The Extended Revoke Definition is defined in
    /// [RFC 6960 4.4.8](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.8).
    pub fn is_extended_revoke_definition(&self) -> bool {
        // iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(48) id-ad-ocsp(1) id-pkix-ocsp-extended-revoke(9)
        const OID: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 9];
        self.get_first_response_extension_by_oid(OID).is_some()
    }
}
