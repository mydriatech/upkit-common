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

//! OCSP request parsing.

use crate::cert::types::WellKnownGeneralName;
use crate::ocsp::parse::OcspParsingError;
use crate::ocsp::parse::OcspParsingErrorKind;
use crate::ocsp::request_extensions::AcceptableResponses;
use crate::ocsp::request_extensions::Nonce;
use crate::ocsp::request_extensions::PreferredSignatureAlgorithms;
use crate::ocsp::types::SingleRequest;

/** OCSP Request parser.

[RFC 6960 4.1.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1):

```text

   OCSPRequest     ::=     SEQUENCE {
       tbsRequest                  TBSRequest,
       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

   TBSRequest      ::=     SEQUENCE {
       version             [0]     EXPLICIT Version DEFAULT v1,
       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
       requestList                 SEQUENCE OF Request,
       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }

   Signature       ::=     SEQUENCE {
       signatureAlgorithm      AlgorithmIdentifier,
       signature               BIT STRING,
       certs               [0] EXPLICIT SEQUENCE OF Certificate
   OPTIONAL}

   Version         ::=             INTEGER  {  v1(0) }

   Request         ::=     SEQUENCE {
       reqCert                     CertID,
       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }

   CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
       serialNumber        CertificateSerialNumber }
```

This implementation will ignore the `ServiceLocator` request extensions outlined
in [RFC 6960 4.4.6](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.6).
`CertID` would normally be sufficient for partitioning and routing, but open an
issue this is not the case for you.

OCSP request signing is not (yet) supported.
*/
#[derive(Clone)]
pub struct OcspRequestParser {
    ocsp_request: rasn_ocsp::OcspRequest,
}

impl OcspRequestParser {
    /// Create a new instance from `encoded_ocsp_request` bytes.
    pub fn from_bytes(encoded_ocsp_request: &[u8]) -> Result<Self, OcspParsingError> {
        rasn::der::decode::<rasn_ocsp::OcspRequest>(encoded_ocsp_request)
            .map_err(|e| {
                let msg = format!(
                    "Error while decoding data. kind: '{:?}', codec: '{:?}'",
                    e.kind, e.codec
                );
                OcspParsingErrorKind::DecodingError.error_with_msg(&msg)
            })
            .map(|ocsp_request| Self { ocsp_request })
    }

    /// Return the signature OID and data as DER encoded bytes.
    ///
    /// NOTE: This currently ignores the signature parameters.
    pub fn get_encoded_signature(&self) -> Option<(String, Vec<u8>, Vec<Vec<u8>>)> {
        self.ocsp_request
            .optional_signature
            .as_ref()
            .map(|signature| {
                let oid = crate::encdec::rasn::algorithm_identifier_as_oid(
                    &signature.signature_algorithm,
                );
                let oid_string = tyst::encdec::oid::as_string(&oid);
                let encoded_certificates = signature
                    .certs
                    .as_ref()
                    .map(|v| {
                        v.iter()
                            .map(|cert| rasn::der::encode(cert).unwrap())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                (
                    oid_string,
                    signature.signature.as_raw_slice().to_vec(),
                    encoded_certificates,
                )
            })
    }

    /// Indicates the name of the OCSP requestor.
    pub fn get_requestor_name(&self) -> Option<(WellKnownGeneralName, String)> {
        self.ocsp_request
            .tbs_request
            .requestor_name
            .as_ref()
            .and_then(WellKnownGeneralName::from_rasn_type)
    }

    /// Get a list of certificate pointers that status is requested for.
    pub fn get_request_list(&self) -> Vec<SingleRequest> {
        self.ocsp_request
            .tbs_request
            .request_list
            .iter()
            .map(SingleRequest::from_rasn_type)
            .collect()
    }

    /// Return the first encountered request extension with a matching OID.
    fn get_first_request_extension_by_oid(&self, oid: &[u32]) -> Option<rasn_pkix::Extension> {
        self.ocsp_request
            .tbs_request
            .request_extensions
            .as_ref()
            .and_then(|extensions| crate::encdec::rasn::first_extension_by_oid(extensions, oid))
    }

    /// Return the type of response messages that are acceptable to the OCSP
    /// client.
    ///
    /// It is expected to only contain the `id-pkix-ocsp-basic` OID when the
    /// extension is present.
    ///
    /// See [AcceptableResponses] for details.
    pub fn get_acceptable_response_types(&self) -> AcceptableResponses {
        self.get_first_request_extension_by_oid(AcceptableResponses::OID)
            .map(AcceptableResponses::from_rasn_extension)
            .unwrap_or_default()
    }

    /// Preferred Signature Algorithms by the OCSP client.
    ///
    /// See [PreferredSignatureAlgorithms] for details.
    pub fn get_preferred_signature_algorithms(&self) -> PreferredSignatureAlgorithms {
        self.get_first_request_extension_by_oid(PreferredSignatureAlgorithms::OID)
            .map(PreferredSignatureAlgorithms::from_rasn_extension)
            .unwrap_or_default()
    }

    /// Return the [Nonce] that the can be used to corrolate this request with a
    /// response later.
    pub fn get_nonce(&self) -> Option<Nonce> {
        self.get_first_request_extension_by_oid(Nonce::OID)
            .map(Nonce::from_rasn_extension)
    }
}
