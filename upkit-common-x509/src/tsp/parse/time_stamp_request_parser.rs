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

//! Time-Stamp request parsing.

pub use crate::tsp::parse::TimeStampParsingError;
pub use crate::tsp::parse::TimeStampParsingErrorKind;
use crate::tsp::tsp_asn1 as asn1;
pub use crate::tsp::types::PkiFailureInfo;
pub use crate::tsp::types::PkiStatus;
pub use crate::tsp::types::TimeStampToken;
use rasn::types::Integer;

/** Time-Stamp request parser.

[RFC 3161 2.4.1](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1):

```text
   TimeStampReq ::= SEQUENCE  {
      version                      INTEGER  { v1(1) },
      messageImprint               MessageImprint,
        --a hash algorithm OID and the hash value of the data to be
        --time-stamped
      reqPolicy             TSAPolicyId              OPTIONAL,
      nonce                 INTEGER                  OPTIONAL,
      certReq               BOOLEAN                  DEFAULT FALSE,
      extensions            [0] IMPLICIT Extensions  OPTIONAL  }

   MessageImprint ::= SEQUENCE  {
        hashAlgorithm                AlgorithmIdentifier,
        hashedMessage                OCTET STRING  }

   TSAPolicyId ::= OBJECT IDENTIFIER
```
*/
#[derive(Clone)]
pub struct TimeStampReqParser {
    time_stamp_req: asn1::TimeStampReq,
}
impl TimeStampReqParser {
    /// Create a new instance from `encoded_time_stamp_req` bytes.
    pub fn from_bytes(encoded_time_stamp_req: &[u8]) -> Result<Self, TimeStampParsingError> {
        rasn::der::decode::<asn1::TimeStampReq>(encoded_time_stamp_req)
            .map_err(|e| {
                let msg = format!(
                    "Error while decoding data. kind: '{:?}', codec: '{:?}'",
                    e.kind, e.codec
                );
                TimeStampParsingErrorKind::DecodingError.error_with_msg(&msg)
            })
            .map(|time_stamp_req| Self { time_stamp_req })
    }

    /// Hash of the time-stamped data and the used message digest algorithm.
    pub fn get_message_imprint(&self) -> &asn1::MessageImprint {
        &self.time_stamp_req.message_imprint
    }

    /// The message digest algorithm object identifier used to produce the hash
    /// that should be time-stampled.
    pub fn get_message_imprint_digest_oid(&self) -> String {
        tyst::encdec::oid::as_string(&self.get_message_imprint().hash_algorithm.algorithm)
    }

    /// The length of the hash that should be time-stampled.
    pub fn get_message_imprint_digest_len_octets(&self) -> usize {
        self.get_message_imprint().hashed_message.len()
    }

    /// Hash of the time-stamped data and the used message digest algorithm as
    /// DER encoded bytes.
    pub fn get_encoded_message_imprint(&self) -> Vec<u8> {
        rasn::der::encode(&self.time_stamp_req.message_imprint).unwrap()
    }

    /// Return the request Nonce when present.
    pub fn get_nonce(&self) -> &Option<Integer> {
        &self.time_stamp_req.nonce
    }

    /// When `true`, the time stamping unit must include at least the signing
    /// certificate in the response.
    pub fn get_cert_req(&self) -> bool {
        self.time_stamp_req.cert_req
    }

    /// Requested policy or None to the service decide on which policy to use.
    pub fn get_req_policy_oid(&self) -> Option<String> {
        self.time_stamp_req
            .req_policy
            .as_ref()
            .map(|oid| tyst::encdec::oid::as_string(oid))
    }

    /// Return a vector of OIDs of all the critical extensions.
    pub fn get_critical_extension_oids(&self) -> Vec<Vec<u32>> {
        self.time_stamp_req
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
}
