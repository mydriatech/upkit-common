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

//! Time-Stamp request builder.

use crate::cert::types::SerialNumber;
use rasn::types::OctetString;

/// Time-Stamp request builder.
pub struct TimeStampReq {
    time_stamp_req: Vec<u8>,
}

impl TimeStampReq {
    /// Return a new instance.
    ///
    /// When `cert_req` is `true` the time-stamping service should provide
    /// at least the signing certificate bundled with the response.
    pub fn new(cert_req: bool, digest_algorithm_oid: &[u32], digest_bytes: &[u8]) -> Self {
        let time_stamp_req = rasn_cms::tsp::TimeStampReq {
            version: 1,
            message_imprint: rasn_cms::tsp::MessageImprint {
                hash_algorithm: crate::encdec::rasn::oid_as_algorithm_identifier(
                    digest_algorithm_oid,
                ),
                hashed_message: OctetString::from(digest_bytes.to_vec()),
            },
            req_policy: None,
            // RFC3161 has a 64-bit int in as example, but this seems a bit outdated
            nonce: Some(SerialNumber::generate(None).to_rasn_type()),
            cert_req,
            extensions: None,
        };
        Self {
            time_stamp_req: rasn::der::encode(&time_stamp_req).unwrap(),
        }
    }

    /// Return the DER encoded object as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.time_stamp_req
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> rasn_cms::tsp::TimeStampReq {
        rasn::der::decode(&self.time_stamp_req).unwrap()
    }
}
