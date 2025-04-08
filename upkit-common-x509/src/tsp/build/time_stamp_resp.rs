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

//! Time-Stamp response builder.

use crate::tsp::tsp_asn1 as asn1;
use crate::tsp::types::PkiFailureInfo;
use crate::tsp::types::PkiStatus;
use crate::tsp::types::PkiStatusInfo;
use crate::tsp::types::TimeStampToken;

/// Time-Stamp response builder.
pub struct TimeStampResp {
    time_stamp_resp: Vec<u8>,
}

impl TimeStampResp {
    /// Create an instance with a successful outcome.
    pub fn with_success(with_mods: bool, time_stamp_token: TimeStampToken) -> Self {
        // When the status contains the value zero or one, a TimeStampToken MUST be present.
        let status = if with_mods {
            PkiStatusInfo::new(&PkiStatus::GrantedWithMods, &[], &None)
        } else {
            PkiStatusInfo::new(&PkiStatus::Granted, &[], &None)
        };
        Self {
            time_stamp_resp: rasn::der::encode(&asn1::TimeStampResp {
                status: status.to_rasn_type(),
                time_stamp_token: Some(time_stamp_token.to_rasn_type()),
            })
            .unwrap(),
        }
    }

    /// Create an instance with a rejected outcome.
    pub fn with_rejection(status_string: &[String], fail_info: &Option<PkiFailureInfo>) -> Self {
        // When status contains a value other than zero or one, a TimeStampToken MUST NOT be present.
        // When the TimeStampToken is not present, the failInfo indicates the reason why the time-stamp request was rejected and may be one of the following values.
        // "one" → interpret this as only a single reason will be used
        Self {
            time_stamp_resp: rasn::der::encode(&asn1::TimeStampResp {
                status: PkiStatusInfo::new(&PkiStatus::Rejection, status_string, fail_info)
                    .to_rasn_type(),
                time_stamp_token: None,
            })
            .unwrap(),
        }
    }

    /// Create an instance with an other outcome than successful or failed.
    ///
    /// [PkiStatus] must be one of `Waiting`, `RevocationWarning` or `RevocationNotification`.
    pub fn with_other_status(pki_status: &PkiStatus, status_string: &[String]) -> Self {
        // Status must be one of the following when this function is invoked.
        match pki_status {
            PkiStatus::Waiting
            | PkiStatus::RevocationWarning
            | PkiStatus::RevocationNotification => (),
            bad_status => panic!("Invalid status at this point: {}", bad_status.as_value()),
        };
        Self {
            time_stamp_resp: rasn::der::encode(&asn1::TimeStampResp {
                status: PkiStatusInfo::new(pki_status, status_string, &None).to_rasn_type(),
                time_stamp_token: None,
            })
            .unwrap(),
        }
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(time_stamp_resp: &asn1::TimeStampResp) -> Self {
        /*
        if !Self::no_signature_algorithm_identifier().eq(&tbs_certificate.signature) {
            log::debug!("Provided TBSCertificate did not use 'id-alg-noSignature' as signature algorithm. Allowing this to proceed anyway.");
        }
        */
        Self {
            time_stamp_resp: rasn::der::encode(time_stamp_resp).unwrap(),
        }
    }

    /// Return the DER encoded object as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.time_stamp_resp
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> asn1::TimeStampResp {
        rasn::der::decode(&self.time_stamp_resp).unwrap()
    }
}
