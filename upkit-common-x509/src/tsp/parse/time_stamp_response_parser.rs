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

//! Time-Stamp response parsing.

pub use crate::tsp::parse::TimeStampParsingError;
pub use crate::tsp::parse::TimeStampParsingErrorKind;
use crate::tsp::tsp_asn1 as asn1;
pub use crate::tsp::types::PkiFailureInfo;
pub use crate::tsp::types::PkiStatus;
pub use crate::tsp::types::TimeStampToken;

/** Time-Stamp response parser.

[RFC 3161 2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2):

```text
   TimeStampResp ::= SEQUENCE  {
      status                  PKIStatusInfo,
      timeStampToken          TimeStampToken     OPTIONAL  }
```
*/
#[derive(Clone)]
pub struct TimeStampRespParser {
    time_stamp_resp: asn1::TimeStampResp,
}
impl TimeStampRespParser {
    /// Create a new instance from `encoded_time_stamp_resp` bytes.
    pub fn from_bytes(encoded_time_stamp_resp: &[u8]) -> Result<Self, TimeStampParsingError> {
        rasn::der::decode::<asn1::TimeStampResp>(encoded_time_stamp_resp)
            .map_err(|e| {
                let msg = format!(
                    "Error while decoding data. kind: '{:?}', codec: '{:?}'",
                    e.kind, e.codec
                );
                TimeStampParsingErrorKind::DecodingError.error_with_msg(&msg)
            })
            .map(|time_stamp_resp| Self { time_stamp_resp })
    }

    /// Return the overall success or failure status of the requested operation.
    pub fn get_status(&self) -> PkiStatus {
        PkiStatus::from_value(self.time_stamp_resp.status.status).unwrap()
    }

    /// Return detailed failure status of the requested operation.
    pub fn get_failure_info(&self) -> Option<PkiFailureInfo> {
        self.time_stamp_resp
            .status
            .fail_info
            .as_ref()
            .map(|error_code| PkiFailureInfo::from_value(error_code).unwrap())
    }

    /// Return the [TimeStampToken] when the requested operation was successful.
    pub fn get_time_stamp_token(&self) -> Option<TimeStampToken> {
        self.time_stamp_resp
            .time_stamp_token
            .as_ref()
            .and_then(TimeStampToken::from_rasn_type)
    }
}
