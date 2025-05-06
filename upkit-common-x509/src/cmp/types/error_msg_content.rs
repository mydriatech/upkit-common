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

use super::PkiFailureInfo;
use super::PkiStatus;
use crate::cmp::asn1;

/** Error Message Content

[RFC 4210 5.3.21](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.21):

```text
   ErrorMsgContent ::= SEQUENCE {
       pKIStatusInfo          PKIStatusInfo,
       errorCode              INTEGER           OPTIONAL,
       errorDetails           PKIFreeText       OPTIONAL
   }
```
*/
pub struct ErrorMessage {
    error_msg_content: asn1::ErrorMsgContent,
}

impl std::fmt::Display for ErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "status: {}", self.get_pki_status_info_status().name())?;
        if let Some(failure_info) = self.get_pki_status_info_failure_info() {
            write!(f, ", failure_info: {}", failure_info.name())?;
        }
        if let Some(status_string) = self.get_pki_status_info_status_string() {
            write!(f, ", status_string: {:?}", status_string)?;
        }
        if let Some(error_code) = self.get_error_code() {
            write!(f, ", error_code: {}", error_code)?;
        }
        if let Some(error_details) = self.get_error_details() {
            write!(f, ", error_details: {:?}", error_details)?;
        }
        Ok(())
    }
}

impl ErrorMessage {
    /// Return the overall status of the request.
    pub fn get_pki_status_info_status(&self) -> PkiStatus {
        self.error_msg_content
            .pki_status_info
            .status
            .clone()
            .try_into()
            .ok()
            .and_then(PkiStatus::from_value)
            .expect("Unsupported PKIStatus")
    }

    /// Optionally, return a list of error messages.
    pub fn get_pki_status_info_status_string(&self) -> Option<Vec<String>> {
        self.error_msg_content.pki_status_info.status_string.clone()
    }

    /// Optionally, return the detailed failure reason.
    pub fn get_pki_status_info_failure_info(&self) -> Option<PkiFailureInfo> {
        self.error_msg_content
            .pki_status_info
            .fail_info
            .clone()
            .as_ref()
            .and_then(PkiFailureInfo::from_value)
    }

    /// Get implementation specific error code.
    pub fn get_error_code(&self) -> Option<usize> {
        self.error_msg_content
            .error_code
            .as_ref()
            .map(|value| value.try_into().unwrap())
    }

    /// Get implementation specific error message.
    pub fn get_error_details(&self) -> Option<&Vec<String>> {
        self.error_msg_content.error_details.as_ref()
    }

    /// Return a new instance from the provided PKIBody.
    pub fn from_pki_body(pki_body: &asn1::PkiBody) -> Option<Self> {
        if let asn1::PkiBody::Error(error_msg_content) = pki_body {
            Some(Self::from_rasn_type(error_msg_content))
        } else {
            panic!("Only init from 'error' is possible here.")
        }
    }

    /// Return a new instance from the provided `rasn` type.
    pub fn from_rasn_type(error_msg_content: &asn1::ErrorMsgContent) -> Self {
        Self {
            error_msg_content: error_msg_content.clone(),
        }
    }
}
