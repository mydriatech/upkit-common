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

//! CMP processing errors. (Not CMP protocol errors.)

use std::error::Error;
use std::fmt;

/// Cause of error.
#[derive(Debug)]
pub enum CmpProcessingErrorKind {
    /// Unknown/unsupported PKIBody type.
    UnknownPkiBodyType,
    /// Failure to parse the DER encoded object.
    DecodingError,
    /// The CMP protected validation failed.
    ProtectionValidationFailure,
    /// The CMP response recipient nonce did not match the request sender nonce.
    BadNonce,
    /// The request is malformed.
    BadRequest,
    /// The response is malformed.
    BadResponse,
    /// Implementation is missing for something that might be defined in the
    /// standards. (Generic error.)
    NotImplemented,
}

impl CmpProcessingErrorKind {
    /// Create a new instance with an error message.
    pub fn error_with_msg(self, msg: &str) -> CmpProcessingError {
        CmpProcessingError {
            kind: self,
            msg: Some(msg.to_string()),
        }
    }

    /// Create a new instance without an error message.
    pub fn error(self) -> CmpProcessingError {
        CmpProcessingError {
            kind: self,
            msg: None,
        }
    }
}

impl fmt::Display for CmpProcessingErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/** Certificate Management Protocol (CMP) processing errors.

Create a new instance via [CmpProcessingErrorKind].

This should not be confused with the CMP protocol defined errors.
*/
#[derive(Debug)]
pub struct CmpProcessingError {
    kind: CmpProcessingErrorKind,
    msg: Option<String>,
}

impl CmpProcessingError {
    /// Return the type of this error.
    pub fn kind(&self) -> &CmpProcessingErrorKind {
        &self.kind
    }
}

impl fmt::Display for CmpProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "{} {}", self.kind, msg)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl Error for CmpProcessingError {}
