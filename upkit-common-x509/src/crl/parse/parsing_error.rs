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

//! X.509 Certificate Revocation List (CRL) parsing errors.

use std::error::Error;
use std::fmt;

/// Cause of error.
#[derive(Debug)]
pub enum CrlParsingErrorKind {
    /// Failure to parse the DER encoded CRL.
    CrlDecodingError,
}

impl CrlParsingErrorKind {
    /// Create a new instance with an error message.
    pub fn error_with_msg(self, msg: &str) -> CrlParsingError {
        CrlParsingError {
            kind: self,
            msg: Some(msg.to_string()),
        }
    }

    /// Create a new instance without an error message.
    pub fn error(self) -> CrlParsingError {
        CrlParsingError {
            kind: self,
            msg: None,
        }
    }
}

impl fmt::Display for CrlParsingErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/** Certificate Revocation List (CRL) parsing error.

Create a new instance via [CrlParsingErrorKind].
*/
#[derive(Debug)]
pub struct CrlParsingError {
    kind: CrlParsingErrorKind,
    msg: Option<String>,
}

impl CrlParsingError {
    /// Return the type of error.
    pub fn kind(&self) -> &CrlParsingErrorKind {
        &self.kind
    }
}

impl fmt::Display for CrlParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "{} {}", self.kind, msg)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl Error for CrlParsingError {}
