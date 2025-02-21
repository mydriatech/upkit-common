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

//! X.509 Certificate parsing errors.

use std::error::Error;
use std::fmt;

/// Cause of certificate parsing error.
#[derive(Debug)]
pub enum CertificateParsingErrorKind {
    /// Failure to parse the DER encoded certificate.
    CertificateDecodingError,
}

impl CertificateParsingErrorKind {
    /// Create a new instance with an error message.
    pub fn error_with_msg(self, msg: &str) -> CertificateParsingError {
        CertificateParsingError {
            kind: self,
            msg: Some(msg.to_string()),
        }
    }

    /// Create a new instance without an error message.
    pub fn error(self) -> CertificateParsingError {
        CertificateParsingError {
            kind: self,
            msg: None,
        }
    }
}

impl fmt::Display for CertificateParsingErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/** Certificate parsing error.

Create a new instance via [CertificateParsingErrorKind].
*/
#[derive(Debug)]
pub struct CertificateParsingError {
    kind: CertificateParsingErrorKind,
    msg: Option<String>,
}

impl CertificateParsingError {
    /// Return the [CertificateParsingErrorKind] type of this error.
    pub fn kind(&self) -> &CertificateParsingErrorKind {
        &self.kind
    }
}

impl fmt::Display for CertificateParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "{} {}", self.kind, msg)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl Error for CertificateParsingError {}
