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

//! X.509 Certificate validation errors.

use std::error::Error;
use std::fmt;

/// Cause of certificate validation error.
#[derive(Debug)]
pub enum CertificateValidationErrorKind {
    /// Failure to parse the encoded certificate.
    CertificateParsingError,
    /// Failure to verify the signature using the issuers public key.
    InvalidSignature,
    /// An unknown signature algorithm was used to sign the certificate.
    UnknownSignature,
    /// The certificate was not yet valid or had expired for the point in time
    /// of validation.
    InvalidLifeSpan,
    /// None or more than one leaf was provided in the certicate chain to
    /// validate.
    NotOneLeaf,
    /// The provided certificate chain does not lead up to any trust anchor.
    NotTrusted,
    /// The certificate contains an unknown critical extensions.
    UnhandledCriticalExtensions,
    /// Rejected certificate while verifying one of the certificate extensions.
    ExtensionHandlingFailure,
}

impl CertificateValidationErrorKind {
    /// Create a new instance with an error message.
    pub fn error_with_msg(self, msg: &str) -> CertificateValidationError {
        CertificateValidationError {
            kind: self,
            msg: Some(msg.to_string()),
        }
    }

    /// Create a new instance without an error message.
    pub fn error(self) -> CertificateValidationError {
        CertificateValidationError {
            kind: self,
            msg: None,
        }
    }
}

impl fmt::Display for CertificateValidationErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/** Certificate validation error.

Create a new instance via [CertificateValidationErrorKind].
*/
#[derive(Debug)]
pub struct CertificateValidationError {
    kind: CertificateValidationErrorKind,
    msg: Option<String>,
}

impl CertificateValidationError {
    /// Return the [CertificateValidationErrorKind] type of this error.
    pub fn kind(&self) -> &CertificateValidationErrorKind {
        &self.kind
    }
}

impl fmt::Display for CertificateValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "{} {}", self.kind, msg)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl Error for CertificateValidationError {}
