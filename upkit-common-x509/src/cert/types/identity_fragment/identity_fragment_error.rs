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

//! Identity fragment handling errors.

use std::error::Error;
use std::fmt;

/// Cause of error.
#[derive(Debug)]
pub enum IdentityFragmentErrorKind {
    /// Failed to encode the value to ASN.1.
    EncodingFailure,
    /// Failed to decode the value from ASN.1.
    DecodingFailure,
    /// Attribute name is not known.
    UnknownAttribute,
    /// Attribute's value violates restrictions for this attribute.
    InvalidAttributeValue,
}

impl IdentityFragmentErrorKind {
    /// Create a new instance with an error message.
    pub fn error_with_msg(self, msg: &str) -> IdentityFragmentError {
        IdentityFragmentError {
            kind: self,
            msg: Some(msg.to_string()),
        }
    }

    /// Create a new instance without an error message.
    pub fn error(self) -> IdentityFragmentError {
        IdentityFragmentError {
            kind: self,
            msg: None,
        }
    }
}

impl fmt::Display for IdentityFragmentErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/** Identity fragment handling error.

Create a new instance via [IdentityFragmentErrorKind].
*/
#[derive(Debug)]
pub struct IdentityFragmentError {
    kind: IdentityFragmentErrorKind,
    msg: Option<String>,
}

impl IdentityFragmentError {
    /// Return the [IdentityFragmentErrorKind] type of this error.
    pub fn kind(&self) -> &IdentityFragmentErrorKind {
        &self.kind
    }
}

impl fmt::Display for IdentityFragmentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "{} {}", self.kind, msg)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl Error for IdentityFragmentError {}
