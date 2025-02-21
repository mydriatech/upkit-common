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

//! X.509 Certificate Basic Constraints.

use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

/** Basic Constraints.

See [RFC5280 4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9).
*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
//#[serde(untagged)]
//#[serde(rename_all = "snake_case")]
pub struct BasicConstraints {
    ca: bool,
    path_len: Option<usize>,
}

impl BasicConstraints {
    // joint-iso-ccitt(2) ds(5) ce(29) basicConstraints(19)
    /// Basic Constraints object identifier
    pub const OID: &[u32] = &[2, 5, 29, 19];

    /// Return a new instance for a leaf certificate.
    pub fn new_leaf() -> Self {
        Self {
            ca: false,
            path_len: None,
        }
    }

    /// Return a new instance for a CA certificate.
    ///
    /// `path_len` MUST be `None` unless [crate::cert::extensions::KeyUsage::KeyCertSign] is used.
    pub fn new_ca(path_len: Option<usize>) -> Self {
        Self { ca: true, path_len }
    }

    /// Return `true` if this belongs to a leaf certificate.
    pub fn is_leaf(&self) -> bool {
        !self.ca
    }

    /// Return `true` if this belongs to a CA certificate.
    pub fn is_ca(&self) -> bool {
        self.ca
    }

    /// Return the number of subordinate levels (including a leaf) that this CA
    /// allows.
    pub fn path_len(&self) -> Option<usize> {
        if self.ca {
            self.path_len
        } else {
            None
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> rasn_pkix::BasicConstraints {
        rasn_pkix::BasicConstraints {
            ca: self.ca,
            path_len_constraint: self.path_len.map(|plc| plc.into()),
        }
    }

    /// Return a Vec of new instances.
    pub fn from_rasn_type(basic_constraints: &rasn_pkix::BasicConstraints) -> Self {
        Self {
            ca: basic_constraints.ca,
            path_len: basic_constraints
                .path_len_constraint
                .as_ref()
                .map(crate::encdec::rasn::integer_as_usize),
        }
    }
}
