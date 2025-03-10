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

//! Partial description of an entity's identity.

mod identity_fragment_error;

pub use self::identity_fragment_error::IdentityFragmentError;
pub use self::identity_fragment_error::IdentityFragmentErrorKind;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

/// Partial description of an entity's identity where the description can be
/// representated as a `String`.
///
/// This can be a `GeneralName` or `AttributeAndValue` of a `DistinguishedName.
///
/// `name` should be `snake_case`.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IdentityFragment {
    /// `snake_case` name of the `GeneralName` or `Attribute`.
    pub name: String,
    /// `String` representation of the partial identity description.
    pub value: String,
}

impl TryFrom<(String, String)> for IdentityFragment {
    type Error = IdentityFragmentError;

    fn try_from(value: (String, String)) -> Result<Self, Self::Error> {
        Self::new(&value.0, &value.1)
    }
}

impl IdentityFragment {
    /// Return a new instance without checking that the `name` parameter is
    /// well-formed.
    pub fn new_unchecked(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    /// Return a new instance.
    ///
    /// If the `name` parameter isn't well-formed, a [IdentityFragmentError]
    /// will be raised.
    pub fn new(name: &str, value: &str) -> Result<Self, IdentityFragmentError> {
        let name = name.to_string();
        Ok(Self {
            name,
            value: value.to_string(),
        })
    }
}
