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

//! PKCS#10 Certification request info attributes.

mod challenge_password_attr;
mod extension_request_attr;

use crossbeam_skiplist::SkipMap;
use rasn::types::{Any, ObjectIdentifier, SetOf};
use rasn_cms::Attribute;

pub use self::challenge_password_attr::*;
pub use self::extension_request_attr::*;

/** PKCS#10 Certification request info attributes.

[RFC 2985 5.4](https://www.rfc-editor.org/rfc/rfc2985.html#section-5) defines
relevant supported attributes.

The Enrollment over Secure Transport (EST) attributes defined in
[RFC 7894 3](https://www.rfc-editor.org/rfc/rfc7894.html#section-3) are currently
not supported.

## Note

Only single valued attributes are supported and if multiple attributes of with
the same OID are present, the last one of these will be used.
*/
#[derive(Default)]
pub struct CertificationRequestInfoAttributes {
    attribute_by_oid: SkipMap<Vec<u32>, Vec<u8>>,
}

impl CertificationRequestInfoAttributes {
    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn from_rasn_type(attrs: &SetOf<Attribute>) -> Self {
        Self {
            attribute_by_oid: SkipMap::from_iter(attrs.to_vec().into_iter().map(|attribute| {
                (
                    attribute.r#type.to_vec(),
                    attribute
                        .values
                        .to_vec()
                        // Only support single valued attributes
                        .first()
                        .map(|any| any.as_bytes().to_vec())
                        .unwrap_or_default(),
                )
            })),
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> SetOf<Attribute> {
        rasn::types::SetOf::from_vec(
            self.attribute_by_oid
                .iter()
                .map(|entry| Attribute {
                    r#type: ObjectIdentifier::new_unchecked(entry.key().to_vec().into()),
                    values: vec![Any::new(entry.value().to_owned())].into(),
                })
                .collect(),
        )
    }

    /// Return the first DER encoded attribute value of the last attribute with
    /// this object identifier.
    fn get_attribute_by_oid(&self, oid: &[u32]) -> Option<Vec<u8>> {
        self.attribute_by_oid
            .get(oid)
            .map(|entry| entry.value().to_vec())
    }

    /// Get the [ChallengePasswordAttribute].
    pub fn get_challenge_password(&self) -> Option<ChallengePasswordAttribute> {
        self.get_attribute_by_oid(ChallengePasswordAttribute::OID)
            .as_ref()
            .map(|value| value as &[u8])
            .and_then(ChallengePasswordAttribute::from_encoded)
    }

    /// Set the [ChallengePasswordAttribute].
    pub fn set_challenge_password(self, challenge_password: &str) -> Self {
        self.attribute_by_oid.insert(
            ChallengePasswordAttribute::OID.to_vec(),
            ChallengePasswordAttribute::new(challenge_password).to_encoded(),
        );
        self
    }

    /// Get the [ExtensionRequestAttribute].
    pub fn get_extension_request(&self) -> Option<ExtensionRequestAttribute> {
        self.get_attribute_by_oid(ExtensionRequestAttribute::OID)
            // Is this perhaps an CSR from an MS system? Handle it transparently in that case.
            .or_else(|| {
                self.get_attribute_by_oid(ExtensionRequestAttribute::OID_MS_CERT_EXTENSIONS)
            })
            .as_ref()
            .map(|value| value as &[u8])
            .and_then(ExtensionRequestAttribute::from_encoded)
    }

    /// Set the [ExtensionRequestAttribute].
    pub fn set_extension_request(
        self,
        extensions: Option<&crate::cert::extensions::Extensions>,
    ) -> Self {
        if let Some(era) = extensions.and_then(ExtensionRequestAttribute::new) {
            self.attribute_by_oid
                .insert(ExtensionRequestAttribute::OID.to_vec(), era.to_encoded());
        }
        self
    }
}
