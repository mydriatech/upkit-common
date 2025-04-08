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

//! ContentType attribute.

use rasn::types::ObjectIdentifier;

/** ContentType attribute.

The content-type attribute type specifies the content type of the ContentInfo.

[RFC 5652 11.1](https://www.rfc-editor.org/rfc/rfc5652#section-11.1):

```text
   ContentType ::= OBJECT IDENTIFIER
```
*/
pub struct ContentTypeAttribute {
    content_type_oid: Vec<u32>,
}

impl ContentTypeAttribute {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) id-contentType(3)
    pub const OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 3];

    /// Return a new instance.
    pub fn new(content_type_oid: &[u32]) -> Self {
        Self {
            content_type_oid: content_type_oid.to_vec(),
        }
    }

    /// The CMS Content type object identifier.
    pub fn get_content_type_oid(&self) -> &[u32] {
        &self.content_type_oid
    }

    /// Return a new instance from the DER encoded attribute value.
    pub fn from_encoded(der_encoded: &[u8]) -> Option<Self> {
        rasn::der::decode::<ObjectIdentifier>(der_encoded)
            .ok()
            .map(|oid| Self {
                content_type_oid: oid.to_vec(),
            })
    }

    /// Return the DER encoded attribute value.
    pub fn to_encoded(&self) -> Vec<u8> {
        rasn::der::encode(&ObjectIdentifier::new_unchecked(
            self.content_type_oid.to_vec().into(),
        ))
        .unwrap()
    }
}
