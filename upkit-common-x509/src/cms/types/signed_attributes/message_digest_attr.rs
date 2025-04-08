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

//! MessageDigest attribute.

use rasn::types::OctetString;

/** MessageDigest attribute.

Specifies the message digest of the encapContentInfo eContent OCTET STRING being
signed in signed-data or authenticated in authenticated-data.

[RFC 5652 11.2](https://www.rfc-editor.org/rfc/rfc5652#section-11.2):

```text
   MessageDigest ::= OCTET STRING
```
*/
pub struct MessageDigestAttribute {
    message_digest: Vec<u8>,
}

impl MessageDigestAttribute {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) id-messageDigest(4)
    pub const OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 4];

    /// Return a new instance.
    pub fn new(message_digest: &[u8]) -> Self {
        Self {
            message_digest: message_digest.to_vec(),
        }
    }

    /// Return eContent message digest.
    pub fn get_message_digest(&self) -> &[u8] {
        &self.message_digest
    }

    /// Return a new instance from the DER encoded attribute value.
    pub fn from_encoded(der_encoded: &[u8]) -> Option<Self> {
        rasn::der::decode::<OctetString>(der_encoded)
            .ok()
            .map(|message_digest| Self {
                message_digest: message_digest.to_vec(),
            })
    }

    /// Return the DER encoded attribute value.
    pub fn to_encoded(&self) -> Vec<u8> {
        rasn::der::encode(&OctetString::from(self.message_digest.to_vec())).unwrap()
    }
}
