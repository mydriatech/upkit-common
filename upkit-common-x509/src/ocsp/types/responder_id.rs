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

//! OCSP Responder identifier.

use crate::cert::types::DistinguishedName;

/** OCSP Responder identifier.

[RFC 6960 4.2.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1):

```text
   ResponderID ::= CHOICE {
      byName               [1] Name,
      byKey                [2] KeyHash }

   KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
   (excluding the tag and length fields)
```

[RFC 5019 2.2.2](https://www.rfc-editor.org/rfc/rfc5019#section-2.2.2):

```text
   Clients MUST be able to identify OCSP responder certificates using
   both the byName and byKey ResponseData.ResponderID choices.
   Responders SHOULD use byKey to further reduce the size of the
   response in scenarios where reducing bandwidth is an issue."
```
*/
pub enum ResponderId {
    /// The subject DN of the certificate that signs the OCSP response.
    ByName(DistinguishedName),
    /// RFC 6960: SHA-1 hash of responder's public key.
    ByKey(Vec<u8>),
}
impl ResponderId {
    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(responder_id: &rasn_ocsp::ResponderId) -> Self {
        match responder_id {
            rasn_ocsp::ResponderId::ByName(name) => {
                Self::ByName(DistinguishedName::from_rasn_type(name).unwrap())
            }
            rasn_ocsp::ResponderId::ByKey(key) => Self::ByKey(key.to_vec()),
        }
    }
}
