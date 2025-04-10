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

//! OCSP AcceptableResponses.

use rasn::types::ObjectIdentifier;

/** OCSP AcceptableResponses request extension.

This is expected to contain `id-pkix-ocsp-basic`.

[RFC 6960 4.4.3](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.3):

```text
   AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
```
*/
#[derive(PartialEq, Eq)]
pub struct AcceptableResponses {
    acceptable_response_oids: Vec<Vec<u32>>,
}

impl Default for AcceptableResponses {
    fn default() -> Self {
        Self::new(&[Self::OID_OCSP_BASIC.to_vec()])
    }
}

impl AcceptableResponses {
    /// iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(48) id-ad-ocsp(1) id-pkix-ocsp-response(4)
    pub const OID: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 4];
    /// iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(48) id-ad-ocsp(1) id-pkix-ocsp-basic(1)
    pub const OID_OCSP_BASIC: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 4];

    /// Return a new instance.
    ///
    /// Normally you would only use [Self::OID_OCSP_BASIC] as acceptable
    /// response type.
    fn new(acceptable_response_oids: &[Vec<u32>]) -> Self {
        Self {
            acceptable_response_oids: acceptable_response_oids.to_vec(),
        }
    }

    /// Return extension in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_extension(&self) -> rasn_pkix::Extension {
        crate::encdec::rasn::to_rasn_extension(Self::OID, false, &self.to_rasn_type())
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    fn to_rasn_type(&self) -> rasn_ocsp::AcceptableResponses {
        self.acceptable_response_oids
            .iter()
            .map(|oid| ObjectIdentifier::new_unchecked(oid.to_vec().into()))
            .collect()
    }

    /// Return a new instances from the matching extension.
    pub fn from_rasn_extension(extension: rasn_pkix::Extension) -> Self {
        Self::from_rasn_type(&crate::encdec::rasn::from_rasn_extension(
            Self::OID,
            &extension,
        ))
    }

    /// Return a new instances from the ASN.1 library `rasn` type.
    fn from_rasn_type(acceptable_responses: &rasn_ocsp::AcceptableResponses) -> Self {
        Self {
            acceptable_response_oids: acceptable_responses
                .iter()
                .map(|oid| oid.to_vec())
                .collect::<Vec<_>>(),
        }
    }
}
