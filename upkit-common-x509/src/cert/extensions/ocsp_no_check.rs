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

//! X.509 Certificate OCSP No Check.

use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

/** OCSP No Check.

See [RFC 6960 4.2.2.2.1](https://www.rfc-editor.org/rfc/rfc6960.html#section-4.2.2.2.1).
*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
//#[serde(untagged)]
//#[serde(rename_all = "snake_case")]
pub struct OcspNoCheck {}

impl OcspNoCheck {
    // iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(48) id-ad-ocsp(1) id-pkix-ocsp-nocheck(5)
    /// OCSP No Check object identifier
    pub const OID: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5];

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type() -> Vec<u8> {
        // "The value of the extension SHALL be NULL."
        rasn::der::encode(&()).unwrap()
    }
}
