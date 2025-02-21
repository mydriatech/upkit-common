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

//! X.509 Certificate Key Usage.

use bitvec::vec::BitVec;
use rasn::types::BitString;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

/** Key Usage.

See [RFC5280 4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3).
*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsage {
    /// Allow use for verifying digital signatures, other than signatures on
    /// certificates and CRLs.
    ///
    /// This is also required in CA certificates that for example signs OCSP
    /// responses directly.
    DigitalSignature,
    /// A.k.a. `contentCommitment`. The signature is not supposed to be easy to
    /// deny later.
    NonRepudiation,
    /// Allow enciphering private or secret keys
    KeyEncipherment,
    /// Allow direct enciphering of data without an intermediate symmetric cipher.
    DataEncipherment,
    /// Allow use in key agreement.
    KeyAgreement,
    /// Allow verification of public key certificates.
    KeyCertSign,
    /// Allow verification of certificate revocation lists.
    CRLSign,
    /// Only allow enciphering data during key agreement.
    ///
    /// Requires [Self::KeyAgreement].
    EncipherOnly,
    /// Only allow deciphering data during key agreement.
    ///
    /// Requires [Self::KeyAgreement].
    DecipherOnly,
}
impl KeyUsage {
    /// joint-iso-ccitt(2) ds(5) id-ce(29) id-ce-keyUsage(15)
    pub const OID: &[u32] = &[2, 5, 29, 15];

    const MSB_ORDERED_KUS: [Self; 9] = [
        Self::DigitalSignature,
        Self::NonRepudiation,
        Self::KeyEncipherment,
        Self::DataEncipherment,
        Self::KeyAgreement,
        Self::KeyCertSign,
        Self::CRLSign,
        Self::EncipherOnly,
        Self::DecipherOnly,
    ];

    /// Return the index of the [KeyUsage] where 0 means [Self::DigitalSignature]
    /// and 8 means [Self::DecipherOnly].
    pub fn index(&self) -> usize {
        Self::MSB_ORDERED_KUS
            .iter()
            .position(|rku| self.eq(rku))
            .unwrap()
    }

    /// Convert a slice of [KeyUsage] to [BitString].
    pub fn to_rasn_type(key_usages: &[KeyUsage]) -> BitString {
        let mut bv = BitVec::<u8, bitvec::order::Msb0>::new();
        for ku in &Self::MSB_ORDERED_KUS {
            bv.push(key_usages.contains(ku));
        }
        while bv.last().is_some_and(|b| b == false) {
            bv.pop();
        }
        bv
    }
}
