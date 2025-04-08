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

//! CRL Number.

use num_bigint::BigInt;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;
use std::cmp::Ordering;

/** Certificate Revocation List (CRL) Number.

[RFC5280 5.2.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.3):

"The CRL number is a non-critical CRL extension that conveys a monotonically
increasing sequence number for a given CRL scope and CRL issuer."

CA/Browser Forum [Baseline requirements 7.2.2](https://cabforum.org/working-groups/server/baseline-requirements/requirements/):

"MUST contain an INTEGER greater than or equal to zero (0) and less than 2^159,
and convey a strictly increasing sequence.""
*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct CrlNumber {
    #[serde_as(as = "serde_with::hex::Hex")]
    crl_number_hex: Vec<u8>,
}

impl Default for CrlNumber {
    fn default() -> Self {
        Self::new(0)
    }
}

impl PartialOrd for CrlNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CrlNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_big_int().cmp(&other.as_big_int())
    }
}

impl PartialEq for CrlNumber {
    fn eq(&self, other: &Self) -> bool {
        self.as_big_int() == other.as_big_int()
    }
}

impl Eq for CrlNumber {}

impl std::fmt::Display for CrlNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_big_int())
    }
}

impl CrlNumber {
    /// joint-iso-itu-t(2) ds(5) certificateExtension(29) cRLNumber(20)
    pub const OID_CRL_NUMBER: &[u32] = &[2, 5, 29, 20];
    /// joint-iso-itu-t(2) ds(5) certificateExtension(29) deltaCRLIndicator(27)
    pub const OID_DELTA_CRL_INDICATOR: &[u32] = &[2, 5, 29, 27];

    /// Return a new instance
    pub fn new(crl_number: u64) -> Self {
        Self {
            crl_number_hex: BigInt::from(crl_number).to_signed_bytes_be(),
        }
    }

    fn as_big_int(&self) -> BigInt {
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.crl_number_hex)
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> rasn::types::Integer {
        rasn::types::Integer::from(BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &self.crl_number_hex,
        ))
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(crl_number: &rasn::types::Integer) -> Self {
        Self {
            crl_number_hex: crate::encdec::rasn::integer_as_bytes_be(crl_number),
        }
    }
}
