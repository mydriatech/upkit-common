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

//! Certificate Serial Number.

use num_bigint::BigInt;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;
use tyst::Tyst;

/** Certificate Serial Number

[RFC5280 4.1.2.2](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2):

"The serial number MUST be a positive integer assigned by the CA to each
certificate. It MUST be unique for each certificate issued by a given CA (i.e.,
the issuer name and serial number identify a unique certificate).  CAs MUST
force the serialNumber to be a non-negative integer."

CA/Browser Forum [Baseline requirements](https://cabforum.org/working-groups/server/baseline-requirements/requirements/):

"serialNumber MUST be a non-sequential number greater than zero (0) and less
than 2^159 containing at least 64 bits of output from a CSPRNG."

Having enough random data in the certificate has historically prevented
collision attacks with a weak signature hash function.

Due to the fact that we already have the uniqness requirement for the
certificate serial number per "issuer name" to mitigate the risk of serial
number collision, using a large highly random number also reduces the need
to syncronize distributed issuance with the performance impact it implies.
*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SerialNumber {
    #[serde_as(as = "serde_with::hex::Hex")]
    serial_number_hex: Vec<u8>,
}

impl Default for SerialNumber {
    fn default() -> Self {
        Self::generate(None)
    }
}

impl SerialNumber {
    /// Generate a non-zero positive serial number. BE encoded.
    ///
    /// The ensure serial numbers with at least 64 bits of CSPRNG output, the
    /// serial number will be generated with a minimum 9 octets.
    ///
    /// At most 20 octets (the default) will be used to comply with RFC5280.
    pub fn generate(octets: Option<usize>) -> Self {
        let octets = octets.unwrap_or(20).clamp(9, 20);
        let mut rnd = vec![127u8; octets];
        loop {
            Tyst::instance().prng_fill_with_random(None, &mut rnd);
            // Ensure that the generated number is positive
            rnd[0] &= 0x7f;
            // Ensure that the generated number is not 0
            if rnd.iter().any(|octet| octet != &0) {
                break;
            }
        }
        Self {
            serial_number_hex: rnd,
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> rasn::types::Integer {
        rasn::types::Integer::from(BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &self.serial_number_hex,
        ))
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(serial_number: &rasn::types::Integer) -> Self {
        Self {
            serial_number_hex: crate::encdec::rasn::integer_as_bytes_be(serial_number),
        }
    }
}
