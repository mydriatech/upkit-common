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

//! OCSP Nonce.

use rasn::types::OctetString;
use tyst::Tyst;

/** OCSP Nonce.

The purpose of the OCSP nonce is to prevent replays of older responses.

[RFC 6960 4.4.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.1) updated
by [RFC 9654](https://www.rfc-editor.org/rfc/rfc9654):

```text
   Nonce ::= OCTET STRING(SIZE(1..128))
```

A fairly safe length of the nonce is 32 octets:

```text
   An OCSP requester ... MUST use a minimum length of 32 octets for Nonce.
   ...
   An OCSP responder ... MUST accept Nonce lengths of at least 16 octets and up
   to and including 32 octets. A responder MAY choose to respond without the
   Nonce extension for requests in which the length of the Nonce is in between 1
   octet and 15 octets or 33 octets and 128 octets.
```

*/
#[derive(PartialEq, Eq)]
pub struct Nonce {
    nonce: Vec<u8>,
}

impl Default for Nonce {
    fn default() -> Self {
        Self::generate(None)
    }
}

impl Nonce {
    /// iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(48) id-ad-ocsp(1) id-pkix-ocsp-nonce(1)
    pub const OID: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 2];

    // TODO: Consolidate with serial number gen?
    /// Generate a new Nonce.
    ///
    /// Defaults to 32 octets and can be interpreted as a positive integer when
    // big endian interpretation is used.
    pub fn generate(octets: Option<usize>) -> Self {
        // https://www.rfc-editor.org/rfc/rfc9654#section-2.1
        let octets = octets.unwrap_or(32).clamp(32, 128);
        let mut rnd = vec![127u8; octets];
        loop {
            Tyst::instance().prng_fill_with_random(None, &mut rnd);
            // Ensure that the generated number is positive, if interpreted as an Integer
            rnd[0] &= 0x7f;
            // Ensure that the generated number is not 0
            if rnd.iter().any(|octet| octet != &0) {
                break;
            }
        }
        Self { nonce: rnd }
    }

    /// Return extension in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_extension(&self) -> rasn_pkix::Extension {
        crate::encdec::rasn::to_rasn_extension(Self::OID, false, &self.to_rasn_type())
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    fn to_rasn_type(&self) -> rasn_ocsp::Nonce {
        OctetString::from(self.nonce.to_vec())
    }

    /// Return a new instances from the matching extension.
    pub fn from_rasn_extension(extension: rasn_pkix::Extension) -> Self {
        Self::from_rasn_type(&crate::encdec::rasn::from_rasn_extension(
            Self::OID,
            &extension,
        ))
    }

    /// Return a Vec of new instances.
    fn from_rasn_type(nonce: &rasn_ocsp::Nonce) -> Self {
        Self {
            nonce: nonce.to_vec(),
        }
    }
}
