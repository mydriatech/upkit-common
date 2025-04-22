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

//! PKCS#10 challenge password attribute.

use rasn::types::PrintableString;
use rasn::types::Utf8String;

/** PKCS#10 challenge password attribute.

[RFC 2985 5.4.1](https://www.rfc-editor.org/rfc/rfc2985.html#section-5):

A password by which an entity may request certificate revocation. The
interpretation of challenge passwords is intended to be specified by certificate
issuers.

```text
   challengePassword ATTRIBUTE ::= {
           WITH SYNTAX DirectoryString {pkcs-9-ub-challengePassword}
           EQUALITY MATCHING RULE caseExactMatch
           SINGLE VALUE TRUE
           ID pkcs-9-at-challengePassword
   }
```

See also the motivation for the new attributes defined for The Enrollment over
Secure Transport (EST) in
[RFC 7894 3](https://www.rfc-editor.org/rfc/rfc7894.html#section-3) before you
use this.
*/
pub struct ChallengePasswordAttribute {
    challenge_password: String,
}

impl ChallengePasswordAttribute {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) challengePassword(7)
    pub const OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 7];

    /// Return a new instance.
    pub fn new(challenge_password: &str) -> Self {
        Self {
            challenge_password: challenge_password.to_owned(),
        }
    }

    /// Return the challenge password as a regular UTF-8 encoded String.
    pub fn get_challenge_password(&self) -> &String {
        &self.challenge_password
    }

    /// Return a new instance from the DER encoded attribute value.
    pub fn from_encoded(der_encoded: &[u8]) -> Option<Self> {
        match rasn::der::decode::<Utf8String>(der_encoded) {
            Ok(v) => Some(v),
            Err(e1) => {
                String::from_utf8(
                    rasn::der::decode::<PrintableString>(der_encoded)
                        .map_err(|e2| {
                            log::debug!(
                                "Failed to decode PKCS#10 attribute 'challengePassword' as Utf8String or PrintableString: {e1:?} {e2:?}"
                            )
                        })
                        .unwrap()
                        .to_vec()
                ).ok()
            }
        }
        .map(|challenge_password|Self{challenge_password})
    }

    /// Return the DER encoded attribute value.
    pub fn to_encoded(&self) -> Vec<u8> {
        rasn::der::encode::<Utf8String>(&self.challenge_password).unwrap()
    }
}
