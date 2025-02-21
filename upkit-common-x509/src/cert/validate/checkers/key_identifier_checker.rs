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

//! X.509 Certificate AuthorityKeyIdentifier and SubjectKeyIdentifier validation.

use super::ExtensionChecker;
use crate::cert::extensions::AuthorityKeyIdentifier;
use crate::cert::extensions::SubjectKeyIdentifier;
use crate::cert::parse::CertificateParser;
use crate::cert::validate::CertificateValidationError;
use crate::cert::validate::CertificateValidationErrorKind;
use crossbeam_skiplist::SkipSet;
use tyst::encdec::hex::ToHex;

/** X.509 Certificate Key Usage validation.

Authority Key Identifier as defined in
[RFC5280 4.2.1.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1) and
Subject Key Identifier as defined in
[RFC5280 4.2.1.2](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2).
 */
#[derive(Default)]
pub struct KeyIdentifierChecker {}

impl ExtensionChecker for KeyIdentifierChecker {
    fn check_extensions(
        &self,
        chain_with_trust: &[CertificateParser],
        unresolved_extensions: &SkipSet<Vec<u32>>,
    ) -> Result<(), CertificateValidationError> {
        let mut last_aki: Option<Vec<u8>> = None;
        for (i, cp) in chain_with_trust.iter().enumerate() {
            if let Some(last_aki) = last_aki {
                if let Some(ski) = cp.get_subject_key_identifier_kid() {
                    if !ski.eq(&last_aki) {
                        let msg = format!(
                            "[{i}]: AuthorityKeyIdentifier '{}' did not match issuer's SubjectKeyIdentifier '{}'.",
                            last_aki.to_hex(), ski.to_hex(),
                        );
                        return Err(CertificateValidationErrorKind::ExtensionHandlingFailure
                            .error_with_msg(&msg));
                    }
                } else {
                    return Err(CertificateValidationErrorKind::ExtensionHandlingFailure
                        .error_with_msg(
                            "Leaf has AuthorityKeyIdentifier, but issuer is missing SubjectKeyIdentifier."
                        ));
                }
            }
            last_aki = cp.get_authority_key_identifier_kid();
        }
        unresolved_extensions.remove(&AuthorityKeyIdentifier::OID.to_vec());
        unresolved_extensions.remove(&SubjectKeyIdentifier::OID.to_vec());
        Ok(())
    }
}
