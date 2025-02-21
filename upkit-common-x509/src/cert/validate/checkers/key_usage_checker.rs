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

//! Key Usage validation.

use super::CertificateParser;
use super::CertificateValidationError;
use super::CertificateValidationErrorKind;
use super::ExtensionChecker;
use crate::cert::extensions::KeyUsage;
use crossbeam_skiplist::SkipSet;

/** X.509 Certificate Key Usage validation.

See [RFC5280 4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3).
 */
pub struct KeyUsageChecker {
    leaf_kus: Vec<KeyUsage>,
    issuer_kus: Vec<KeyUsage>,
}
impl Default for KeyUsageChecker {
    /// Return a new instance with minimal set of required [KeyUsage]s.
    ///
    /// By default only [KeyUsage::KeyCertSign] is required for CA certs and
    /// [KeyUsage::DigitalSignature] for leaf certificates,
    fn default() -> Self {
        Self::new(
            vec![KeyUsage::DigitalSignature],
            vec![KeyUsage::KeyCertSign],
        )
    }
}

impl KeyUsageChecker {
    /// Return a new instance with custom [KeyUsage] requirements.
    pub fn new(required_leaf_kus: Vec<KeyUsage>, required_issuer_kus: Vec<KeyUsage>) -> Self {
        Self {
            leaf_kus: required_leaf_kus,
            issuer_kus: required_issuer_kus,
        }
    }
}

impl ExtensionChecker for KeyUsageChecker {
    fn check_extensions(
        &self,
        chain_with_trust: &[CertificateParser],
        unresolved_extensions: &SkipSet<Vec<u32>>,
    ) -> Result<(), CertificateValidationError> {
        let mut msg = String::new();
        let failure = chain_with_trust.iter().enumerate().any(|(i, cp)| {
            let required_kus = if i > 0 {
                &self.issuer_kus
                // Check: Must have "Certificate Sign" to have issued cert
            } else {
                // Check: Allow any or KUs provided in non-default constructor
                //self.leaf_kus;
                &self.leaf_kus
            };
            let failure = if let Some(ku) = cp.get_key_usage() {
                required_kus
                    .iter()
                    .any(|required_key_usage| !ku[required_key_usage.index()])
            } else {
                !required_kus.is_empty()
            };
            if failure {
                msg = format!(
                    "[{i}]: Missing KeyUsage(s). Required: {required_kus:?}, Actual: {:?}",
                    cp.get_key_usage()
                );
            }
            failure
        });
        if failure {
            return Err(
                CertificateValidationErrorKind::ExtensionHandlingFailure.error_with_msg(&msg)
            );
        } else {
            unresolved_extensions.remove(&KeyUsage::OID.to_vec());
        }
        Ok(())
    }
}
