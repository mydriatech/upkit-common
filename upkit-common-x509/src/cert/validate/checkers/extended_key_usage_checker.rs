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

//! Extended Key Usage validation.

use super::CertificateParser;
use super::CertificateValidationError;
use super::CertificateValidationErrorKind;
use super::ExtensionChecker;
use crate::cert::extensions::ExtendedKeyUsage;
use crossbeam_skiplist::SkipSet;

/** X.509 Certificate Extended Key Usage validation.

See [RFC5280 4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12).
 */
pub struct ExtendedKeyUsageChecker {
    leaf_ekus: Vec<ExtendedKeyUsage>,
    issuer_ekus: Vec<ExtendedKeyUsage>,
}

impl ExtendedKeyUsageChecker {
    /// Return a new instance with custom [ExtendedKeyUsage] requirements.
    pub fn new(required_leaf_ekus: &[ExtendedKeyUsage]) -> Self {
        Self {
            leaf_ekus: required_leaf_ekus.to_vec(),
            issuer_ekus: Vec::default(),
        }
    }

    /// Return a new instance with custom [ExtendedKeyUsage] requirements.
    ///
    /// Normally the EKU of the issuer is not relevant when checking a leaf
    /// certificate.
    pub fn with_issuer_ekus(
        required_leaf_ekus: &[ExtendedKeyUsage],
        required_issuer_ekus: &[ExtendedKeyUsage],
    ) -> Self {
        Self {
            leaf_ekus: required_leaf_ekus.to_vec(),
            issuer_ekus: required_issuer_ekus.to_vec(),
        }
    }
}

impl ExtensionChecker for ExtendedKeyUsageChecker {
    fn check_extensions(
        &self,
        chain_with_trust: &[CertificateParser],
        unresolved_extensions: &SkipSet<Vec<u32>>,
    ) -> Result<(), CertificateValidationError> {
        let mut msg = String::new();
        let failure = chain_with_trust.iter().enumerate().any(|(i, cp)| {
            let required_ekus = if i > 0 {
                &self.issuer_ekus
            } else {
                &self.leaf_ekus
            };
            let ekus = cp.get_extended_key_usage();
            let failure = if ekus.is_empty() {
                !required_ekus.is_empty()
            } else {
                required_ekus.iter().any(|required_eku| !ekus.contains(required_eku))
            };
            if failure {
                msg = format!(
                    "[{i}]: Missing ExtendedKeyUsage(s). Required: {required_ekus:?}, Actual: {ekus:?}"
                );
            }
            failure
        });
        if failure {
            return Err(
                CertificateValidationErrorKind::ExtensionHandlingFailure.error_with_msg(&msg)
            );
        } else {
            unresolved_extensions.remove(&ExtendedKeyUsage::OID.to_vec());
        }
        Ok(())
    }
}
