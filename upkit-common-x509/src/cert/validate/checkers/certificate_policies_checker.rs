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

//! Certificate Policies validation.

use crate::cert::extensions::CertificatePolicy;

use super::CertificateParser;
use super::CertificateValidationError;
use super::CertificateValidationErrorKind;
use super::ExtensionChecker;
use crossbeam_skiplist::SkipSet;

/** X.509 Certificate Certificate Policies validation.

See [RFC5280 4.2.1.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4).
 */
#[derive(Default)]
pub struct CertificatePoliciesChecker {
    leaf_policies: Vec<CertificatePolicy>,
    issuer_policies: Vec<CertificatePolicy>,
}

impl CertificatePoliciesChecker {
    /// Return a new instance with custom [CertificatePolicy] requirements.
    pub fn new(required_leaf_policies: &[CertificatePolicy]) -> Self {
        Self {
            leaf_policies: required_leaf_policies.to_vec(),
            issuer_policies: Vec::default(),
        }
    }

    /// Return a new instance with custom [CertificatePolicy] requirements.
    pub fn with_issuer_policies(
        required_leaf_policies: &[CertificatePolicy],
        required_issuer_policies: &[CertificatePolicy],
    ) -> Self {
        Self {
            leaf_policies: required_leaf_policies.to_vec(),
            issuer_policies: required_issuer_policies.to_vec(),
        }
    }
}

impl ExtensionChecker for CertificatePoliciesChecker {
    fn check_extensions(
        &self,
        chain_with_trust: &[CertificateParser],
        unresolved_extensions: &SkipSet<Vec<u32>>,
    ) -> Result<(), CertificateValidationError> {
        let mut msg = String::new();
        let failure = chain_with_trust.iter().enumerate().any(|(i, cp)| {
            let required_policies = if i > 0 {
                &self.issuer_policies
            } else {
                &self.leaf_policies
            };
            let policies = cp.get_certificate_policies();
            let failure = if policies.is_empty() {
                !required_policies.is_empty()
            } else {
                required_policies.iter().any(|required_policy| !policies.contains(required_policy))
            };
            if failure {
                msg = format!(
                    "[{i}]: Missing CertificatePolicy. Required: {required_policies:?}, Actual: {policies:?}"
                );
            }
            failure
        });
        if failure {
            return Err(
                CertificateValidationErrorKind::ExtensionHandlingFailure.error_with_msg(&msg)
            );
        } else {
            unresolved_extensions.remove(&CertificatePolicy::OID.to_vec());
        }
        Ok(())
    }
}
