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
use crate::cert::extensions::BasicConstraints;
use crate::cert::extensions::KeyUsage;
use crossbeam_skiplist::SkipSet;

/** X.509 Certificate Key Usage validation.

[RFC5280 4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3)
states:

```text
   CAs MUST include this extension in certificates that contain public keys that
   are used to validate digital signatures on other public key certificates or
   CRLs.
```

Basically this makes the leaf certificate KU optional to include.
 */
pub struct KeyUsageChecker {
    leaf_kus: Vec<KeyUsage>,
    issuer_kus: Vec<KeyUsage>,
    strict_non_repudiation: bool,
}
impl Default for KeyUsageChecker {
    /// Return a new instance with minimal set of required [KeyUsage]s.
    ///
    /// By default only [KeyUsage::KeyCertSign] is required for CA certs and
    /// [KeyUsage::DigitalSignature] or [KeyUsage::NonRepudiation] for leaf
    /// certificates,
    fn default() -> Self {
        Self::new(
            vec![KeyUsage::NonRepudiation],
            vec![KeyUsage::KeyCertSign],
            false,
        )
    }
}

impl KeyUsageChecker {
    /// Return a new instance with custom [KeyUsage] requirements.
    pub fn new(
        required_leaf_kus: Vec<KeyUsage>,
        required_issuer_kus: Vec<KeyUsage>,
        strict_non_repudiation: bool,
    ) -> Self {
        Self {
            leaf_kus: required_leaf_kus,
            issuer_kus: required_issuer_kus,
            strict_non_repudiation,
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
            let is_leaf = cp.get_basic_constraints().as_ref().is_none_or(BasicConstraints::is_leaf);
            let required_kus =
            if is_leaf {
                // Check: Allow any or KUs provided in non-default constructor
                &self.leaf_kus
            } else {
                // Check: Must have "Certificate Sign" to have issued cert
                &self.issuer_kus
            };
            let failure = if let Some(ku) = cp.get_key_usage() {
                required_kus.iter().any(|required_key_usage| {
                    if required_key_usage.eq(&KeyUsage::NonRepudiation)
                        && !self.strict_non_repudiation
                    {
                        !ku.contains(required_key_usage) && !ku.contains(&KeyUsage::DigitalSignature)
                    } else {
                        !ku.contains(required_key_usage)
                    }
                })
            } else {
                !is_leaf && !required_kus.is_empty()
            };
            if failure {
                if !self.strict_non_repudiation && required_kus.contains(&KeyUsage::NonRepudiation) && !required_kus.contains(&KeyUsage::DigitalSignature) {
                    msg = format!(
                        "[{i}]: Missing KeyUsage(s). Required: {required_kus:?} (DigitalSignature is accepted instead of NonRepudiation), Actual: {:?}",
                        cp.get_key_usage()
                );
                } else {
                    msg = format!(
                        "[{i}]: Missing KeyUsage(s). Required: {required_kus:?}, Actual: {:?}",
                        cp.get_key_usage()
                    );
                }
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
