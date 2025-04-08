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

//! Private Key Usage Period validation.

use super::CertificateParser;
use super::CertificateValidationError;
use super::CertificateValidationErrorKind;
use super::ExtensionChecker;
use crate::cert::extensions::KeyUsage;
use crossbeam_skiplist::SkipSet;

/** X.509 Certificate Private Key Usage Period validation.

See [crate::cert::extensions::PrivateKeyUsagePeriod] for additional details.
 */
#[derive(Default)]
pub struct PrivateKeyUsagePeriodChecker {}

impl ExtensionChecker for PrivateKeyUsagePeriodChecker {
    fn check_extensions(
        &self,
        chain_with_trust: &[CertificateParser],
        unresolved_extensions: &SkipSet<Vec<u32>>,
    ) -> Result<(), CertificateValidationError> {
        // Sanity check each cert that PKUP is in certificate validity range
        let failure = chain_with_trust.iter().any(|cp| {
            cp.get_private_key_usage_period().is_some_and(|pkup| {
                pkup.get_not_after().is_some_and(|pkup_not_after| {
                    pkup_not_after > cp.get_validity().get_not_after()
                        || pkup_not_after < cp.get_validity().get_not_before()
                }) || pkup.get_not_before().is_some_and(|pkup_not_before| {
                    pkup_not_before > cp.get_validity().get_not_after()
                        || pkup_not_before < cp.get_validity().get_not_before()
                }) || pkup.get_not_after().is_some_and(|pkup_not_after| {
                    pkup.get_not_before()
                        .is_some_and(|pkup_not_before| pkup_not_after < pkup_not_before)
                })
            })
        });
        if failure {
            Err(CertificateValidationErrorKind::ExtensionHandlingFailure
                .error_with_msg("PrivateKeyUsagePeriod is outside the certificate's validity."))?;
        }
        // Check that each cert has been issued within the issuers PKUP
        let mut last_issued = chain_with_trust
            .first()
            .unwrap()
            .get_validity()
            .get_not_before();
        let failure = chain_with_trust.iter().skip(1).any(|cp| {
            let local_failure = cp.get_private_key_usage_period().is_some_and(|pkup| {
                pkup.get_not_before()
                    .is_some_and(|pkup_not_before| last_issued < pkup_not_before)
                    || pkup
                        .get_not_after()
                        .is_some_and(|pkup_not_after| last_issued > pkup_not_after)
            });
            last_issued = cp.get_validity().get_not_before();
            local_failure
        });
        if failure {
            Err(
                CertificateValidationErrorKind::ExtensionHandlingFailure.error_with_msg(
                    "Certificate was issued outside the issuer's PrivateKeyUsagePeriod.",
                ),
            )?;
        }
        unresolved_extensions.remove(&KeyUsage::OID.to_vec());
        Ok(())
    }
}
