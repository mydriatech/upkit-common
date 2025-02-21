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

//! X.509 Certificate extension checks.

mod basic_constraints_checker;
mod certificate_policies_checker;
mod extended_key_usage_checker;
mod key_identifier_checker;
mod key_usage_checker;

pub use self::basic_constraints_checker::BasicConstraintsChecker;
pub use self::certificate_policies_checker::CertificatePoliciesChecker;
pub use self::extended_key_usage_checker::ExtendedKeyUsageChecker;
pub use self::key_identifier_checker::KeyIdentifierChecker;
pub use self::key_usage_checker::KeyUsageChecker;
use super::CertificateParser;
use super::CertificateValidationError;
use super::CertificateValidationErrorKind;
use crossbeam_skiplist::SkipSet;

/* TODO:
 * Revocation checking: Caller must provide OCSP response with optional OCSP signing cert
 * Revocation checking: Caller must provide CRL
 * Name constraints validation
*/

/// X.509 Certificate extension checker.
pub trait ExtensionChecker {
    /** Validate one or more specific extensions of a certificate.

    `chain_of_trust` is provided in ordered form with the leaf certificate
    firsts.

    The implementation must remove the OID for the checked extension(s) from
    `unresolved_extensions` once processing is successful.
     */
    fn check_extensions(
        &self,
        chain_with_trust: &[CertificateParser],
        unresolved_extensions: &SkipSet<Vec<u32>>,
    ) -> Result<(), CertificateValidationError>;
}
