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

//! OCSP No Check validation.

use super::CertificateParser;
use super::CertificateValidationError;
use super::CertificateValidationErrorKind;
use super::ExtensionChecker;
use crate::cert::extensions::OcspNoCheck;
use crossbeam_skiplist::SkipSet;

/** X.509 Certificate OCSP No Check validation.

See [RFC 6960 4.2.2.2.1](https://www.rfc-editor.org/rfc/rfc6960.html#section-4.2.2.2.1).
 */
#[derive(Default)]
pub struct OcspNoCheckChecker {}

impl ExtensionChecker for OcspNoCheckChecker {
    fn check_extensions(
        &self,
        chain_with_trust: &[CertificateParser],
        unresolved_extensions: &SkipSet<Vec<u32>>,
    ) -> Result<(), CertificateValidationError> {
        if chain_with_trust.first().unwrap().is_ocsp_no_check() {
            unresolved_extensions.remove(OcspNoCheck::OID);
            Ok(())
        } else {
            Err(CertificateValidationErrorKind::ExtensionHandlingFailure
                .error_with_msg("Failed check of Basic Constraints."))
        }
    }
}
