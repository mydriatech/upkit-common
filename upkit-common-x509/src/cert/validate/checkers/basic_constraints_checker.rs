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

//! Basic Constraints validation.

use super::CertificateParser;
use super::CertificateValidationError;
use super::CertificateValidationErrorKind;
use super::ExtensionChecker;
use crate::cert::extensions::BasicConstraints;
use crossbeam_skiplist::SkipSet;

/** X.509 Certificate Basic Constraints validation.

See [RFC5280 4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9).
 */
#[derive(Default)]
pub struct BasicConstraintsChecker {}

impl ExtensionChecker for BasicConstraintsChecker {
    fn check_extensions(
        &self,
        chain_with_trust: &[CertificateParser],
        unresolved_extensions: &SkipSet<Vec<u32>>,
    ) -> Result<(), CertificateValidationError> {
        // The provided chain could be an excerpt from a much larger chain, so
        // make no assumptions here about the length.
        // if first one is a leaf, skip 1 to get the enumeration right
        let mut skip_first = 0;
        if chain_with_trust
            .first()
            .and_then(CertificateParser::get_basic_constraints)
            .as_ref()
            .is_none_or(BasicConstraints::is_leaf)
        {
            skip_first = 1;
        }
        let failed_item = chain_with_trust
            .iter()
            .skip(skip_first)
            .enumerate()
            .map(|(i, cp)| (i, cp.get_basic_constraints()))
            .find(|(i, basic_constraints)| {
                !Self::is_ca_with_sufficient_path_len(basic_constraints, i.to_owned())
            });
        if let Some((required_path_len, basic_constraints)) = failed_item {
            return Err(CertificateValidationErrorKind::ExtensionHandlingFailure
                .error_with_msg(&format!("Failed check of Basic Constraints '{basic_constraints:?}' since required path length was {required_path_len}.")));
        } else {
            unresolved_extensions.remove(BasicConstraints::OID);
        }
        Ok(())
    }
}

impl BasicConstraintsChecker {
    /// Ignore leaf and check that the rest are marked as CAs and have
    /// sufficient path len for this chain.
    fn is_ca_with_sufficient_path_len(
        basic_constraints: &Option<BasicConstraints>,
        required_path_len: usize,
    ) -> bool {
        basic_constraints.as_ref().is_some_and(|basic_constraints| {
            basic_constraints.is_ca()
                && basic_constraints
                    .path_len()
                    .is_none_or(|path_len| path_len >= required_path_len)
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn check_basic_constraints_checker() {
        init_logger();
        assert!(!BasicConstraintsChecker::is_ca_with_sufficient_path_len(
            &Some(BasicConstraints::new_leaf()),
            0
        ));
        assert!(BasicConstraintsChecker::is_ca_with_sufficient_path_len(
            &Some(BasicConstraints::new_ca(None)),
            3
        ));
        assert!(BasicConstraintsChecker::is_ca_with_sufficient_path_len(
            &Some(BasicConstraints::new_ca(Some(3))),
            3
        ));
    }
}
