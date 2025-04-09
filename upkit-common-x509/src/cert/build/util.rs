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

//! X.509 Certificate build utility functions.

use crate::cert::types::DistinguishedName;
use crate::cert::types::IdentityFragment;
use crate::cert::types::WellKnownAttribute;
use crate::cert::types::WellKnownGeneralName;

/// Split [IdentityFragment]s into [DistinguishedName] and
/// [AlternativeName](crate::cert::extensions::AlternativeName) components.
///
/// This is useful when you want to think about the identity parts of an end
/// entity without having to care about what part that goes where.
pub fn split_by_identity_fragment_type(
    idfs: &[IdentityFragment],
) -> (DistinguishedName, Vec<(WellKnownGeneralName, String)>) {
    let mut dn = vec![];
    let mut an = vec![];
    for idf in idfs {
        if WellKnownAttribute::by_name(&idf.name).is_ok() {
            dn.push(vec![idf.clone()]);
        } else if let Some(wkgn) = WellKnownGeneralName::by_name(&idf.name) {
            an.push((wkgn, idf.value.to_owned()));
        } else {
            log::info!("Ignoring unsupported identity fragment: {idf:?}");
        }
    }
    (DistinguishedName::new_unchecked(dn), an)
}
