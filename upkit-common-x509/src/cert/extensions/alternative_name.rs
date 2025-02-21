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

//! X.509 Certificate Alternative Name.

use crate::cert::types::WellKnownGeneralName;
use rasn::types::SequenceOf;
use rasn_pkix::GeneralName;

/*
SubjectAltName ::= GeneralNames

GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
*/

/** Alternative Name.

See [RFC5280 4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6).
See [RFC5280 4.2.1.7](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.7).
*/
pub struct AlternativeName {}

impl AlternativeName {
    /// [RFC5280 4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6)
    pub const OID_SUBJECT_AN: &[u32] = &[2, 5, 29, 17];
    /// [RFC5280 4.2.1.7](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.7)
    pub const OID_ISSUER_AN: &[u32] = &[2, 5, 29, 18];

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(
        alternative_names: &[(WellKnownGeneralName, String)],
    ) -> SequenceOf<GeneralName> {
        alternative_names
            .iter()
            .map(|(an, value)| an.to_rasn_type(value))
            .collect::<Vec<_>>()
    }

    /// Return a Vec of new instances (ignoring any unknown GeneralName).
    pub fn from_rasn_type(
        general_names: &SequenceOf<GeneralName>,
    ) -> Vec<(WellKnownGeneralName, String)> {
        general_names
            .iter()
            .filter_map(WellKnownGeneralName::from_rasn_type)
            .collect()
    }
}
