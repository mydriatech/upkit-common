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

//! X.509 Authority Information Access.

use rasn::types::ObjectIdentifier;
use rasn::types::SequenceOf;
use rasn_pkix::AccessDescription;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

use crate::cert::types::WellKnownGeneralName;

/// Authority Information Access description.
///
/// See [RFC5280 4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1).
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
//#[serde(untagged)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityInfoAccessDescription {
    /// Access to Onlince Certificate Status Protocol (OCSP) information for the
    /// certificate.
    Ocsp {
        /// A URI as defined in [RFC6960 3.1](https://www.rfc-editor.org/rfc/rfc6960#section-3.1).
        uri: String,
    },
    /// Additional certificates that were issued to the CA to aid certificate
    /// users to find a path to a trust-anchor.
    ///
    /// Multiple inclusions of this AuthorityInfoAccessDescription is allowed.
    CaIssuers {
        /// URI or directory name
        access_location: (WellKnownGeneralName, String),
    },
    /// RFC5280 allows for additional types of services being declared.
    Other {
        /// Access method
        oid: Vec<u32>,
        /// Access location
        access_location: (WellKnownGeneralName, String),
    },
}

impl AuthorityInfoAccessDescription {
    // iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) pe(1) authorityInfoAccess(1)
    /// AuthorityInfoAccess extension object identfier.
    pub const OID: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];

    const OID_ACCESS_METHOD_OCSP: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1];
    const OID_ACCESS_METHOD_CA_ISSUER: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];

    /// Return the access method OID.
    pub fn access_method_oid(&self) -> &[u32] {
        match self {
            // iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(1) ocsp(1)
            Self::Ocsp { uri: _ } => Self::OID_ACCESS_METHOD_OCSP,
            // iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(1) caIssuers(2)
            Self::CaIssuers { access_location: _ } => Self::OID_ACCESS_METHOD_CA_ISSUER,
            Self::Other {
                oid,
                access_location: _,
            } => oid.as_slice(),
        }
    }

    fn as_rasn_type(&self) -> AccessDescription {
        match self {
            // https://www.rfc-editor.org/rfc/rfc2560#section-3.1 MUST be a URI
            Self::Ocsp { uri } => AccessDescription {
                access_method: ObjectIdentifier::new_unchecked(
                    self.access_method_oid().to_vec().into(),
                ),
                access_location: WellKnownGeneralName::Uri.to_rasn_type(uri),
            },
            // Could be a directoryName
            Self::CaIssuers { access_location } => AccessDescription {
                access_method: ObjectIdentifier::new_unchecked(
                    self.access_method_oid().to_vec().into(),
                ),
                access_location: access_location.0.to_rasn_type(&access_location.1),
            },
            // Could be a directoryName
            Self::Other {
                oid,
                access_location,
            } => AccessDescription {
                access_method: ObjectIdentifier::new_unchecked(oid.clone().into()),
                access_location: access_location.0.to_rasn_type(&access_location.1),
            },
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(
        access_descriptions: &[AuthorityInfoAccessDescription],
    ) -> SequenceOf<AccessDescription> {
        access_descriptions
            .iter()
            .map(AuthorityInfoAccessDescription::as_rasn_type)
            .collect()
    }

    /// Return a Vec of new instances.
    pub fn from_rasn_type(accesss_descriptions: &SequenceOf<AccessDescription>) -> Vec<Self> {
        accesss_descriptions
            .iter()
            .map(Self::from_accesss_description)
            .collect()
    }

    fn from_accesss_description(access_description: &AccessDescription) -> Self {
        let access_location =
            WellKnownGeneralName::from_rasn_type(&access_description.access_location).unwrap();
        match access_description.access_method.to_vec().as_slice() {
            Self::OID_ACCESS_METHOD_OCSP => Self::Ocsp {
                uri: access_location.1,
            },
            Self::OID_ACCESS_METHOD_CA_ISSUER => Self::CaIssuers { access_location },
            other_oid => Self::Other {
                oid: other_oid.to_vec(),
                access_location,
            },
        }
    }
}
