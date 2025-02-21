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

//! X.509 Certificate Policies.

use rasn::types::Integer;
use rasn::types::{Any, Ia5String, ObjectIdentifier, SequenceOf};
use rasn_pkix::{DisplayText, NoticeReference, PolicyInformation, PolicyQualifierInfo, UserNotice};
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

/// Common [CertificatePolicy] object identifiers-
pub enum WellKnownCertificatePolicy {
    // RFC5280
    /// RFC5280 `2.5.29.32.0`:
    /// CA does not wish to limit the set of policies for certification paths
    /// that include this certificate.
    AnyPolicy,
    // https://cabforum.org/resources/object-registry/
    // joint-iso-itu-t(2) international-organizations(23) ca-browser-forum(140)
    // certificate-policies(1) baseline-requirements(2)
    /// CAB Forum: `2.23.140.1.1`:
    /// Certificate issued in compliance with the Extended Validation Guidelines.
    CabfExtendedValidation,
    /// CAB Forum `2.23.140.1.2`: TLS Baseline Requirements.
    CabfBaselineRequirements,
    /// CAB Forum `2.23.140.1.2.1`:
    /// Certificate issued in compliance with the TLS Baseline Requirements -
    /// No entity identity asserted.
    CabfDomainValidated,
    /// CAB Forum `2.23.140.1.2.2`:
    /// Certificate issued in compliance with the TLS Baseline Requirements -
    /// Organization identity asserted.
    CabfOrganizationValidated,
    /// CAB Forum `2.23.140.1.2.3`:
    /// Certificate issued in compliance with the TLS Baseline Requirements -
    /// Individual identity asserted.
    CabfIndividualValidated,
    /// CAB Forum `2.23.140.1.3`:
    /// EV Code Signing Certificate issued in compliance with the Code Signing
    /// Baseline Requirements.
    CabfExtendedValidationCodeSigning,
    /// CAB Forum `2.23.140.1.4.1`:
    /// Code Signing Certificate issued in compliance with the Code Signing
    /// Baseline Requirements.
    CabfCodeSigningRequirementsCodeSigning,
    /// CAB Forum `2.23.140.1.4.2`:
    /// Timestamp Certificate issued in compliance with the Code Signing
    /// Baseline Requirements.
    CabfCodeSigningRequirementsTimestamping,
    // Internet Security Research Group (https://www.abetterinternet.org/)
    // ISRG Domain Validated is no longer present in the CPS
    // https://letsencrypt.org/documents/isrg-cp-cps-v5.7/
    //IsgrDomainValidated,
}
impl WellKnownCertificatePolicy {
    /// Return the Certificate Policy OID
    pub fn as_oid(&self) -> &[u32] {
        match self {
            Self::AnyPolicy => &[2, 5, 29, 32, 0],
            Self::CabfExtendedValidation => &[2, 23, 140, 1, 1],
            Self::CabfBaselineRequirements => &[2, 23, 140, 1, 2],
            Self::CabfDomainValidated => &[2, 23, 140, 1, 2, 1],
            Self::CabfOrganizationValidated => &[2, 23, 140, 1, 2, 2],
            Self::CabfIndividualValidated => &[2, 23, 140, 1, 2, 3],
            Self::CabfExtendedValidationCodeSigning => &[2, 23, 140, 1, 3],
            Self::CabfCodeSigningRequirementsCodeSigning => &[2, 23, 140, 1, 4, 1],
            Self::CabfCodeSigningRequirementsTimestamping => &[2, 23, 140, 1, 4, 2],
            //Self::IsgrDomainValidated => &[1, 3, 6, 1, 4, 1, 44947, 1, 1, 1],
        }
    }
}

/// Certificate Policy
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CertificatePolicy {
    // Use well known policy instead
    //Any,
    /// Policy information terms specified by OID. (Recommended by RFC5280.)
    ///
    /// OIDs for well-known certificate policies (including the "anyPolicy") can
    /// be retrieved by using the [WellKnownCertificatePolicy] enum.
    OidPolicy {
        /// Object identifier
        oid: Vec<u32>,
    },
    /// Policy information terms specified by OID and Certificate Practice
    /// Statement (CSP).
    CspPolicy {
        /// Object identifier
        oid: Vec<u32>,
        /// Pointer to the Certificate Practice Statement (CSP).
        uri: String,
    },
    /// User notice is intended for display to a relying party when a
    /// certificate is used.
    UserNoticePolicy {
        /// Object identifier
        oid: Vec<u32>,
        /// (Discuraged by RFC5280.) Reference a text intended to show to user
        /// of cert.
        notice_ref: Option<(String, Vec<isize>)>,
        /// Text intended to show to user of cert.
        explicit_text: Option<String>,
    },
}

impl CertificatePolicy {
    /// joint-iso-ccitt(2) ds(5) ce(29) certificatePolicies(32)
    pub const OID: &[u32] = &[2, 5, 29, 32];
    const OID_QUALIFIER_ID_CPS: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 2, 1];
    const OID_QUALIFIER_ID_UNOTICE: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 2, 2];

    /// Return a Vec of new instances.
    pub fn from_rasn_type(policies: &SequenceOf<PolicyInformation>) -> Vec<Self> {
        policies.iter().map(Self::from_policy_information).collect()
    }

    fn from_policy_information(policy: &PolicyInformation) -> Self {
        let oid = policy.policy_identifier.to_vec();
        if let Some(policy_qualifiers) = &policy.policy_qualifiers {
            for policy_qualifier in policy_qualifiers {
                match policy_qualifier.id.to_vec().as_slice() {
                    Self::OID_QUALIFIER_ID_CPS => {
                        return Self::from_csp_policy(oid, policy_qualifier.qualifier.as_bytes())
                    }
                    Self::OID_QUALIFIER_ID_UNOTICE => {
                        return Self::from_user_notice_policy(
                            oid,
                            policy_qualifier.qualifier.as_bytes(),
                        )
                    }
                    unknown_qualifier => todo!("Unknown CP qualifier {unknown_qualifier:?}."),
                }
            }
        }
        Self::OidPolicy { oid }
    }

    fn from_csp_policy(oid: Vec<u32>, qualifier: &[u8]) -> Self {
        Self::CspPolicy {
            oid,
            uri: crate::encdec::rasn::display_text_as_string(
                &rasn::der::decode::<DisplayText>(qualifier).unwrap(),
            ),
        }
    }

    fn from_user_notice_policy(oid: Vec<u32>, qualifier: &[u8]) -> Self {
        let user_notice = rasn::der::decode::<UserNotice>(qualifier).unwrap();
        //if let Some(notice_ref) = user_notice.notice_ref {}
        let explicit_text = user_notice
            .explicit_text
            .map(|display_text| crate::encdec::rasn::display_text_as_string(&display_text));
        let notice_ref = user_notice.notice_ref.map(|notice_reference| {
            let organisation =
                crate::encdec::rasn::display_text_as_string(&notice_reference.organisation);
            let notice_numbers = notice_reference
                .notice_numbers
                .iter()
                .map(crate::encdec::rasn::integer_as_isize)
                .collect();
            (organisation, notice_numbers)
        });
        Self::UserNoticePolicy {
            oid,
            notice_ref,
            explicit_text,
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(
        certificate_policies: &[CertificatePolicy],
    ) -> SequenceOf<PolicyInformation> {
        certificate_policies
            .iter()
            .map(Self::as_policy_information)
            .collect()
    }

    fn as_policy_information(&self) -> PolicyInformation {
        match self {
            //Self::Any => Self::as_any_policy(),
            Self::OidPolicy { oid } => Self::as_oid_policy(oid),
            Self::CspPolicy { oid, uri } => Self::as_csp_policy(oid, uri),
            Self::UserNoticePolicy {
                oid,
                notice_ref,
                explicit_text,
            } => Self::as_user_notice_policy(oid, notice_ref, explicit_text),
        }
    }

    fn as_oid_policy(oid: &[u32]) -> PolicyInformation {
        PolicyInformation {
            policy_identifier: ObjectIdentifier::new_unchecked(oid.to_vec().into()),
            policy_qualifiers: None,
        }
    }

    fn as_csp_policy(oid: &[u32], csp_uri: &str) -> PolicyInformation {
        PolicyInformation {
            policy_identifier: ObjectIdentifier::new_unchecked(oid.to_vec().into()),
            policy_qualifiers: vec![PolicyQualifierInfo {
                id: ObjectIdentifier::new_unchecked(Self::OID_QUALIFIER_ID_CPS.into()),
                qualifier: Any::new(
                    rasn::der::encode(&Ia5String::try_from(csp_uri).unwrap()).unwrap(),
                ),
            }]
            .into(),
        }
    }

    fn as_user_notice_policy(
        oid: &[u32],
        notice_ref: &Option<(String, Vec<isize>)>,
        explicit_text: &Option<String>,
    ) -> PolicyInformation {
        let user_notice = UserNotice {
            notice_ref: notice_ref.to_owned().map(|(organization, notice_numbers)| {
                NoticeReference {
                    organisation: DisplayText::Utf8String(organization),
                    notice_numbers: notice_numbers
                        .iter()
                        .map(|n| Integer::Primitive(*n))
                        .collect(),
                }
            }),
            // Displaytext is 1..200 chars
            explicit_text: explicit_text
                .to_owned()
                .filter(|et| !et.is_empty())
                .map(|mut et| {
                    et.truncate(200);
                    et
                })
                .map(DisplayText::Utf8String),
        };
        PolicyInformation {
            policy_identifier: ObjectIdentifier::new_unchecked(oid.to_vec().into()),
            policy_qualifiers: vec![PolicyQualifierInfo {
                id: ObjectIdentifier::new_unchecked(Self::OID_QUALIFIER_ID_UNOTICE.into()),
                qualifier: Any::new(rasn::der::encode(&user_notice).unwrap()),
            }]
            .into(),
        }
    }
}
