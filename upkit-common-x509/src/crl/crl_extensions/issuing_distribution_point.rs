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

//! CRL Issuing Distribution Point.

use rasn_pkix::DistributionPointName;

use crate::cert::types::WellKnownGeneralName;
use crate::crl::parse::CrlParsingError;
use crate::crl::parse::CrlParsingErrorKind;

/** CRL Issuing Distribution Point.

Since partitioned CRLs may or may not be in used, this field should always match
the CRL distribution point of the certificate when present during validation.

This implementation only supports direct CRLs with all reason codes and both CA
and leaf certificates. Only a single full URI can be used as `distributionPoint`.

[RFC5280 5.2.5](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.5):

```text
  id-ce-issuingDistributionPoint OBJECT IDENTIFIER ::= { id-ce 28 }

  IssuingDistributionPoint ::= SEQUENCE {
       distributionPoint          [0] DistributionPointName OPTIONAL,
       onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
       onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
       onlySomeReasons            [3] ReasonFlags OPTIONAL,
       indirectCRL                [4] BOOLEAN DEFAULT FALSE,
       onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }

       -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
       -- and onlyContainsAttributeCerts may be set to TRUE.
```

CA/Browser Forum [Baseline requirements 7.2.2.1](https://cabforum.org/working-groups/server/baseline-requirements/requirements/#7221-crl-issuing-distribution-point):

```text
"
1. If a Certificate within the scope of the CRL contains a CRL Distribution
Points extension, then at least one of the uniformResourceIdentifiers in the CRL
Distribution Points’s fullName field MUST be included in the fullName field of
the CRL’s Issuing Distribution Point extension. The encoding of the
uniformResourceIdentifier value in the Issuing Distribution Point extension
SHALL be byte-for-byte identical to the encoding used in the Certificate’s CRL
Distribution Points extension.
2. Other GeneralNames of type uniformResourceIdentifier MAY be included.
3. Non-uniformResourceIdentifier GeneralName types MUST NOT be included.
"
```
*/
pub struct IssuingDistributionPoint {}

impl IssuingDistributionPoint {
    /// joint-iso-itu-t(2) ds(5) certificateExtension(29) issuingDistributionPoint(28)
    pub const OID: &[u32] = &[2, 5, 29, 28];

    /// Return extension in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_extension(distribution_point_uri: &str) -> rasn_pkix::Extension {
        crate::encdec::rasn::to_rasn_extension(
            Self::OID,
            true,
            &Self::to_rasn_type(distribution_point_uri),
        )
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    fn to_rasn_type(distribution_point_uri: &str) -> rasn_pkix::IssuingDistributionPoint {
        rasn_pkix::IssuingDistributionPoint {
            distribution_point: Some(rasn_pkix::DistributionPointName::FullName(
                [WellKnownGeneralName::Uri.to_rasn_type(distribution_point_uri)].to_vec(),
            )),
            only_contains_user_certs: false,
            only_contains_ca_certs: false,
            only_some_reasons: None,
            indirect_crl: false,
            only_contains_attribute_certs: false,
        }
    }

    /// Return a new instances from the matching extension.
    pub fn from_rasn_extension(extension: rasn_pkix::Extension) -> Result<String, CrlParsingError> {
        Self::from_rasn_type(&crate::encdec::rasn::from_rasn_extension(
            Self::OID,
            &extension,
        ))
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(
        idp: &rasn_pkix::IssuingDistributionPoint,
    ) -> Result<String, CrlParsingError> {
        if idp.only_contains_user_certs
            || idp.only_contains_ca_certs
            || idp.indirect_crl
            || idp.only_contains_attribute_certs
            || idp.only_some_reasons.is_some()
        {
            Err(CrlParsingErrorKind::CrlDecodingError
                .error_with_msg("This implementation only supports full direct CRLs. "))?
        }
        if let Some(dp) = &idp.distribution_point {
            match dp {
                DistributionPointName::FullName(general_names) => {
                    if general_names.len() == 1 {
                        let general_name = general_names.first().unwrap();
                        if let Some((WellKnownGeneralName::Uri, distribution_point_uri)) =
                            WellKnownGeneralName::from_rasn_type(general_name)
                        {
                            return Ok(distribution_point_uri);
                        }
                    }
                }
                DistributionPointName::NameRelativeToCrlIssuer(_) => {}
            }
        }
        Err(CrlParsingErrorKind::CrlDecodingError.error_with_msg("This implementation requires 'distributionPoint' to use a full name with a single URI. "))
    }
}
