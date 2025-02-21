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

//! X.509 Certificate Revocation List (CRL) distribution points (CDP).

use crate::cert::types::WellKnownGeneralName;
use rasn::types::Ia5String;
use rasn::types::SequenceOf;
use rasn_pkix::DistributionPoint;
use rasn_pkix::DistributionPointName;
use rasn_pkix::GeneralName;

/// Certificate Revocation List (CRL) distribution point (CDP).
///
/// See [RFC5280 4.2.2.13](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13).
///
/// NOTES:
/// * RFC5280 "RECOMMENDS against segmenting CRLs by reason code" (unsupported)
/// * Real world support for indirect CRLs can't be relied upon. (unsupported)
/// * Having multiple alternative locations for retrieving the same CRL is not
///     very practical in the real world.
///
/// -> Suppport parsing, but use a single CA signed CDP when building certs.
pub struct CrlDistributionPoint {}

impl CrlDistributionPoint {
    // joint-iso-ccitt(2) ds(5) ce(29) cRLDistributionPoints(31)
    /// CRL Distribution Points object identifier
    pub const OID: &[u32] = &[2, 5, 29, 31];

    /// Return a CA issued CDP URI for all revocation reasons if present. Preferr http over ldap.
    pub fn from_rasn_type(cdps: &SequenceOf<DistributionPoint>) -> Option<String> {
        cdps.iter()
            .filter(|dp| dp.reasons.is_none())
            .filter(|dp| dp.crl_issuer.is_none())
            .filter_map(|dp| {
                if let Some(DistributionPointName::FullName(general_names)) = &dp.distribution_point
                {
                    let mut y = general_names
                        .iter()
                        .filter_map(WellKnownGeneralName::from_rasn_type)
                        .filter(|(wkgn, _value)| WellKnownGeneralName::Uri.eq(wkgn))
                        .map(|(_, value)| value)
                        .collect::<Vec<_>>();
                    // http(s) before ldap(s), since h<l
                    y.sort();
                    y.first().cloned()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .first()
            .cloned()
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    ///
    /// `cdp_uri` is the URI of a CA issued CRL for all revocation reasons.
    pub fn to_rasn_type(cdp_uri: &str) -> SequenceOf<DistributionPoint> {
        // If the certificate issuer is also the CRL issuer, then conforming CAs MUST omit the cRLIssuer
        vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![GeneralName::Uri(
                Ia5String::try_from(cdp_uri).unwrap(),
            )])),
            reasons: None,
            crl_issuer: None,
        }]
    }
}
