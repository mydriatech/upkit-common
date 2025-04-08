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

//! CRL entry extension ReasonCode.

/** CRL entry extension ReasonCode.

[RFC 5280 5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1):

```text
CRLReason ::= ENUMERATED {
     unspecified             (0),
     keyCompromise           (1),
     cACompromise            (2),
     affiliationChanged      (3),
     superseded              (4),
     cessationOfOperation    (5),
     certificateHold         (6),
          -- value 7 is not used
     removeFromCRL           (8),
     privilegeWithdrawn      (9),
     aACompromise           (10) }
```
*/
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReasonCode {
    // Additional interpretations of meaning for these reason codes:
    // * https://cabforum.org/working-groups/server/baseline-requirements/requirements/#722-crl-and-crl-entry-extensions
    // * https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.509-201210-S!!PDF-E&type=items 8.5.3.1
    /// Represented by the omission of a reasonCode.
    /// Can be used to revoke certificates for reasons other than the specific codes.
    Unspecified,
    /// Indicates that it is known or suspected that the Subscriber’s Private Key has been compromised.
    KeyCompromise,
    /// Used in revoking a CA-certificate; it indicates that it is known or suspected that the
    /// subject's private key, or other aspects of the subject validated in the certificate, have been compromised.
    CaCompromise,
    /// Indicates that the Subject’s name or other Subject Identity Information in the Certificate has changed, but there is no cause to suspect that the Certificate’s Private Key has been compromised.
    AffiliationChanged,
    /// Indicates that the Certificate is being replaced
    Superseded,
    /// Indicates that the certificate is no longer needed for the purpose for which it
    /// was issued but there is no cause to suspect that the private key has been compromised.
    CessationOfOperation,
    /// A certificate may be placed on hold by issuing a CRL entry with a reason code of certificateHold.
    CertificateHold,
    /// May only appear in delta CRLs and indicates that a certificate is to be removed from a CRL because
    /// either the certificate expired or was removed from hold.
    RemoveFromCrl,
    /// Entity has for example violated ToS, but key has not been compromised.
    /// Indicates that a certificate (public-key or attribute certificate) was revoked
    /// because a privilege contained within that certificate has been withdrawn.
    PrivilegeWithdrawn,
    /// Indicates that it is known or suspected that aspects of the Attribute Authority (AA) validated in the attribute
    /// certificate have been compromised.
    AaCompromise,
}

impl Default for ReasonCode {
    fn default() -> Self {
        Self::Unspecified
    }
}

impl ReasonCode {
    /// joint-iso-itu-t(2) ds(5) certificateExtension(29) cRLReasons(21)
    pub const OID: &[u32] = &[2, 5, 29, 21];

    /// Return the snake-case name.
    pub fn name(&self) -> &str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "key_compromise",
            Self::CaCompromise => "ca_compromise",
            Self::AffiliationChanged => "affiliation_changed",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessation_of_operation",
            Self::CertificateHold => "certificate_hold",
            Self::RemoveFromCrl => "remove_from_crl",
            Self::PrivilegeWithdrawn => "privilege_withdrawn",
            Self::AaCompromise => "aa_compromise",
        }
    }

    /// Return the numeric value.
    pub fn value(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }

    /// Return a new instance from the numeric value.
    pub fn from_value(value: usize) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            unknown => panic!("Unable to interpret reason code '{unknown}'."),
        }
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(value: &rasn_pkix::CrlReason) -> Self {
        match value {
            rasn_pkix::CrlReason::Unspecified => Self::Unspecified,
            rasn_pkix::CrlReason::KeyCompromise => Self::KeyCompromise,
            rasn_pkix::CrlReason::CaCompromise => Self::CaCompromise,
            rasn_pkix::CrlReason::AffiliationChanged => Self::AffiliationChanged,
            rasn_pkix::CrlReason::Superseded => Self::Superseded,
            rasn_pkix::CrlReason::CessationOfOperation => Self::CessationOfOperation,
            rasn_pkix::CrlReason::CertificateHold => Self::CertificateHold,
            rasn_pkix::CrlReason::RemoveFromCRL => Self::RemoveFromCrl,
            rasn_pkix::CrlReason::PrivilegeWithdrawn => Self::PrivilegeWithdrawn,
            rasn_pkix::CrlReason::AaCompromise => Self::AaCompromise,
        }
    }
}
