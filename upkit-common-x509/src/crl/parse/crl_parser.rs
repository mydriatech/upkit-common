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

//! CRL parsing.

pub use super::CrlParsingError;
pub use super::CrlParsingErrorKind;
use crate::cert::extensions::AuthorityInfoAccessDescription;
use crate::cert::types::{DistinguishedName, SerialNumber, WellKnownGeneralName};
use crate::crl::crl_entry_extensions::CrlEntryExtensions;
use crate::crl::crl_entry_extensions::ReasonCode;
use crate::crl::crl_extensions::CrlExtensions;
use crate::crl::crl_extensions::CrlNumber;

/** CRL parser.

[RFC 5280 5](https://www.rfc-editor.org/rfc/rfc5280#section-5):

```text
   CertificateList  ::=  SEQUENCE  {
      tbsCertList          TBSCertList,
      signatureAlgorithm   AlgorithmIdentifier,
      signatureValue       BIT STRING  }

   TBSCertList  ::=  SEQUENCE  {
      version                 Version OPTIONAL,
                                   -- if present, MUST be v2
      signature               AlgorithmIdentifier,
      issuer                  Name,
      thisUpdate              Time,
      nextUpdate              Time OPTIONAL,
      revokedCertificates     SEQUENCE OF SEQUENCE  {
           userCertificate         CertificateSerialNumber,
           revocationDate          Time,
           crlEntryExtensions      Extensions OPTIONAL
                                    -- if present, version MUST be v2
                                 }  OPTIONAL,
      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                       -- if present, version MUST be v2
```

```text
   Conforming applications that support CRLs are REQUIRED to process both
   version 1 and version 2 complete CRLs that provide revocation information
   for all certificates issued by one CA.  Conforming applications are not
   required to support processing of delta CRLs, indirect CRLs, or CRLs with a
   scope other than all certificates issued by one CA.
```

## Notes

* Delta CRLs are not supported.
* Indirect CRLs are not supported.

Basic CRLs are supported, so you can use CRL partitioning or OCSP instead.
*/
pub struct CrlParser {
    crl_extensions: Option<CrlExtensions>,
    crl: rasn_pkix::CertificateList,
}

impl CrlParser {
    /// Create a new instance from `encoded_crl` bytes.
    pub fn from_bytes(encoded_crl: &[u8]) -> Result<Self, CrlParsingError> {
        rasn::der::decode::<rasn_pkix::CertificateList>(encoded_crl)
            .map_err(|e| {
                let msg = format!(
                    "Error while decoding data. kind: '{:?}', codec: '{:?}'",
                    e.kind, e.codec
                );
                CrlParsingErrorKind::CrlDecodingError.error_with_msg(&msg)
            })
            .map(|crl| Self {
                crl_extensions: CrlExtensions::from_rasn_type(&crl.tbs_cert_list.crl_extensions),
                crl,
            })
    }

    /// Return the DER encoded CRL.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CrlParsingError> {
        rasn::der::encode(&self.crl).map_err(|e| {
            let msg = format!(
                "Error while encoding CRL. kind: '{:?}', codec: '{:?}'",
                e.kind, e.codec
            );
            CrlParsingErrorKind::CrlDecodingError.error_with_msg(&msg)
        })
    }

    /// Return the part of the CRL that is covered by the signature
    /// as DER encoded bytes.
    pub fn get_encoded_tbs_cert_list(&self) -> Vec<u8> {
        rasn::der::encode(&self.crl.tbs_cert_list).unwrap()
    }

    /// Return the signature OID and data as DER encoded bytes.
    ///
    /// NOTE: This currently ignores the signature parameters.
    pub fn get_encoded_signature(&self) -> (String, Vec<u8>) {
        let oid = crate::encdec::rasn::algorithm_identifier_as_oid(&self.crl.signature_algorithm);
        let oid_string = tyst::encdec::oid::as_string(&oid);
        (oid_string, self.crl.signature.as_raw_slice().to_vec())
    }

    /// Return the issuer distinguished name as DER encoded bytes.
    pub fn get_encoded_issuer(&self) -> Vec<u8> {
        rasn::der::encode(&self.crl.tbs_cert_list.issuer).unwrap()
    }

    /// Return the issuer distinguished name.
    pub fn get_issuer(&self) -> Result<DistinguishedName, CrlParsingError> {
        DistinguishedName::from_rasn_type(&self.crl.tbs_cert_list.issuer).map_err(|e| {
            CrlParsingErrorKind::CrlDecodingError.error_with_msg(&format!(
                "Failed to parse Issuer Distinguished Name of certifiate: {e:?}"
            ))
        })
    }

    /// Return the issue date of this CRL (in Unix Epoch seconds).
    pub fn get_this_update(&self) -> u64 {
        crate::encdec::rasn::from_rasn_epoch_seconds(&self.crl.tbs_cert_list.this_update)
    }

    /// Return the latest point in time a new CRL will have been issued (in Unix
    /// Epoch seconds).
    ///
    /// NOTE: If an issuer would omit this field, it would be extremely hard to
    /// to know if a certificate is valid unless a fresh copy of the latest CRL
    /// is download using secure transport each time a certificate is validated.
    pub fn get_next_update(&self) -> Option<u64> {
        self.crl
            .tbs_cert_list
            .next_update
            .as_ref()
            .map(crate::encdec::rasn::from_rasn_epoch_seconds)
    }

    /// Return true if the CRL is valid at `point_in_time_epoch_seconds`.
    ///
    /// The CA is required to have published the next CRL at `nextUpdate`.
    ///
    /// In practice this means that CAs generate the CRL well before this point
    /// in time and `nextUpdate` is used as expiration date for a CRL.
    pub fn is_valid_at(&self, point_in_time_epoch_seconds: u64) -> bool {
        if let Some(next_update) = self.get_next_update()
            && point_in_time_epoch_seconds >= next_update
        {
            return false;
        }
        if point_in_time_epoch_seconds < self.get_this_update() {
            return false;
        }
        true
    }

    /// Return the revocation status of a certificate if its `serial_numer` is
    /// present in the CRL.
    pub fn get_certificate_status(&self, serial_number: SerialNumber) -> Option<(ReasonCode, u64)> {
        let revoked_certificate =
            self.crl
                .tbs_cert_list
                .revoked_certificates
                .iter()
                .find(|revoked_certificate| {
                    serial_number.eq(&SerialNumber::from_rasn_type(
                        &revoked_certificate.user_certificate,
                    ))
                });
        revoked_certificate
            .map(|revoked_certificate| {
                let revocation_date_epoch_seconds = crate::encdec::rasn::from_rasn_epoch_seconds(
                    &revoked_certificate.revocation_date,
                );
                let mut invalid_from_epoch_seconds = revocation_date_epoch_seconds;
                let mut crl_reason = ReasonCode::Unspecified;
                if let Some(crl_entry_extensions) =
                    &CrlEntryExtensions::from_rasn_type(&revoked_certificate.crl_entry_extensions)
                {
                    crl_reason = crl_entry_extensions.get_reason_code();
                    if let Some(invalidity_date_epoch_seconds) =
                        crl_entry_extensions.get_invalidity_date_epoch_seconds()
                    {
                        invalid_from_epoch_seconds = std::cmp::min(
                            invalid_from_epoch_seconds,
                            invalidity_date_epoch_seconds,
                        );
                    } else {
                        // Depending on the reson code we might nee to take different actions
                        // e.g. OnHold -> use revocation_date (no action)
                        // e.g. KeyCompromise -> use start of cert (->0)
                        match crl_reason {
                            ReasonCode::Unspecified
                            | ReasonCode::KeyCompromise
                            | ReasonCode::CaCompromise => {
                                // Assume the worst
                                invalid_from_epoch_seconds = 0;
                            }
                            _ => {}
                        }
                    }
                }
                (crl_reason, invalid_from_epoch_seconds)
            })
            .filter(|(crl_reason, _invalid_from_epoch_seconds)| {
                !ReasonCode::RemoveFromCrl.eq(crl_reason)
            })
    }

    /// Return the [crate::cert::extensions::AuthorityKeyIdentifier] `key_identifier` bytes if present.
    pub fn get_authority_key_identifier_kid(&self) -> Option<Vec<u8>> {
        self.crl_extensions
            .as_ref()
            .and_then(CrlExtensions::get_authority_key_identifier_kid)
    }

    /// Return the all [WellKnownGeneralName] if present.
    pub fn get_issuer_alternative_name(&self) -> Vec<(WellKnownGeneralName, String)> {
        self.crl_extensions
            .as_ref()
            .map(CrlExtensions::get_issuer_alternative_name)
            .unwrap_or_default()
    }

    /// Return the [CrlNumber] if present.
    pub fn get_crl_number(&self) -> Option<CrlNumber> {
        self.crl_extensions
            .as_ref()
            .and_then(CrlExtensions::get_crl_number)
    }

    /// Return the Delta CRL indicator base [CrlNumber] if present.
    pub fn get_delta_crl_indicator(&self) -> Option<CrlNumber> {
        self.crl_extensions
            .as_ref()
            .and_then(CrlExtensions::get_delta_crl_indicator)
    }

    /// Return the [crate::crl::crl_extensions::IssuingDistributionPoint] if present. Return an Err when present in an unsupported format.
    pub fn get_issuing_distribution_point(&self) -> Result<Option<String>, CrlParsingError> {
        self.crl_extensions
            .as_ref()
            .map(CrlExtensions::get_issuing_distribution_point)
            .unwrap_or(Ok(None))
    }

    /// Return freshest/delta CRL distribution point. Preferr http over ldap. The scope etc is implied by the full CRL.
    pub fn get_crl_distribution_point(&self) -> Option<String> {
        self.crl_extensions
            .as_ref()
            .and_then(CrlExtensions::get_crl_distribution_point)
    }

    /// Return the `id-ad-caIssuers` [AuthorityInfoAccessDescription] if present.
    pub fn get_authority_information_access(&self) -> Option<AuthorityInfoAccessDescription> {
        self.crl_extensions
            .as_ref()
            .and_then(CrlExtensions::get_authority_information_access)
    }
}
