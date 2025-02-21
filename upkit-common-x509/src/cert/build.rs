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

//! X.509 Certificate build.

use super::extensions::Extensions;
use super::types::DistinguishedName;
use super::types::SerialNumber;
use super::types::Validity;
use rasn::prelude::Any;
use rasn::types::BitString;
use rasn::types::ObjectIdentifier;
use rasn_pkix::AlgorithmIdentifier;
use rasn_pkix::TbsCertificate;
use rasn_pkix::Version;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;
use tyst::traits::se::PublicKey;

/** Unsigned TBSCertificate in preparation for signing.

This allows assembly and encoding of all relevent pieces of information that
goes into a certificate except for the actual signing of the data-structure.

[RFC5280](https://datatracker.ietf.org/doc/html/rfc5280) ASN.1 encoding:

```text
TBSCertificate  ::=  SEQUENCE  {
    version         [0]  EXPLICIT Version DEFAULT v1,
    serialNumber         CertificateSerialNumber,
    signature            AlgorithmIdentifier,
    issuer               Name,
    validity             Validity,
    subject              Name,
    subjectPublicKeyInfo SubjectPublicKeyInfo,
    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                         -- If present, version MUST be v2 or v3
    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                         -- If present, version MUST be v2 or v3
    extensions      [3]  EXPLICIT Extensions OPTIONAL
                         -- If present, version MUST be v3
    }
```

*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct NoSignatureTbsCertificate {
    tbs_certificate_b64: Vec<u8>,
}

impl NoSignatureTbsCertificate {
    /// [RFC2797 3.3.3.1](https://datatracker.ietf.org/doc/html/rfc2797#section-3.3.3.1)
    /// (CMS) defines `id-alg-noSignature` as `1.3.6.1.5.5.7.6.2`.
    ///
    /// Even though this isn't normally used in the context of a
    /// `TBSCertificate`, it will be quite easy for external parties to find and
    /// interpret as a placeholder.
    pub const OID_NO_SIGNATURE: &'static [u32] = &[1, 3, 6, 1, 5, 5, 7, 6, 2];

    /// Return a new instance.
    pub fn new(
        issuer: DistinguishedName,
        not_after_epoch_seconds: u64,
        subject: DistinguishedName,
        subject_public_key: &dyn PublicKey,
        extensions: Extensions,
    ) -> Self {
        let subject_public_key_info =
            rasn::der::decode(&subject_public_key.try_as_spki().unwrap()).unwrap();
        let tbs_certificate = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::default().to_rasn_type(),
            signature: Self::no_signature_algorithm_identifier(),
            issuer: issuer.as_rasn_type().unwrap(),
            validity: Validity::with_backdated_not_before_now(not_after_epoch_seconds)
                .to_rasn_type(),
            subject: subject.as_rasn_type().unwrap(),
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: extensions.to_rasn_type(),
        };
        Self::from_rasn_type(&tbs_certificate)
    }

    /// See [Self::OID_NO_SIGNATURE].
    fn no_signature_algorithm_identifier() -> AlgorithmIdentifier {
        AlgorithmIdentifier {
            algorithm: ObjectIdentifier::new_unchecked(Self::OID_NO_SIGNATURE.into()),
            parameters: Some(Any::new(rasn::der::encode(&()).unwrap())),
        }
    }

    /// Get the TBSCertificate with an updated `TBSCertificate.signature` as bytes.
    ///
    /// This is the data that the issuer should sign.
    pub fn with_signature_algorithm_as_bytes(&self, signature_algorithm: &[u8]) -> Vec<u8> {
        let mut tbs_certificate =
            rasn::der::decode::<TbsCertificate>(&self.tbs_certificate_b64).unwrap();
        tbs_certificate.signature = rasn::der::decode(signature_algorithm).unwrap();
        rasn::der::encode(&tbs_certificate).unwrap()
    }

    /// Transform the TBSCertificate into a signed Certificate.
    pub fn to_certificate(
        &self,
        signature_algorithm: &[u8],
        signature: Vec<u8>,
    ) -> rasn_pkix::Certificate {
        let mut tbs_certificate =
            rasn::der::decode::<TbsCertificate>(&self.tbs_certificate_b64).unwrap();
        tbs_certificate.signature = rasn::der::decode(signature_algorithm).unwrap();
        let signature_algorithm = tbs_certificate.signature.clone();
        let signature_value = BitString::from_vec(signature);
        rasn_pkix::Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        }
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(tbs_certificate: &TbsCertificate) -> Self {
        if !Self::no_signature_algorithm_identifier().eq(&tbs_certificate.signature) {
            log::debug!("Provided TBSCertificate did not use 'id-alg-noSignature' as signature algorithm. Allowing this to proceed anyway.");
        }
        Self {
            tbs_certificate_b64: rasn::der::encode(tbs_certificate).unwrap(),
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> TbsCertificate {
        rasn::der::decode(&self.tbs_certificate_b64).unwrap()
    }
}
