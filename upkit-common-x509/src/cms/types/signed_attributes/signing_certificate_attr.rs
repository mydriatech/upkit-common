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

//! SigningCertificate attribute.

use crate::cert::parse::CertificateParser;
use rasn::types::OctetString;
use rasn_pkix::GeneralName;
use rasn_smime::ess::IssuerSerial;
use tyst::Tyst;

/** SigningCertificate attribute.

Originally defined in [RFC 2634](https://www.rfc-editor.org/rfc/rfc2634), the
purpose of this attribute to link a specific signing certificate to the
signature by including a `SHA-1` hash of the certificate.

To allow other message digest algorithms to be used, this was updated by
[RFC 5035](https://www.rfc-editor.org/rfc/rfc5035) and the version 2 of this
attribute is implemented in [super::SigningCertificateV2Attribute].
*/
pub struct SigningCertificateAttribute {
    cert_hash: Vec<u8>,
    issuer_serial: Option<IssuerSerial>,
}

impl SigningCertificateAttribute {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) id-aa(2) signingCertificate(12)
    pub const OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 2, 12];
    /// iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)
    pub const OID_SHA1: &[u32] = &[1, 3, 14, 3, 2, 26];

    /// Return a new instance.
    pub fn new(signing_cert: &CertificateParser) -> Self {
        let cert_hash = Tyst::instance()
            .digests()
            .by_oid(&tyst::encdec::oid::as_string(Self::OID_SHA1))
            .unwrap()
            .hash(&signing_cert.to_bytes().unwrap());
        let issuer_serial = Some(IssuerSerial {
            issuer: vec![GeneralName::DirectoryName(
                rasn::der::decode(&signing_cert.get_encoded_issuer()).unwrap(),
            )],
            serial_number: signing_cert.get_serial_number().to_rasn_type(),
        });
        Self {
            cert_hash,
            issuer_serial,
        }
    }

    /// Return `true` if the hash of the DER encoded signing certificate matches
    /// the SHA-1 hash of this extension.
    pub fn is_signing_certificate(&self, signing_cert: &CertificateParser) -> bool {
        let cert_hash = Tyst::instance()
            .digests()
            .by_oid(&tyst::encdec::oid::as_string(self.get_hash_algorithm()))
            .unwrap()
            .hash(&signing_cert.to_bytes().unwrap());
        cert_hash.eq(self.get_cert_hash())
    }

    /// Return the used hash algorithm's object identifier.
    fn get_hash_algorithm(&self) -> &[u32] {
        Self::OID_SHA1
    }

    /// Return the hash of the DER encoded signing certificate.
    fn get_cert_hash(&self) -> &[u8] {
        &self.cert_hash
    }

    /// Return a new instance from the DER encoded attribute value.
    pub fn from_encoded(der_encoded: &[u8]) -> Option<Self> {
        rasn::der::decode::<rasn_smime::ess::SigningCertificate>(der_encoded)
            .ok()
            .and_then(|signing_certificate| {
                signing_certificate.certs.first().map(|ess_cert_id| Self {
                    cert_hash: ess_cert_id.cert_hash.to_vec(),
                    // Ignore parsing of issuer+serial number since these are mainly used
                    // for lookup of the signing certificate from a cert store.
                    issuer_serial: None,
                })
            })
    }

    /// Return the DER encoded attribute value.
    pub fn to_encoded(&self) -> Vec<u8> {
        rasn::der::encode(&rasn_smime::ess::SigningCertificate {
            certs: vec![rasn_smime::ess::EssCertId {
                cert_hash: OctetString::from(self.cert_hash.to_vec()),
                issuer_serial: self.issuer_serial.to_owned(),
            }],
            policies: None,
        })
        .unwrap()
    }
}
