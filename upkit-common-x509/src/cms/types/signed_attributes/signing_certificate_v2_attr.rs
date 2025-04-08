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

//! SigningCertificateV2 attribute.

use crate::cert::parse::CertificateParser;
use rasn::types::OctetString;
use rasn_pkix::GeneralName;
use rasn_smime::ess::IssuerSerial;
use tyst::Tyst;

/** SigningCertificateV2 attribute.

The purpose of this attribute to link a specific signing certificate to the
signature by including a hash of the certificate.

The attribute is defined in [RFC 5035](https://www.rfc-editor.org/rfc/rfc5035).
*/
pub struct SigningCertificateV2Attribute {
    hash_algorithm: Vec<u32>,
    cert_hash: Vec<u8>,
    issuer_serial: Option<IssuerSerial>,
}

impl SigningCertificateV2Attribute {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) id-aa(2) signingCertificateV2(47)
    pub const OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 2, 47];

    /// Return a new instance.
    pub fn new(signing_cert: &CertificateParser, digest_algorithm_oid: &[u32]) -> Self {
        let cert_hash = Tyst::instance()
            .digests()
            .by_oid(&tyst::encdec::oid::as_string(digest_algorithm_oid))
            .unwrap()
            .hash(&signing_cert.to_bytes().unwrap());
        let issuer_serial = Some(IssuerSerial {
            issuer: vec![GeneralName::DirectoryName(
                rasn::der::decode(&signing_cert.get_encoded_issuer()).unwrap(),
            )],
            serial_number: signing_cert.get_serial_number().to_rasn_type(),
        });
        Self {
            hash_algorithm: digest_algorithm_oid.to_vec(),
            cert_hash,
            issuer_serial,
        }
    }

    /// Return `true` if the hash of the DER encoded signing certificate matches
    /// the hash of this extension.
    pub fn is_signing_certificate(
        &self,
        signing_cert: &CertificateParser,
        digest_algorithm_oid: &[u32],
    ) -> bool {
        if !self.hash_algorithm.eq(digest_algorithm_oid) {
            return false;
        }
        let cert_hash = Tyst::instance()
            .digests()
            .by_oid(&tyst::encdec::oid::as_string(self.get_hash_algorithm()))
            .unwrap()
            .hash(&signing_cert.to_bytes().unwrap());
        cert_hash.eq(self.get_cert_hash())
    }

    /// Return the used hash algorithm's object identifier.
    fn get_hash_algorithm(&self) -> &[u32] {
        &self.hash_algorithm
    }

    /// Return the hash of the DER encoded signing certificate.
    fn get_cert_hash(&self) -> &[u8] {
        &self.cert_hash
    }

    /// Return a new instance from the DER encoded attribute value.
    pub fn from_encoded(der_encoded: &[u8]) -> Option<Self> {
        rasn::der::decode::<rasn_smime::ess::SigningCertificateV2>(der_encoded)
            .ok()
            .and_then(|signing_certificate| {
                signing_certificate
                    .certs
                    .first()
                    .map(|ess_cert_id_v2| Self {
                        hash_algorithm: ess_cert_id_v2.hash_algorithm.algorithm.to_vec(),
                        cert_hash: ess_cert_id_v2.cert_hash.to_vec(),
                        // Ignore parsing of issuer+serial number since these are mainly used
                        // for lookup of the signing certificate from a cert store.
                        issuer_serial: None,
                    })
            })
    }

    /// Return the DER encoded attribute value.
    pub fn to_encoded(&self) -> Vec<u8> {
        rasn::der::encode(&rasn_smime::ess::SigningCertificateV2 {
            certs: vec![rasn_smime::ess::EssCertIdv2 {
                hash_algorithm: crate::encdec::rasn::oid_as_algorithm_identifier(
                    &self.hash_algorithm,
                ),
                cert_hash: OctetString::from(self.cert_hash.to_vec()),
                issuer_serial: self.issuer_serial.to_owned(),
            }],
            policies: None,
        })
        .unwrap()
    }
}
