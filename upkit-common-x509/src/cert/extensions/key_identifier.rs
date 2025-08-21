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

//! X.509 Certificate AuthorityKeyIdentifier and SubjectKeyIdentifier.

use rasn::types::OctetString;
use tyst::Tyst;
use tyst::traits::se::PublicKey;

/// Authority Key Identifier as defined in [RFC5280 4.2.1.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1).
pub struct AuthorityKeyIdentifier {
    aki: rasn_pkix::AuthorityKeyIdentifier,
}

impl AuthorityKeyIdentifier {
    /// joint-iso-ccitt(2) ds(5) ce(29) subjectKeyIdentifier (35)
    pub const OID: &[u32] = &[2, 5, 29, 35];

    /// Return the key identifier as bytes.
    pub fn get_key_identifier(&self) -> Option<Vec<u8>> {
        self.aki.key_identifier.as_ref().map(|ki| ki.to_vec())
    }

    /// Make an exact byte copy of the issuers Subject Key Identifier.
    pub fn from_issuers_subject_key_identifier(issuer_subject_key_identifier: &[u8]) -> Self {
        Self {
            aki: rasn_pkix::AuthorityKeyIdentifier {
                key_identifier: Some(rasn_pkix::SubjectKeyIdentifier::from_slice(
                    issuer_subject_key_identifier,
                )),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
        }
    }

    /// Return an AKI where only the key identifier fields is populated.
    pub fn from_public_key(public_key: &dyn PublicKey) -> Self {
        Self {
            aki: rasn_pkix::AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::from(
                    SubjectKeyIdentifier::get_key_identifier_bytes(public_key),
                )),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
        }
    }

    /// Return a new instances from the matching extension.
    pub fn from_rasn_extension(extension: rasn_pkix::Extension) -> Self {
        Self::from_rasn_type(&crate::encdec::rasn::from_rasn_extension(
            Self::OID,
            &extension,
        ))
    }

    /// Return a new instances from the matching extension.
    fn from_rasn_type(authority_key_identifier: &rasn_pkix::AuthorityKeyIdentifier) -> Self {
        Self {
            aki: authority_key_identifier.to_owned(),
        }
    }

    /// Return an AKI where only the key identifier fields is populated.
    pub fn to_rasn_type(&self) -> &rasn_pkix::AuthorityKeyIdentifier {
        &self.aki
    }
}

/// Subject Key Identifier as defined in [RFC5280 4.2.1.2](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2).
pub struct SubjectKeyIdentifier {
    ski: rasn_pkix::SubjectKeyIdentifier,
}

impl SubjectKeyIdentifier {
    /// joint-iso-ccitt(2) ds(5) ce(29) subjectKeyIdentifier (14)
    pub const OID: &[u32] = &[2, 5, 29, 14];

    /// Return the key identifier as bytes.
    pub fn get_key_identifier(&self) -> Vec<u8> {
        self.ski.to_vec()
    }

    /// Return a new instance
    pub fn from_public_key(public_key: &dyn PublicKey) -> Self {
        Self {
            ski: OctetString::from(Self::get_key_identifier_bytes(public_key)),
        }
    }

    /// Return a new instances from the matching extension.
    pub fn from_rasn_extension(extension: rasn_pkix::Extension) -> Self {
        Self::from_rasn_type(&crate::encdec::rasn::from_rasn_extension(
            Self::OID,
            &extension,
        ))
    }

    /// Return a new instances from the matching extension.
    fn from_rasn_type(subject_key_identifier: &rasn_pkix::SubjectKeyIdentifier) -> Self {
        Self {
            ski: subject_key_identifier.to_owned(),
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> &rasn_pkix::SubjectKeyIdentifier {
        &self.ski
    }

    /** Calculate KID similar to RFC 5280 type 1 identifier.

    SHA3-256 is not strictly neccessary according to the (now old) RFC5280, but
    this decrease collission risk conciderable and allows SHA-1 to be phased out
    at the cost of 12 additional bytes per KeyIdentifier.
    */
    pub fn get_key_identifier_bytes(public_key: &dyn PublicKey) -> Vec<u8> {
        Tyst::instance()
            .digests()
            .by_name("SHA3-256")
            .unwrap()
            .hash(&public_key.try_as_raw().unwrap())
    }
}
