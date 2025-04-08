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

//! CMS SignedAttributes.

mod cms_algo_protection_attr;
mod content_type_attr;
mod message_digest_attr;
mod signing_certificate_attr;
mod signing_certificate_v2_attr;

use crossbeam_skiplist::SkipMap;
use rasn::types::{Any, ObjectIdentifier, SetOf};
use rasn_cms::Attribute;

use crate::cert::parse::CertificateParser;

pub use self::cms_algo_protection_attr::CmsAlgorithmProtectionAttribute;
pub use self::content_type_attr::ContentTypeAttribute;
pub use self::message_digest_attr::MessageDigestAttribute;
pub use self::signing_certificate_attr::SigningCertificateAttribute;
pub use self::signing_certificate_v2_attr::SigningCertificateV2Attribute;

/** CMS SignedAttributes.

Additional values besides the `eContent` that is covered by SignedData
signatures.

[RFC 5652 5.3](https://www.rfc-editor.org/rfc/rfc5652#section-5.3):


```text
   SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

   Attribute ::= SEQUENCE {
     attrType OBJECT IDENTIFIER,
     attrValues SET OF AttributeValue }

   AttributeValue ::= ANY
```

## Note

Only single valued attributes are supported and if multiple attributes of with
the same OID are present, the last one of these will be used.
*/
#[derive(Default)]
pub struct SignedAttributes {
    attribute_by_oid: SkipMap<Vec<u32>, Vec<u8>>,
}

impl SignedAttributes {
    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn from_rasn_type(signed_attrs: &Option<SetOf<Attribute>>) -> Self {
        Self {
            attribute_by_oid: SkipMap::from_iter(
                signed_attrs
                    .as_ref()
                    .unwrap()
                    .to_vec()
                    .into_iter()
                    .map(|attribute| {
                        (
                            attribute.r#type.to_vec(),
                            attribute
                                .values
                                .to_vec()
                                // Only support single valued attributes
                                .first()
                                .map(|any| any.as_bytes().to_vec())
                                .unwrap_or_default(),
                        )
                    }),
            ),
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> SetOf<Attribute> {
        rasn::types::SetOf::from_vec(
            self.attribute_by_oid
                .iter()
                .map(|entry| Attribute {
                    r#type: ObjectIdentifier::new_unchecked(entry.key().to_vec().into()),
                    values: vec![Any::new(entry.value().to_owned())].into(),
                })
                .collect(),
        )
    }

    /// Return the first DER encoded attribute value of the last attribute with
    /// this object identifier.
    fn get_attribute_by_oid(&self, oid: &[u32]) -> Option<Vec<u8>> {
        self.attribute_by_oid
            .get(oid)
            .map(|entry| entry.value().to_vec())
    }

    /// Return `true` if CMS was hashed and signed by the provided algorithms.
    ///
    /// See  [CmsAlgorithmProtectionAttribute].
    pub fn is_cms_algo_protection(
        &self,
        digest_algorithm_oid: &[u32],
        signature_algorithm_oid: &[u32],
    ) -> bool {
        self.get_cms_algo_protection().is_some_and(|capa| {
            capa.get_digest_algorithm_oid().eq(digest_algorithm_oid)
                && capa
                    .get_signature_algorithm_oid()
                    .eq(signature_algorithm_oid)
        })
    }

    /// Get the [CmsAlgorithmProtectionAttribute].
    fn get_cms_algo_protection(&self) -> Option<CmsAlgorithmProtectionAttribute> {
        self.get_attribute_by_oid(CmsAlgorithmProtectionAttribute::OID)
            .as_ref()
            .map(|value| value as &[u8])
            .and_then(CmsAlgorithmProtectionAttribute::from_encoded)
    }

    /// Specify the algorithms the CMS will be hashed and signed with.
    ///
    /// See  [CmsAlgorithmProtectionAttribute].
    pub fn set_cms_algo_protection(
        self,
        digest_algorithm_oid: &[u32],
        signature_algorithm_oid: &[u32],
    ) -> Self {
        self.attribute_by_oid.insert(
            CmsAlgorithmProtectionAttribute::OID.to_vec(),
            CmsAlgorithmProtectionAttribute::new(digest_algorithm_oid, signature_algorithm_oid)
                .to_encoded(),
        );
        self
    }

    /// Return `true` if signed content is of the exected type.
    ///
    /// See  [ContentTypeAttribute].
    pub fn is_content_type(&self, content_type_oid: &[u32]) -> bool {
        self.get_content_type()
            .is_some_and(|cta| cta.get_content_type_oid().eq(content_type_oid))
    }

    /// Get the [ContentTypeAttribute].
    fn get_content_type(&self) -> Option<ContentTypeAttribute> {
        self.get_attribute_by_oid(ContentTypeAttribute::OID)
            .as_ref()
            .map(|value| value as &[u8])
            .and_then(ContentTypeAttribute::from_encoded)
    }

    /// Specify the object identifier for the signed content.
    ///
    /// See  [ContentTypeAttribute].
    pub fn set_content_type(self, content_type_oid: &[u32]) -> Self {
        self.attribute_by_oid.insert(
            ContentTypeAttribute::OID.to_vec(),
            ContentTypeAttribute::new(content_type_oid).to_encoded(),
        );
        self
    }

    /// Return `true` if message digest of the content matches the provided one.
    ///
    /// See  [MessageDigestAttribute].
    pub fn is_message_digest(&self, content_digest: &[u8]) -> bool {
        self.get_message_digest()
            .is_some_and(|mda| mda.get_message_digest().eq(content_digest))
    }

    /// Get the [MessageDigestAttribute].
    fn get_message_digest(&self) -> Option<MessageDigestAttribute> {
        self.get_attribute_by_oid(MessageDigestAttribute::OID)
            .as_ref()
            .map(|value| value as &[u8])
            .and_then(MessageDigestAttribute::from_encoded)
    }

    /// Specify the message digest of the signed content.
    ///
    /// See  [MessageDigestAttribute].
    pub fn set_message_digest(self, message_digest: &[u8]) -> Self {
        self.attribute_by_oid.insert(
            MessageDigestAttribute::OID.to_vec(),
            MessageDigestAttribute::new(message_digest).to_encoded(),
        );
        self
    }

    /// Return `true` if signing certificate was used to sign the CMS.
    ///
    /// See  [SigningCertificateAttribute] and [SigningCertificateV2Attribute].
    pub fn is_signing_certificate(
        &self,
        signing_cert: &CertificateParser,
        digest_algorithm_oid: &[u32],
    ) -> bool {
        /*
        When the SHA-1 hash function is used, the SigningCertificate attribute
        MUST be used.
        The SigningCertificateV2 attribute MUST be used if any algorithm other
        than SHA-1 is used and SHOULD NOT be used for SHA-1.
        */
        if digest_algorithm_oid.eq(SigningCertificateAttribute::OID_SHA1) {
            self.get_signing_certificate_v1()
                .is_some_and(|scv1a| scv1a.is_signing_certificate(signing_cert))
        } else {
            self.get_signing_certificate_v2().is_some_and(|scv2a| {
                scv2a.is_signing_certificate(signing_cert, digest_algorithm_oid)
            })
        }
    }

    /// Specify the signing certificate that will be used to sign the CMS.
    ///
    /// See [SigningCertificateAttribute] and [SigningCertificateV2Attribute].
    pub fn set_signing_certificate_digests(
        self,
        signing_cert: &CertificateParser,
        digest_algorithm_oid: &[u32],
    ) -> Self {
        // See comment in is_signing_certificate()
        if digest_algorithm_oid.eq(SigningCertificateAttribute::OID_SHA1) {
            self.attribute_by_oid.insert(
                SigningCertificateAttribute::OID.to_vec(),
                SigningCertificateAttribute::new(signing_cert).to_encoded(),
            );
        } else {
            self.attribute_by_oid.insert(
                SigningCertificateV2Attribute::OID.to_vec(),
                SigningCertificateV2Attribute::new(signing_cert, digest_algorithm_oid).to_encoded(),
            );
        }
        self
    }

    /// Get the [SigningCertificateAttribute].
    fn get_signing_certificate_v1(&self) -> Option<SigningCertificateAttribute> {
        self.get_attribute_by_oid(SigningCertificateAttribute::OID)
            .as_ref()
            .map(|value| value as &[u8])
            .and_then(SigningCertificateAttribute::from_encoded)
    }

    /// Get the [SigningCertificateV2Attribute].
    fn get_signing_certificate_v2(&self) -> Option<SigningCertificateV2Attribute> {
        self.get_attribute_by_oid(SigningCertificateV2Attribute::OID)
            .as_ref()
            .map(|value| value as &[u8])
            .and_then(SigningCertificateV2Attribute::from_encoded)
    }
}
