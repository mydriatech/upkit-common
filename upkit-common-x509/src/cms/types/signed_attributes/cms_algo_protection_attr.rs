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

//! CMSAlgorithmProtection attribute.

use crate::cms::cms_asn1 as asn1;

/** CMSAlgorithmProtection attribute.

By default in RFC 5652, only the message digest (and not the message digest
algorithm identifier) is protected by a signature.

The assumptions of the digest algorithm can be found in
[RFC 5652 5.4](https://www.rfc-editor.org/rfc/rfc5652#section-5.4).

If the verifier accepts a weak digest algorithm with the same output size and an
attacker could craft arbitrary content with the same fingerprint using the
weaker digest algorithm.

An alternative to validating this extension could be to only allows a trusted
set of message digest and signature algorithms.


[RFC 6211 2](https://www.rfc-editor.org/rfc/rfc6211#section-2) :

```text
   CMSAlgorithmProtection ::= SEQUENCE {
       digestAlgorithm         DigestAlgorithmIdentifier,
       signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
       macAlgorithm        [2] MessageAuthenticationCodeAlgorithm
                                        OPTIONAL
   }
   (WITH COMPONENTS { signatureAlgorithm PRESENT,
                      macAlgorithm ABSENT } |
    WITH COMPONENTS { signatureAlgorithm ABSENT,
                      macAlgorithm PRESENT })
```

## Security Note

The simplified algorithm identifier (without parameters) will partially mitigate
the purpose of this attribute for signature algorithms that rely on parameters.

## References

* [RFC 6211](https://www.rfc-editor.org/rfc/rfc6211) CMS Algorithm Identifier Protection Attribute
* [RFC 8933](https://www.rfc-editor.org/rfc/rfc8933) Update to the CMS for Algorithm Identifier Protection
*/
pub struct CmsAlgorithmProtectionAttribute {
    digest_algorithm_oid: Vec<u32>,
    signature_algorithm_oid: Vec<u32>,
}

impl CmsAlgorithmProtectionAttribute {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) cmsAlgorithmProtection(52))
    pub const OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 52];

    /// Return a new instance.
    pub fn new(digest_algorithm_oid: &[u32], signature_algorithm_oid: &[u32]) -> Self {
        Self {
            digest_algorithm_oid: digest_algorithm_oid.to_vec(),
            signature_algorithm_oid: signature_algorithm_oid.to_vec(),
        }
    }

    /// The object identifier of the signature algorithm used to hash the CMS
    /// SignedData.encapContentInfo.eContent.
    pub fn get_digest_algorithm_oid(&self) -> &[u32] {
        &self.digest_algorithm_oid
    }

    /// The object identifier of the signature algorithm used to sign the CMS.
    pub fn get_signature_algorithm_oid(&self) -> &[u32] {
        &self.signature_algorithm_oid
    }

    /// Return a new instance from the DER encoded attribute value.
    pub fn from_encoded(der_encoded: &[u8]) -> Option<Self> {
        rasn::der::decode::<asn1::CmsAlgorithmProtection>(der_encoded)
            .ok()
            .and_then(|cap| {
                cap.signature_algorithm.map(|signature_algorithm| Self {
                    digest_algorithm_oid: cap.digest_algorithm.algorithm.to_vec(),
                    signature_algorithm_oid: signature_algorithm.algorithm.to_vec(),
                })
            })
    }

    /// Return the DER encoded attribute value.
    pub fn to_encoded(&self) -> Vec<u8> {
        rasn::der::encode(&asn1::CmsAlgorithmProtection {
            digest_algorithm: crate::encdec::rasn::oid_as_algorithm_identifier(
                &self.digest_algorithm_oid,
            ),
            signature_algorithm: Some(crate::encdec::rasn::oid_as_algorithm_identifier(
                &self.signature_algorithm_oid,
            )),
            mac_algorithm: None,
        })
        .unwrap()
    }
}
