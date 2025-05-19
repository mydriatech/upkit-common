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

//! PKCS#10 Certification request building.

use tyst::Tyst;
use tyst::traits::se::{PrivateKey, PublicKey};

use crate::cert::extensions::Extensions;
use crate::cert::types::DistinguishedName;
use crate::pkcs10::pkcs10_asn1 as asn1;
use crate::pkcs10::types::CertificationRequestInfoAttributes;

/** PKCS#10 Certification Request.

[RFC 2986 4](https://www.rfc-editor.org/rfc/rfc2986#section-4):

```text
   CertificationRequestInfo ::= SEQUENCE {
        version       INTEGER { v1(0) } (v1,...),
        subject       Name,
        subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
        attributes    [0] Attributes{{ CRIAttributes }}
   }

   ...

   CRIAttributes  ATTRIBUTE  ::= {
        ... -- add any locally defined attributes here -- }

   CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }
```
*/
pub struct CertificationRequest {
    certification_request: Vec<u8>,
}

impl CertificationRequest {
    /// Return a new instance.
    pub fn new(
        dn: &DistinguishedName,
        signature_algorithm_oid: &[u32],
        subject_public_key: &dyn PublicKey,
        subject_private_key: &dyn PrivateKey,
        extensions: Option<&Extensions>,
    ) -> Self {
        let certification_request_info = asn1::CertificationRequestInfo {
            version: 0.into(),
            subject: dn.as_rasn_type().unwrap(),
            subject_pk_info: rasn::der::decode(&subject_public_key.try_as_spki().unwrap()).unwrap(),
            attributes: CertificationRequestInfoAttributes::default()
                .set_extension_request(extensions)
                .to_rasn_type(),
        };
        let message = rasn::der::encode(&certification_request_info).unwrap();
        let mut se = Tyst::instance()
            .ses()
            .by_oid(&tyst::encdec::oid::as_string(signature_algorithm_oid))
            .unwrap();
        let signature = se.sign(subject_private_key, &message).unwrap();

        let certification_request = asn1::CertificationRequest {
            certification_request_info,
            signature_algorithm: crate::encdec::rasn::oid_as_algorithm_identifier(
                signature_algorithm_oid,
            ),
            signature: rasn::types::BitString::from_vec(signature),
        };
        Self {
            certification_request: rasn::der::encode(&certification_request).unwrap(),
        }
    }

    /// Return the DER encoded object as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.certification_request
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> asn1::CertificationRequest {
        rasn::der::decode(&self.certification_request).unwrap()
    }
}
