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

//! OCSP PreferredSignatureAlgorithms.

use crate::ocsp::ocsp_asn1 as asn1;

/** OCSP PreferredSignatureAlgorithms request extension.

[RFC 6960 4.4.7](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.7):

```text
   PreferredSignatureAlgorithms ::= SEQUENCE OF
                                    PreferredSignatureAlgorithm

   PreferredSignatureAlgorithm ::= SEQUENCE {
      sigIdentifier        AlgorithmIdentifier,
      pubKeyAlgIdentifier  SMIMECapability OPTIONAL
```

See also [RFC 6960 4.3](https://www.rfc-editor.org/rfc/rfc6960#section-4.3)
where legacy algorithm sha256WithRSAEncryption are SHALL, but modern algorithms
are MAY.

NOTE/TODO: Currently the parameters will be ignored which is oversimplified!
*/
#[derive(PartialEq, Eq)]
pub struct PreferredSignatureAlgorithms {
    preferred_signature_algorithms_oids: Vec<Vec<u32>>,
}

impl Default for PreferredSignatureAlgorithms {
    fn default() -> Self {
        Self::new(&[Self::OID_SHA_256_WITH_RSA_ENCRYPTION.to_vec()])
    }
}

impl PreferredSignatureAlgorithms {
    /// iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(48) id-ad-ocsp(1) id-pkix-ocsp-pref-sig-algs(8)
    pub const OID: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 8];
    // iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha256WithRSAEncryption(11)
    const OID_SHA_256_WITH_RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113549, 1, 1, 11];

    /// Return a new instance with signature algorithms preferred by the OCSP
    /// client.
    pub fn new(preferred_signature_algorithms_oids: &[Vec<u32>]) -> Self {
        Self {
            preferred_signature_algorithms_oids: preferred_signature_algorithms_oids.to_vec(),
        }
    }

    /// Return signature algorithms preferred by the OCSP client.
    pub fn get_preferred_signature_algorithms(
        &self,
    ) -> Vec<(Vec<u32>, Option<String>, Option<String>)> {
        self.preferred_signature_algorithms_oids
            .iter()
            .map(|sign_alg_oid| (sign_alg_oid.to_vec(), None::<String>, None::<String>))
            .collect::<Vec<_>>()
    }

    /// Return extension in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_extension(&self) -> rasn_pkix::Extension {
        crate::encdec::rasn::to_rasn_extension(Self::OID, false, &self.to_rasn_type())
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    fn to_rasn_type(&self) -> asn1::PreferredSignatureAlgorithms {
        self.preferred_signature_algorithms_oids
            .iter()
            .map(|oid| asn1::PreferredSignatureAlgorithm {
                sig_identifier: crate::encdec::rasn::oid_as_algorithm_identifier(oid),
                pub_key_alg_identifier: None,
            })
            .collect()
    }

    /// Return a new instances from the matching extension.
    pub fn from_rasn_extension(extension: rasn_pkix::Extension) -> Self {
        Self::from_rasn_type(&crate::encdec::rasn::from_rasn_extension(
            Self::OID,
            &extension,
        ))
    }

    /// Return a new instances from the ASN.1 library `rasn` type.
    fn from_rasn_type(preferred_signature_algorithms: &asn1::PreferredSignatureAlgorithms) -> Self {
        let list =
        preferred_signature_algorithms.iter().map(|psa|{
            let signature_algorithm_oid = psa.sig_identifier
                .algorithm
                .to_vec();
            // Example from RFC: algorithm=id-ecPublicKey and parameters= secp256r1.
            // iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) ecPublicKey(1)
            const OID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10045, 2, 1];
            let public_key_algorithm = None::<String>;
            let public_key_params = None::<String>;
            if let Some(capability) = &psa.pub_key_alg_identifier {
                match capability.capability_id.as_ref() {
                    OID_EC_PUBLIC_KEY => {
                        log::debug!("Preferred sig algorithm params for 'id-ecPublicKey' is not implemented yet.")
                    }
                    unknown => {
                        log::debug!("Preferred sig algorithm params for '{unknown:?}' is not implemented yet.")
                    }
                };
            }
            (signature_algorithm_oid, public_key_algorithm, public_key_params)
        }).collect::<Vec<_>>();
        Self {
            preferred_signature_algorithms_oids: list
                .iter()
                .map(
                    |(signature_algorithm_oid, _public_key_algorithm, _public_key_params)| {
                        signature_algorithm_oid.to_vec()
                    },
                )
                .collect::<Vec<_>>(),
        }
    }
}
