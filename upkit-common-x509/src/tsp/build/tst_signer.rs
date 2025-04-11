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

//! Time-Stamp Token Signer and validation information.

use crate::cert::parse::CertificateParser;
use crate::tsp::types::TimeStampToken;
use std::sync::Arc;
use tyst::traits::se::PrivateKey;

/// Encoded revocation information holder.
pub enum RevocationInfoVariant {
    /// The encoded data is a X.509 CRL.
    Crl {
        #[allow(missing_docs)]
        encoded: Vec<u8>,
    },
    /// The encoded data is an OCSP response.
    OcspResponse {
        #[allow(missing_docs)]
        encoded: Vec<u8>,
    },
}

/// TimeStampTokenSigner holds information for how to protect the time-stamp.
pub struct TimeStampTokenSigner {
    digest_algo_oid: Vec<u32>,
    sign_algo_oid: Vec<u32>,
    private_key: Arc<Box<dyn PrivateKey>>,
    signing_certificate_chain: Vec<Vec<u8>>,
    revocation_infos: Vec<RevocationInfoVariant>,
}

impl TimeStampTokenSigner {
    /// Return a new instance.
    pub fn new(
        digest_algo_oid: Vec<u32>,
        sign_algo_oid: Vec<u32>,
        private_key: Arc<Box<dyn PrivateKey>>,
        signing_certificate_chain: Vec<Vec<u8>>,
        revocation_infos: Vec<RevocationInfoVariant>,
    ) -> Self {
        Self {
            digest_algo_oid,
            sign_algo_oid,
            private_key,
            signing_certificate_chain,
            revocation_infos,
        }
    }

    /// Return the content digest algorithm's object identifier.
    pub fn get_digest_algo_oid(&self) -> &[u32] {
        &self.digest_algo_oid
    }

    /// Return the signing algorithm's object identifier.
    pub fn get_sign_algo_oid(&self) -> &[u32] {
        &self.sign_algo_oid
    }

    /// Return the signing certificate that can be used to validate the
    /// time-stamp response signature.
    pub fn get_signing_certificate(&self) -> CertificateParser {
        CertificateParser::from_bytes(self.signing_certificate_chain.first().unwrap()).unwrap()
    }

    /// Return the private key that corresponds to the signing certificate and
    /// will be used to sign the time-stamp response.
    pub fn get_private_key(&self) -> &dyn PrivateKey {
        self.private_key.as_ref().as_ref()
    }

    /// Return certificates to bundle in the response.
    pub fn get_certificate_choices(&self) -> rasn::types::SetOf<rasn_cms::CertificateChoices> {
        /*
        https://www.rfc-editor.org/rfc/rfc5652#section-10.2.3

        CertificateSet ::= SET OF CertificateChoices

        https://www.rfc-editor.org/rfc/rfc5652#section-10.2.2

        CertificateChoices ::= CHOICE {
         certificate Certificate,
         extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
         v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
         v2AttrCert [2] IMPLICIT AttributeCertificateV2,
         other [3] IMPLICIT OtherCertificateFormat }

        OtherCertificateFormat ::= SEQUENCE {
          otherCertFormat OBJECT IDENTIFIER,
          otherCert ANY DEFINED BY otherCertFormat }
        */
        self.signing_certificate_chain
            .iter()
            .map(|encoded_certificate| {
                rasn::der::decode::<rasn_pkix::Certificate>(encoded_certificate).unwrap()
            })
            .map(|certificate| rasn_cms::CertificateChoices::Certificate(Box::new(certificate)))
            .collect::<Vec<_>>()
            .into()
    }

    /// Return revocation info to bundle (OCSP responses and CRLs) and if result
    /// contains any OCSP responses.
    pub fn get_revocation_info_choices(
        &self,
    ) -> (
        Option<rasn::types::SetOf<rasn_cms::RevocationInfoChoice>>,
        bool,
    ) {
        /*
        RevocationInfoChoices ::= SET OF RevocationInfoChoice

        RevocationInfoChoice ::= CHOICE {
          crl CertificateList,
          other [1] IMPLICIT OtherRevocationInfoFormat }

        OtherRevocationInfoFormat ::= SEQUENCE {
          otherRevInfoFormat OBJECT IDENTIFIER,
          otherRevInfo ANY DEFINED BY otherRevInfoFormat }
        */
        let mut revocation_info_choices = vec![];
        let mut other_type_present = false;
        for revocation_info in &self.revocation_infos {
            match revocation_info {
                RevocationInfoVariant::Crl { encoded } => {
                    revocation_info_choices.push(rasn_cms::RevocationInfoChoice::Crl(
                        rasn::der::decode::<rasn_cms::CertificateList>(encoded).unwrap(),
                    ));
                }
                RevocationInfoVariant::OcspResponse { encoded } => {
                    revocation_info_choices.push(rasn_cms::RevocationInfoChoice::Other(
                        rasn_cms::OtherRevocationInfoFormat {
                            // https://www.rfc-editor.org/rfc/rfc5940#section-2
                            other_rev_info_format: rasn::types::ObjectIdentifier::new_unchecked(
                                TimeStampToken::OID_ID_RI_OCSP_RESPONSE.to_vec().into(),
                            ),
                            other_rev_info: rasn::types::Any::new(encoded.clone()),
                        },
                    ));
                    // When crls of othertype exists -> version = 5, otherwise 3.
                    other_type_present = true;
                }
            }
        }
        (Some(revocation_info_choices.into()), other_type_present)
    }
}
