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

use crate::cert::extensions::ExtendedKeyUsage;
use crate::cert::extensions::Extensions;
use crate::cert::types::DistinguishedName;
use crate::cert::types::WellKnownGeneralName;
use crate::cmp::asn1;
use crate::cmp::error::CmpProcessingError;
use crate::cmp::error::CmpProcessingErrorKind;
use rasn::types::BitString;
use tyst::traits::se::PrivateKey;
use tyst::traits::se::PublicKey;
use tyst::Tyst;

/// Single certificate initialization request.
pub struct InitializationRequest {
    cert_req_msg: asn1::CertReqMsg,
}

impl InitializationRequest {
    /// Return a new instance.
    pub fn new(
        public_key: &dyn PublicKey,
        encoded_issuer_dn: Option<Vec<u8>>,
        dn: DistinguishedName,
        sans: &[(WellKnownGeneralName, String)],
        ekus: &[ExtendedKeyUsage],
    ) -> Self {
        let spki = rasn::der::decode(&public_key.try_as_spki().unwrap()).unwrap();
        // TODO: Grab issuer from CA cert
        let issuer = encoded_issuer_dn.map(|encoded| rasn::der::decode(&encoded).unwrap());
        let subject = Some(dn.as_rasn_type().unwrap());
        let mut extensions = Extensions::default();
        extensions.add_subject_alternative_name(sans, dn.is_empty());
        extensions.add_extended_key_usage(ekus);
        let cert_req = asn1::CertRequest {
            cert_req_id: 0.into(),
            cert_template: asn1::CertTemplate {
                version: None,
                serial_number: None,
                signing_alg: None,
                issuer,
                validity: None,
                subject,
                public_key: Some(spki),
                issuer_uid: None,
                subject_uid: None,
                extensions: extensions.to_rasn_type(),
            },
            controls: None,
        };
        Self {
            cert_req_msg: asn1::CertReqMsg {
                cert_req,
                popo: Some(asn1::ProofOfPossession::RaVerified),
                reg_info: None,
            },
        }
    }

    /// Return this as a `rasn` type.
    pub fn to_pki_body(self) -> asn1::PkiBody {
        asn1::PkiBody::Ir(vec![self.cert_req_msg].into())
    }

    /// Create and set Proof Of Possession.
    pub fn sign_pop(
        mut self,
        signature_algorithm_oid: &[u32],
        private_key: &dyn PrivateKey,
    ) -> Self {
        let encoded_cert_req = rasn::der::encode(&self.cert_req_msg.cert_req).unwrap();
        let signature_algorithm_oid_str = tyst::encdec::oid::as_string(signature_algorithm_oid);
        let mut se = Tyst::instance()
            .ses()
            .by_oid(&signature_algorithm_oid_str)
            .unwrap();
        let signature = se.sign(private_key, &encoded_cert_req).unwrap();
        self.cert_req_msg.popo = Some(asn1::ProofOfPossession::Signature(asn1::PopoSigningKey {
            poposk_input: None,
            algorithm_identifier: rasn::der::decode(&se.get_algorithm_identifier().unwrap())
                .unwrap(),
            signature: BitString::from_slice(&signature),
        }));
        self
    }

    /// Return a new instance from the provided `rasn` type.
    pub fn from_rasn_type(
        cert_req_messages: &asn1::CertReqMessages,
    ) -> Result<Self, CmpProcessingError> {
        if cert_req_messages.is_empty() {
            Err(CmpProcessingErrorKind::BadRequest.error_with_msg(
                "Initialization request can not contain an empty list of certificate requests.",
            ))?;
        }
        if cert_req_messages.len() > 1 {
            Err(CmpProcessingErrorKind::NotImplemented
                .error_with_msg("This implementation does not support batched requests."))?;
        }
        Ok(Self {
            cert_req_msg: cert_req_messages.first().unwrap().clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::cert::types::{IdentityFragment, WellKnownAttribute};

    use super::*;

    #[test]
    fn create_initialization_request() {
        // ML-DSA-65: 2.16.840.1.101.3.4.18
        let signature_algorithm_oid = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
        let signature_algorithm_oid_str = tyst::encdec::oid::as_string(signature_algorithm_oid);
        let mut se = Tyst::instance()
            .ses()
            .by_oid(&signature_algorithm_oid_str)
            .unwrap();
        let (public_key, private_key) = se.generate_key_pair();
        let (dn, sans) = crate::cert::build::util::split_by_identity_fragment_type(&[
            IdentityFragment::new_unchecked(
                &WellKnownAttribute::CommonName.as_name(),
                "Requested common name",
            ),
            IdentityFragment::new_unchecked(
                &WellKnownGeneralName::Rfc822Name.as_name(),
                "no-reply@example.com",
            ),
        ]);
        InitializationRequest::new(
            public_key.as_ref(),
            None,
            dn,
            &sans,
            &[ExtendedKeyUsage::PkixClientAuth],
        )
        .sign_pop(signature_algorithm_oid, private_key.as_ref())
        .to_pki_body();
    }
}
