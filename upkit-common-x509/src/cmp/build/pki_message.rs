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

//! Certificate Management Protocol (CMP) PKIMessage.

use crate::cert::types::DistinguishedName;
use crate::cert::types::IdentityFragment;
use crate::cert::types::WellKnownAttribute;
use crate::cmp::asn1;
use crate::cmp::error::CmpProcessingError;
use crate::cmp::error::CmpProcessingErrorKind;
use crate::cmp::types::PkiBody;
use bitvec::order::Msb0;
use bitvec::vec::BitVec;
use rasn::types::ObjectIdentifier;
use rasn::types::OctetString;
use tyst::misc::Pbkdf2;
use tyst::misc::Pbmac1;
use tyst::Tyst;

/** A generic CMP messages.

[RFC 4210 5.1](https://www.rfc-editor.org/rfc/rfc4210#section-5.1):

```text
   PKIMessage ::= SEQUENCE {
      header           PKIHeader,
      body             PKIBody,
      protection   [0] PKIProtection OPTIONAL,
      extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                        OPTIONAL
   }
```

Note that the protection only covers `header` and `body`, but not `extraCerts`.
*/
pub struct PkiMessage {
    pki_message: asn1::PkiMessage,
}

impl PkiMessage {
    /// iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) it(4) implicitConfirm(13)
    pub const OID_IMPLICIT_CONFIRM: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 4, 13];

    /// Return a new instance from the DER encoded bytes.
    pub fn from_bytes(encoded_pki_message: &[u8]) -> Self {
        Self {
            pki_message: rasn::der::decode(encoded_pki_message).unwrap(),
        }
    }

    /// Return the ASN.1 tag (≃type) of `PKIBody` in the `PKIMessage.body`.
    pub fn get_pki_body_tag(&self) -> usize {
        PkiBody::get_tag(&self.pki_message.body)
    }

    /// Return a supported type of [PkiBody].
    pub fn get_pki_body(&self) -> Result<PkiBody, CmpProcessingError> {
        PkiBody::from_rasn_type(&self.pki_message.body)
    }

    /// Validate that the nonce of this response matches a request nonce.
    pub fn validate_response_nonce(&self, request: &PkiMessage) -> Result<(), CmpProcessingError> {
        if self
            .pki_message
            .header
            .recip_nonce
            .eq(&request.pki_message.header.sender_nonce)
        {
            Ok(())
        } else {
            Err(CmpProcessingErrorKind::BadNonce
                .error_with_msg("Request sender nonce did not match response reciepient nonce."))
        }
    }

    /// Validate protection using PBMAC1.
    pub fn validate_with_shared_secret(
        &self,
        shared_secret: &[u8],
    ) -> Result<(), CmpProcessingError> {
        if let Some(protection_alg) = self.pki_message.header.protection_alg.as_ref() {
            if let Some(mut pbmac1) = Pbmac1::from_algorithm_identifier(
                *Tyst::instance().as_ref(),
                &rasn::der::encode(protection_alg).unwrap(),
            ) {
                let message = rasn::der::encode(&asn1::ProtectedPart {
                    header: self.pki_message.header.clone(),
                    body: self.pki_message.body.clone(),
                })
                .unwrap();
                let protection =
                    BitVec::<u8, Msb0>::from_vec(pbmac1.pbmac(shared_secret, &message));
                if let Some(pki_message_protection) = self.pki_message.protection.as_ref() {
                    if protection.eq(pki_message_protection) {
                        return Ok(());
                    }
                    Err(CmpProcessingErrorKind::ProtectionValidationFailure
                        .error_with_msg("Protection in PKIMessage does not match."))?;
                } else {
                    Err(CmpProcessingErrorKind::ProtectionValidationFailure
                        .error_with_msg("Missing protection in PKIMessage."))?;
                }
            } else {
                Err(CmpProcessingErrorKind::ProtectionValidationFailure
                    .error_with_msg("Unable to get PBMAC1 implementation."))?;
            }
        }
        Err(CmpProcessingErrorKind::ProtectionValidationFailure
            .error_with_msg("No protection algorithm specified in header."))
    }

    /// Return this `PKIMessage` as DER encoded bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        rasn::der::encode(&self.pki_message).unwrap()
    }

    /// Create a new PkiMessage using PBMAC1 shared secret protection.
    pub fn with_shared_secret(
        body: crate::cmp::asn1::PkiBody,
        sender_common_name: &str,
        //encoded_recipient_dn: &[u8],
        recip_nonce: Option<OctetString>,
        shared_secret: &[u8],
    ) -> Self {
        let sender_dn = DistinguishedName::new_unchecked(vec![vec![IdentityFragment {
            name: WellKnownAttribute::CommonName.as_name(),
            value: sender_common_name.to_string(),
        }]])
        .as_rasn_type()
        .unwrap();
        let message_time = Some(crate::encdec::rasn::to_generalized_time(
            upkit_common_util::time::now_epoch_seconds(),
        ));
        let general_info = Some(vec![asn1::InfoTypeAndValue {
            info_type: ObjectIdentifier::new_unchecked(Self::OID_IMPLICIT_CONFIRM.to_vec().into()),
            info_value: Some(crate::encdec::rasn::null()),
        }]);
        let (mut pbmac1, protection_alg) = Self::get_pbmac1();
        let header = crate::cmp::asn1::PkiHeader {
            pvno: 2.into(),
            sender: rasn_pkix::GeneralName::DirectoryName(sender_dn),
            recipient: rasn_pkix::GeneralName::DirectoryName(rasn_pkix::Name::RdnSequence(vec![])),
            message_time,
            protection_alg: Some(protection_alg),
            // EJBCA CE 9.1.1 requires the sender kid to be set in order to do PBMAC1 response protection.
            sender_kid: Some(OctetString::new()),
            recip_kid: None,
            transaction_id: Some(OctetString::from(Self::get_random_bytes(128 >> 3))),
            sender_nonce: Some(OctetString::from(Self::get_random_bytes(128 >> 3))),
            recip_nonce,
            free_text: None,
            general_info,
        };
        let protected_part = asn1::ProtectedPart { header, body };
        let message = rasn::der::encode(&protected_part).unwrap();
        let protection = Some(BitVec::from_vec(pbmac1.pbmac(shared_secret, &message)));
        Self {
            pki_message: crate::cmp::asn1::PkiMessage {
                header: protected_part.header,
                body: protected_part.body,
                protection,
                extra_certs: None,
            },
        }
    }

    fn get_pbmac1() -> (Pbmac1, rasn_cms::AlgorithmIdentifier) {
        const HMAC_SHA3_512: &str = "2.16.840.1.101.3.4.2.16";
        // TODO: EJBCA CE 9.1.1 has a bug that will default to HMAC_SHA_256 as PRF... :/
        const HMAC_SHA_256: &str = "1.2.840.113549.2.9";
        let mac_factory = Tyst::instance().macs();
        let mac = mac_factory.by_oid(HMAC_SHA3_512).unwrap();
        let prf = mac_factory.by_oid(HMAC_SHA_256).unwrap();
        let salt = Self::get_random_bytes(mac.get_mac_size_bits() >> 3);
        let pbmac1 = Pbmac1::new(mac, Pbkdf2::new(&salt, 1024, salt.len(), prf));
        let protection_alg = rasn::der::decode(&pbmac1.get_algorithm_identifier()).unwrap();
        (pbmac1, protection_alg)
    }

    fn get_random_bytes(octets: usize) -> Vec<u8> {
        let mut rnd = vec![0u8; octets];
        Tyst::instance().prng_fill_with_random(None, &mut rnd);
        rnd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::extensions::ExtendedKeyUsage;
    use crate::cert::types::WellKnownGeneralName;
    use crate::cmp::types::InitializationRequest;

    /// Can we validate the protection we created?
    #[test]
    fn test_can_eat_own_dogfood() {
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
        let initialization_request = InitializationRequest::new(
            public_key.as_ref(),
            None,
            dn,
            &sans,
            &[ExtendedKeyUsage::PkixClientAuth],
        )
        .sign_pop(signature_algorithm_oid, private_key.as_ref())
        .to_pki_body();
        let shared_secret = b"foobar123";
        let request = PkiMessage::with_shared_secret(
            initialization_request,
            "end_entity_1",
            None,
            shared_secret,
        );
        request.validate_with_shared_secret(shared_secret).unwrap();
    }
}
