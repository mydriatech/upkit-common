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

//! Time-Stamp Token.

use super::TstInfo;
use crate::cert::extensions::ExtendedKeyUsage;
use crate::cert::parse::CertificateParser;
use crate::cms::types::SignedAttributes;
use crate::tsp::build::TimeStampTokenSigner;
use crate::tsp::tsp_asn1 as asn1;
use rasn::types::Any;
use rasn::types::ObjectIdentifier;
use rasn::types::OctetString;
use rasn_cms::Attribute;
use rasn_cms::ContentInfo;
use rasn_cms::EncapsulatedContentInfo;
use rasn_cms::IssuerAndSerialNumber;
use rasn_cms::SignedData;
use rasn_cms::SignerIdentifier;
use rasn_cms::SignerInfo;
use tyst::encdec::hex::ToHex;
use tyst::traits::se::ToPublicKey;
use tyst::Tyst;

/** RFC3161 TimeStampToken.

```text
   TimeStampToken ::= ContentInfo
     -- contentType is id-signedData ([CMS])
     -- content is SignedData ([CMS])
```

## See also

* [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) Time-Stamp Protocol (TSP)
* [RFC 3628](https://www.rfc-editor.org/rfc/rfc3628) Policy Requirements for Time-Stamping Authorities (TSAs)
* [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816) ESSCertIDv2 Update for RFC 3161 (allow non-SHA1)
* [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) Cryptographic Message Syntax (CMS)
* [RFC 2634](https://www.rfc-editor.org/rfc/rfc2634) Enhanced Security Services for S/MIME
* [RFC 5035](https://www.rfc-editor.org/rfc/rfc5035) ESS Update: Adding CertID Algorithm Agility
* [RFC 8933](https://www.rfc-editor.org/rfc/rfc8933) Update to the CMS for Algorithm Identifier Protection
* [RFC 6211](https://www.rfc-editor.org/rfc/rfc6211) CMS Algorithm Identifier Protection Attribute
* [RFC 5940](https://www.rfc-editor.org/rfc/rfc5940) Additional CMS Revocation Information Choices
*/
pub struct TimeStampToken {
    time_stamp_token_content: SignedData,
}

impl TimeStampToken {
    /// RFC 5940: iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) ri(16) ocsp-response(2)
    pub const OID_ID_RI_OCSP_RESPONSE: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 16, 2];
    // iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) TSTInfo(4)
    const OID_ID_CT_TST_INFO: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];

    /// Create a new signed Time-Stamp.
    pub fn new(mut tst_info: TstInfo, tst_signer: &TimeStampTokenSigner, cert_req: bool) -> Self {
        let digest_algo_oid = tst_signer.get_digest_algo_oid();
        let signing_cert = tst_signer.get_signing_certificate();
        if !signing_cert
            .get_extended_key_usage()
            .contains(&ExtendedKeyUsage::PkixTimeStamping)
            && log::log_enabled!(log::Level::Debug)
        {
            log::debug!("Signing certificate EKU does not explicitly declare that key can be used for Time-Stamping. Allowing this to proceed, but verification if this Time-Stamp might fail.");
        }
        if !cert_req {
            // https://www.rfc-editor.org/rfc/rfc3628.html#section-7.3.1.h mandates that the signer is identifiable (country, device etc).
            // This implementation expects that the caller provides sufficient information about this in the TSA certificate.
            // If the TimeStampReq.certReq is false, we still provide the subject of this cert here.
            // This might not be strictly neccessary, since the verifier still needs to be able to look up
            // the referenced certificate via TimeStampResp.timeStampToken.content.signer_infos[0].sid.
            tst_info.set_tsa_from_dn(&signing_cert.get_subject().unwrap());
        }
        let digest_algorithm = crate::encdec::rasn::oid_as_algorithm_identifier(digest_algo_oid);
        // "Only the octets comprising the value of the eContent OCTET STRING are
        //  input to the message digest algorithm, not the tag or the length octets."
        let content = rasn::der::encode(&tst_info.to_rasn_type()).unwrap();
        let mut digest = Tyst::instance()
            .digests()
            .by_oid(&tyst::encdec::oid::as_string(digest_algo_oid))
            .unwrap();
        // Signed attributes MUST be present if the content type is not id-data.
        let content_digest = digest.hash(&content);
        let signed_attrs = SignedAttributes::default()
            .set_content_type(Self::OID_ID_CT_TST_INFO)
            .set_signing_certificate_digests(&signing_cert, digest_algo_oid)
            .set_message_digest(&content_digest)
            .set_cms_algo_protection(digest_algo_oid, tst_signer.get_sign_algo_oid())
            .to_rasn_type();
        let encoded_signed_attrs = Self::encode_signed_attrs(&signed_attrs);
        let mut se = Tyst::instance()
            .ses()
            .by_oid(&tyst::encdec::oid::as_string(
                tst_signer.get_sign_algo_oid(),
            ))
            .unwrap();
        let signature = se
            .sign(tst_signer.get_private_key(), &encoded_signed_attrs)
            .unwrap();
        // https://www.rfc-editor.org/rfc/rfc5652#section-5.3
        let signer_info = SignerInfo {
            // sid is issuerAndSerialNumber -> version 1
            version: 1.into(),
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: signing_cert.get_issuer().unwrap().as_rasn_type().unwrap(),
                serial_number: signing_cert.get_serial_number().to_rasn_type(),
            }),
            digest_algorithm: digest_algorithm.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: crate::encdec::rasn::oid_as_algorithm_identifier(
                tst_signer.get_sign_algo_oid(),
            ),
            signature: OctetString::from(signature),
            unsigned_attrs: None,
        };
        let mut version = 3isize;
        // https://www.rfc-editor.org/rfc/rfc5652#section-5.1
        let certificates = if cert_req {
            Some(tst_signer.get_certificate_choices())
        } else {
            None
        };
        let (crls, other_rev_type_present) = tst_signer.get_revocation_info_choices();
        if cert_req {
            tst_signer.get_revocation_info_choices()
        } else {
            (None, false)
        };
        if other_rev_type_present {
            version = 5;
        }
        let signed_data = SignedData {
            // encap_content_info is not of type id-data
            // crls or cert of other type present => 5
            version: version.into(),
            digest_algorithms: vec![digest_algorithm].into(),
            encap_content_info: EncapsulatedContentInfo {
                content_type: ObjectIdentifier::new_unchecked(Self::OID_ID_CT_TST_INFO.into()),
                content: Some(content.into()),
            },
            certificates,
            crls,
            signer_infos: vec![signer_info].into(),
        };
        Self {
            time_stamp_token_content: signed_data,
        }
    }

    /** DER encode `SignedData.signedAttrs` field.

    [RFC5652 5.4](https://www.rfc-editor.org/rfc/rfc5652#section-5.4) states:

    ```text
       The IMPLICIT [0] tag in the signedAttrs is not used for the DER
       encoding, rather an EXPLICIT SET OF tag is used.
    ```

    What is really ment by this is just:

    "DER encode the `SetOf<Attributes>` without any tagging at all."
    */
    fn encode_signed_attrs(signed_attrs: &rasn::types::SetOf<Attribute>) -> Vec<u8> {
        let encoded_signed_attrs = rasn::der::encode(&signed_attrs).unwrap();
        if log::log_enabled!(log::Level::Trace) {
            log::trace!("encoded_signed_attrs:  {}", encoded_signed_attrs.to_hex())
        }
        encoded_signed_attrs
    }

    /// Return true if this time stamp was signed by the public key.
    pub fn is_signed_by_certificate(&self, ts_certificate: &CertificateParser) -> bool {
        let spki = ts_certificate.get_encoded_subject_public_key_info();
        let ts_certificate_public_key = spki.to_public_key();

        if !self
            .time_stamp_token_content
            .encap_content_info
            .content_type
            .eq(Self::OID_ID_CT_TST_INFO)
        {
            log::debug!("Wrong type of encapsulated content.");
            return false;
        }
        if self
            .time_stamp_token_content
            .encap_content_info
            .content
            .as_ref()
            .is_none_or(|content| content.is_empty())
        {
            log::debug!("Encapsulated content is empty.");
            return false;
        }
        let content = self
            .time_stamp_token_content
            .encap_content_info
            .content
            .as_ref()
            .unwrap();
        let digest_algos = self.time_stamp_token_content.digest_algorithms.to_vec();
        let digest_algo = digest_algos.first().unwrap();
        let digest_algorithm_oid = digest_algo.algorithm.as_ref();
        let mut digest = Tyst::instance()
            .digests()
            .by_oid(&tyst::encdec::oid::as_string(digest_algorithm_oid))
            .unwrap();
        let content_digest = digest.hash(content);
        let signer_infos = self.time_stamp_token_content.signer_infos.to_vec();
        /*
        RFC3161 2.4.2  The time-stamp token MUST NOT contain any signatures
        other than the signature of the TSA.  The certificate identifier ...
        MUST be included as a signerInfo attribute inside a SigningCertificate
        attribute.
        */
        if signer_infos.len() != 1 {
            log::debug!("The time-stamp token MUST NOT contain any signatures other than the signature of the TSA.");
            return false;
        }

        let signer_info = signer_infos.first().unwrap();
        if !signer_info.digest_algorithm.eq(digest_algo) {
            log::debug!("Wrong digest algorithm used by signed. (Only single signer support is implemented.)");
            return false;
        }
        let signed_attributes = SignedAttributes::from_rasn_type(&signer_info.signed_attrs);
        if !signed_attributes.is_content_type(Self::OID_ID_CT_TST_INFO) {
            log::debug!("Encapsulated content type is not backed up by signed attribute.");
            return false;
        }
        if !signed_attributes.is_message_digest(&content_digest) {
            log::debug!("Wrong or missing content digest in signed attribute.");
            return false;
        }
        if !signed_attributes.is_signing_certificate(ts_certificate, digest_algorithm_oid) {
            log::debug!("Bundled signing certificate was not used to sign this time-stamp.");
            return false;
        }
        if !signed_attributes.is_cms_algo_protection(
            digest_algorithm_oid,
            &signer_info.signature_algorithm.algorithm,
        ) {
            log::debug!("Content digest or siganture algorithm does not match protected version.");
            return false;
        }
        let encoded_signed_attrs =
            Self::encode_signed_attrs(signer_info.signed_attrs.as_ref().unwrap());
        // TODO: Ignore params for now (even if this limits usable algs).
        let oid = signer_info.signature_algorithm.algorithm.as_ref();
        let oid_string = tyst::encdec::oid::as_string(oid);
        let signature = signer_info.signature.as_ref();
        if let Some(mut se) = Tyst::instance().ses().by_oid(&oid_string) {
            se.verify(
                ts_certificate_public_key.as_ref(),
                signature,
                //&content_and_attrs_digest,
                &encoded_signed_attrs,
            )
        } else {
            log::debug!("Unknown signature OID '{oid_string}'.");
            false
        }
    }

    fn is_signed_data(cms_content_info: &ContentInfo) -> bool {
        cms_content_info
            .content_type
            .as_ref()
            .eq(rasn_cms::CONTENT_SIGNED_DATA)
    }

    /// Return bundled certificates (ordering is not guaranteed).
    pub fn get_certificates(&self) -> Vec<Vec<u8>> {
        self.time_stamp_token_content
            .certificates
            .as_ref()
            .map(|certificates| {
                certificates
                    .to_vec()
                    .into_iter()
                    .filter_map(|cc| match cc {
                        // TODO: Should extended cert be used? https://www.rfc-editor.org/rfc/rfc5816
                        rasn_cms::CertificateChoices::Certificate(boxed_cert) => {
                            Some(rasn::der::encode(boxed_cert).unwrap())
                        }
                        other_choice => {
                            log::debug!("Ignoring certificate entry {other_choice:?}");
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    /// Return encoded CRL and OCSP Response entries.
    ///
    /// Encoded data is not checked for correctness in any way.
    pub fn get_revocation_infos(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut crls = vec![];
        let mut ocsp_responses = vec![];
        if let Some(revocation_info_choices) = &self.time_stamp_token_content.crls {
            for revocation_info_choice in revocation_info_choices.to_vec() {
                match revocation_info_choice {
                    rasn_cms::RevocationInfoChoice::Crl(crl) => {
                        crls.push(rasn::der::encode(crl).unwrap());
                    }
                    rasn_cms::RevocationInfoChoice::Other(other_revocation_info_format) => {
                        if other_revocation_info_format
                            .other_rev_info_format
                            .as_ref()
                            .eq(TimeStampToken::OID_ID_RI_OCSP_RESPONSE)
                        {
                            ocsp_responses.push(
                                other_revocation_info_format
                                    .other_rev_info
                                    .as_bytes()
                                    .to_vec(),
                            );
                        } else {
                            log::debug!(
                                "Ignoring certificate entry {other_revocation_info_format:?}"
                            );
                        }
                    }
                }
            }
        }
        (crls, ocsp_responses)
    }

    /// Return the encapsulated (protected) TSTInfo content.
    pub fn get_tst_info(&self) -> Option<TstInfo> {
        if self
            .time_stamp_token_content
            .encap_content_info
            .content_type
            .as_ref()
            .eq(Self::OID_ID_CT_TST_INFO)
        {
            if let Some(content) = &self.time_stamp_token_content.encap_content_info.content {
                return Some(TstInfo::from_rasn_type(
                    &rasn::der::decode(content).unwrap(),
                ));
            }
        }
        None
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn from_rasn_type(time_stamp_token: &asn1::TimeStampToken) -> Option<Self> {
        if Self::is_signed_data(time_stamp_token) {
            Some(Self {
                time_stamp_token_content: rasn::der::decode::<SignedData>(
                    time_stamp_token.content.as_bytes(),
                )
                .unwrap(),
            })
        } else {
            None
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> asn1::TimeStampToken {
        rasn_cms::ContentInfo {
            content_type: rasn_cms::CONTENT_SIGNED_DATA.into(),
            content: Any::new(rasn::der::encode(&self.time_stamp_token_content).unwrap()),
        }
    }
}
