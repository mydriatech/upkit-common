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

//! X.509 Certificate path validation.

pub mod checkers;
mod validation_error;

use self::checkers::*;
pub use self::validation_error::CertificateValidationError;
pub use self::validation_error::CertificateValidationErrorKind;
use super::extensions::BasicConstraints;
use crate::cert::parse::CertificateParser;
use crossbeam_skiplist::SkipSet;
use std::sync::Arc;
use tyst::traits::se::ToPublicKey;
use tyst::Tyst;

/** Certificate path validation.

See [RFC5280 6](https://www.rfc-editor.org/rfc/rfc5280.html#section-6).
*/
pub struct CertificatePathValidator {
    all_leafs_extension_checkers: Vec<Arc<dyn ExtensionChecker>>,
    bag_of_trust_anchors: Vec<CertificateParser>,
}

impl CertificatePathValidator {
    /// Create a new instance from DER encoded trust anchors (trusted
    /// certificates).
    pub fn new(trusted_anchors_der: Vec<Vec<u8>>) -> Result<Self, CertificateValidationError> {
        Ok(Self {
            all_leafs_extension_checkers: Vec::default(),
            bag_of_trust_anchors: Self::parse_certs_and_preserve_order(&trusted_anchors_der)?,
        })
    }

    fn parse_certs_and_preserve_order(
        encoded_certificates: &Vec<Vec<u8>>,
    ) -> Result<Vec<CertificateParser>, CertificateValidationError> {
        let mut certificates = Vec::with_capacity(encoded_certificates.len());
        for encoded_certificate in encoded_certificates {
            match CertificateParser::from_bytes(encoded_certificate) {
                Ok(certificate) => {
                    certificates.push(certificate);
                }
                Err(e) => {
                    Err(CertificateValidationErrorKind::CertificateParsingError
                        .error_with_msg(&e.to_string()))?;
                }
            }
        }
        Ok(certificates)
    }

    /// Add certificate extension checks that will be used for all leaf chains.
    pub fn add_extension_checkers(
        mut self,
        extension_checkers: Vec<Arc<dyn ExtensionChecker>>,
    ) -> Self {
        self.all_leafs_extension_checkers.extend(extension_checkers);
        self
    }

    /** Add basic certificate extension checks that will be used for all leaf
    chains.

    This includes [BasicConstraintsChecker], [KeyIdentifierChecker],
    [KeyUsageChecker] and [PrivateKeyUsagePeriodChecker].
     */
    pub fn add_standard_extension_checkers(mut self) -> Self {
        self.all_leafs_extension_checkers.extend([
            Arc::new(BasicConstraintsChecker::default()) as Arc<dyn ExtensionChecker>,
            Arc::new(KeyUsageChecker::default()),
            Arc::new(KeyIdentifierChecker::default()),
            Arc::new(PrivateKeyUsagePeriodChecker::default()),
        ]);
        self
    }

    /** Order and validate the DER encoded leaf certificate chain.

    If no [CertificateValidationError] is returned, the retruned certificate
    chain is valid.

    `at_epoch_seconds` is the time in seconds from UNIX Epoch when the
    certificate(s) validity will be compared to.

    `additional_extension_checkers` only apply to this invocation of
    [`validate()`](Self::validate).
     */
    pub fn validate(
        &self,
        encoded_bag_of_certificates: Vec<Vec<u8>>,
        at_epoch_seconds: u64,
        additional_extension_checkers: Vec<Arc<dyn ExtensionChecker>>,
    ) -> Result<Vec<CertificateParser>, CertificateValidationError> {
        // Don't assume that these are ordered
        let bag_of_certificates =
            Self::parse_certs_and_preserve_order(&encoded_bag_of_certificates)?;
        let chain_with_trust =
            Self::get_trusted_certificate_chain(&bag_of_certificates, &self.bag_of_trust_anchors)?;
        if let Some(not_valid_cert) = chain_with_trust
            .iter()
            .find(|cert| !cert.get_validity().is_valid_at(at_epoch_seconds))
        {
            Err(CertificateValidationErrorKind::InvalidLifeSpan.error_with_msg(&format!(
                "Certificate with fingerprint '{}' is not valid at this point in time ({at_epoch_seconds} epoch seconds).",
                not_valid_cert.fingerprint(),
            )))?;
        }
        // Build list of all used critical extensions for the entire chain (except the trust anchor)
        let critical_extension_oids = SkipSet::default();
        chain_with_trust.iter().rev().skip(1).for_each(|cp| {
            cp.get_critical_extension_oids()
                .into_iter()
                .for_each(|oid| {
                    critical_extension_oids.insert(oid);
                });
        });
        // Invoke all Extension checkers that apply to all chains
        // Note: We could potentially invoke in parallel, but this would imply
        //       additional overhead (e.g. async).
        for extension_checker in &self.all_leafs_extension_checkers {
            extension_checker.check_extensions(&chain_with_trust, &critical_extension_oids)?;
        }
        // Invoke all Extension checkers that apply to this chain
        for extension_checker in &additional_extension_checkers {
            extension_checker.check_extensions(&chain_with_trust, &critical_extension_oids)?;
        }
        // Fail if there are still unresolved critical extensions
        if !critical_extension_oids.is_empty() {
            let msg = format!(
                "unhandled critical extensions: {:?}",
                critical_extension_oids.iter().collect::<Vec<_>>()
            );
            return Err(
                CertificateValidationErrorKind::UnhandledCriticalExtensions.error_with_msg(&msg)
            );
        }
        Ok(chain_with_trust)
    }

    /// Return a chain that starts with a leaf and ends with a trust anchor (or fail with error otherwise).
    pub fn get_trusted_certificate_chain(
        bag_of_certificates: &[CertificateParser],
        bag_of_trust_anchors: &[CertificateParser],
    ) -> Result<Vec<CertificateParser>, CertificateValidationError> {
        // Check: There can only be a single leaf
        // Order leaf chain: leaf to root
        let certificate_chain = Self::get_ordered_chain_from_bag_of_certs(bag_of_certificates)?;
        // From leaf to root: pick a trust anchor that is identical to this level or has issued the last
        let chain_with_trust = Self::get_certificate_chain_with_trust_anchor(
            &certificate_chain,
            bag_of_trust_anchors,
        )?;
        // Validate signatures up to trusted
        Self::validate_signatures_in_chain_up_to_trusted(&chain_with_trust)?;
        Ok(certificate_chain)
    }

    /// Return the leaf certificate from a bag of certs.
    ///
    /// If no leaf is present or if more than one leaf is found an error will be raised.
    fn get_single_leaf_from_bag_of_certs(
        certificates: &[CertificateParser],
    ) -> Result<&CertificateParser, CertificateValidationError> {
        // Check: There can only be a single leaf
        if log::log_enabled!(log::Level::Trace) {
            for cert in certificates {
                log::trace!("Subject:          {:?}", cert.get_subject().unwrap());
                log::trace!("Issuer:           {:?}", cert.get_issuer().unwrap());
                log::trace!(
                    "BasicConstraints: {:?}\n",
                    cert.get_basic_constraints().unwrap()
                );
            }
        }
        let leafs = certificates
            .iter()
            .filter(|lcp| {
                lcp.get_basic_constraints()
                    .as_ref()
                    .is_none_or(BasicConstraints::is_leaf)
            })
            .collect::<Vec<_>>();
        if leafs.is_empty() {
            Err(CertificateValidationErrorKind::NotOneLeaf
                .error_with_msg("No leaf certificate detected."))?;
        }
        if leafs.len() > 1 {
            Err(
                CertificateValidationErrorKind::NotOneLeaf.error_with_msg(&format!(
                    "More than one ({}) leaf certificate detected.",
                    leafs.len()
                )),
            )?;
        }
        Ok(leafs.first().unwrap())
    }

    /// Return an ordered chain with leaf certificate first from bag of certs.
    fn get_ordered_chain_from_bag_of_certs(
        certificates: &[CertificateParser],
    ) -> Result<Vec<CertificateParser>, CertificateValidationError> {
        let mut certificates = certificates.to_vec();
        let leaf = Self::get_single_leaf_from_bag_of_certs(&certificates)?;
        // Order leaf chain: leaf to root
        let mut current_subject = leaf.get_encoded_subject();
        let mut chain_from_leaf = vec![];
        for _i in 0..certificates.len() {
            if let Some(index) = certificates
                .iter()
                .position(|cp| cp.get_encoded_subject().eq(&current_subject))
            {
                let cp = certificates.remove(index);
                current_subject = cp.get_encoded_issuer();
                chain_from_leaf.push(cp);
            } else {
                Err(
                    CertificateValidationErrorKind::NotOneLeaf.error_with_msg(&format!(
                        "No parent for certificate with fingerprint '{}' detected.",
                        chain_from_leaf.last().unwrap().fingerprint()
                    )),
                )?;
            }
        }
        Ok(chain_from_leaf)
    }

    /// Return a chain that ends with a trust anchor (or fail with error otherwise).
    fn get_certificate_chain_with_trust_anchor(
        certificate_chain: &[CertificateParser],
        bag_of_trust_anchors: &[CertificateParser],
    ) -> Result<Vec<CertificateParser>, CertificateValidationError> {
        // Pick a trust anchor that is identical to this level...
        if let Some(pos) = certificate_chain.iter().position(|cp| {
            bag_of_trust_anchors
                .iter()
                .any(|trust_anchor| trust_anchor.fingerprint().eq(cp.fingerprint()))
        }) {
            // Actual certificate in chain is present already as trust anchor
            return Ok(certificate_chain[0..=pos].to_vec());
        }
        // ...or has issued this level
        let last_in_chain_encoded_issuer = certificate_chain.last().unwrap().get_encoded_issuer();
        let trust_anchor = bag_of_trust_anchors.iter().find(|trust_anchor| {
            trust_anchor
                .get_encoded_subject()
                .eq(&last_in_chain_encoded_issuer)
        });
        if let Some(trust_anchor) = trust_anchor {
            let mut certificate_chain = certificate_chain.to_vec();
            certificate_chain.push(trust_anchor.clone());
            return Ok(certificate_chain);
        }
        Err(CertificateValidationErrorKind::NotTrusted.error())
    }

    /// Validate signatures in chain.
    ///
    /// The signature of the last position in the chain is assumed to be trusted.
    fn validate_signatures_in_chain_up_to_trusted(
        certificate_chain_with_trust: &[CertificateParser],
    ) -> Result<(), CertificateValidationError> {
        let mut current_issuer = certificate_chain_with_trust.last().unwrap();
        for current in certificate_chain_with_trust.iter().rev().skip(1) {
            let spki = current_issuer.get_encoded_subject_public_key_info();
            let public_key = spki.to_public_key();
            let tbs_certificate = current.get_encoded_tbs_certificate();
            let (oid, signature) = current.get_encoded_signature();
            //log::debug!("current.signature.oid: {oid}");
            if let Some(mut se) = Tyst::instance().ses().by_oid(&oid) {
                if !se.verify(public_key.as_ref(), &signature, &tbs_certificate) {
                    let mut msg = format!("Unable to verify signature of cert with fp '{}' using issuer cert fp '{}'.", current.fingerprint(), current_issuer.fingerprint());
                    // Help out with troubleshooting: Is it self-signed??
                    let spki = current.get_encoded_subject_public_key_info();
                    let public_key = spki.to_public_key();
                    if se.verify(public_key.as_ref(), &signature, &tbs_certificate) {
                        msg += " The cert was self-signed.";
                    }
                    if log::log_enabled!(log::Level::Debug) {
                        log::debug!("{msg}");
                    }
                    return Err(
                        CertificateValidationErrorKind::InvalidSignature.error_with_msg(&msg)
                    );
                }
            } else {
                let msg = format!(
                    "Unknown signature algorithm '{oid}' in cert with fp '{}'.",
                    current.fingerprint()
                );
                return Err(CertificateValidationErrorKind::UnknownSignature.error_with_msg(&msg));
            }
            current_issuer = current;
        }
        Ok(())
    }
}
