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
use crossbeam_skiplist::SkipMap;
use crossbeam_skiplist::SkipSet;
use std::sync::Arc;
use tyst::traits::se::ToPublicKey;
use tyst::Tyst;

/** Certificate path validation.

See [RFC5280 6](https://www.rfc-editor.org/rfc/rfc5280.html#section-6).
*/
pub struct CertificatePathValidator {
    fingerprint_by_subject: SkipMap<Vec<u8>, String>,
    trust_anchors_by_fingerprint: SkipMap<String, CertificateParser>,
    all_leafs_extension_checkers: Vec<Arc<dyn ExtensionChecker>>,
}

impl CertificatePathValidator {
    /// Create a new instance from DER encoded trust anchors (trusted
    /// certificates).
    pub fn new(trusted_anchors_der: Vec<Vec<u8>>) -> Result<Self, CertificateValidationError> {
        let ret = Self {
            fingerprint_by_subject: SkipMap::default(),
            trust_anchors_by_fingerprint: SkipMap::default(),
            all_leafs_extension_checkers: Vec::default(),
        };
        for trusted_anchor_der in trusted_anchors_der {
            match CertificateParser::from_bytes(&trusted_anchor_der) {
                Ok(trusted_anchor) => {
                    // In general whoever is calling this should kind of be trusted to provide a sane anchor...
                    // Starting to second guess this might cause more harm than it fixes..
                    let fingerprint = trusted_anchor.fingerprint().to_string();
                    let subject = trusted_anchor.get_encoded_subject();
                    ret.trust_anchors_by_fingerprint
                        .insert(fingerprint.to_owned(), trusted_anchor);
                    ret.fingerprint_by_subject.insert(subject, fingerprint);
                }
                Err(e) => {
                    return Err(CertificateValidationErrorKind::CertificateParsingError
                        .error_with_msg(&e.to_string()));
                }
            }
        }
        Ok(ret)
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

    This includes [BasicConstraintsChecker], [KeyIdentifierChecker] and
    [KeyUsageChecker].
     */
    pub fn add_standard_extension_checkers(mut self) -> Self {
        self.all_leafs_extension_checkers.extend([
            Arc::new(BasicConstraintsChecker::default()) as Arc<dyn ExtensionChecker>,
            Arc::new(KeyUsageChecker::default()),
            Arc::new(KeyIdentifierChecker::default()),
        ]);
        self
    }

    /** Order and validate the DER encoded leaf certificate chain.

    If no [CertificateValidationError] is returned the certificate is valid.

    `at_epoch_seconds` is the time in seconds from UNIX Epoch when the
    certificate(s) validity will be compared to.

    `additional_extension_checkers` only apply to this invocation of
    [`validate()`](Self::validate).
     */
    pub fn validate(
        &self,
        leaf_certificate_chain_der: Vec<Vec<u8>>,
        at_epoch_seconds: u64,
        additional_extension_checkers: Vec<Arc<dyn ExtensionChecker>>,
    ) -> Result<(), CertificateValidationError> {
        // Don't assume that these are ordered
        let mut leaf_certificates = vec![];
        for leaf_certificate_der in leaf_certificate_chain_der {
            let lcp = CertificateParser::from_bytes(&leaf_certificate_der).unwrap();
            // Kick out certs that are not valid (time)
            if lcp.get_validity().is_valid_at(at_epoch_seconds) {
                if log::log_enabled!(log::Level::Trace) {
                    log::trace!(
                        "Loaded leaf chain cert with fingerprint '{}'.",
                        lcp.fingerprint()
                    );
                }
                leaf_certificates.push(lcp);
            } else {
                let msg = format!("Certificate is not valid at this point in time ({at_epoch_seconds} epoch seconds).");
                return Err(CertificateValidationErrorKind::InvalidLifeSpan.error_with_msg(&msg));
            }
        }
        // Check: There can only be a single leaf
        let leafs = leaf_certificates
            .iter()
            .filter(|lcp| {
                lcp.get_basic_constraints()
                    .as_ref()
                    .is_none_or(BasicConstraints::is_leaf)
            })
            .collect::<Vec<_>>();
        if leafs.is_empty() {
            return Err(CertificateValidationErrorKind::NotOneLeaf
                .error_with_msg("No leaf certificate detected."));
        }
        if leafs.len() > 1 {
            let msg = format!("More than one ({}) leaf certificate detected.", leafs.len());
            return Err(CertificateValidationErrorKind::NotOneLeaf.error_with_msg(&msg));
        }
        // Order leaf chain: leaf to root
        let leaf = leafs.first().unwrap();
        let mut current_subject = leaf.get_encoded_subject();
        let mut leaf_chain = vec![];
        for _i in 0..leaf_certificates.len() {
            if let Some(index) = leaf_certificates
                .iter()
                .position(|cp| cp.get_encoded_subject().eq(&current_subject))
            {
                let cp = leaf_certificates.remove(index);
                current_subject = cp.get_encoded_issuer();
                leaf_chain.push(cp);
            } else {
                let failed = leaf_chain.last().unwrap();
                let msg = format!(
                    "No parent for certificate with fingerprint '{}' detected.",
                    failed.fingerprint()
                );
                return Err(CertificateValidationErrorKind::NotOneLeaf.error_with_msg(&msg));
            }
        }
        // From leaf to root: pick a trust anchor that has issued this level or is identical to this level
        let chain_with_trust = if let Some(pos) = leaf_chain.iter().position(|cp| {
            self.trust_anchors_by_fingerprint
                .contains_key(cp.fingerprint())
        }) {
            // Actual certificate in leaf chain is present already as trust anchor
            leaf_chain[0..pos].to_vec()
        } else if let Some(pos) = leaf_chain.iter().position(|cp| {
            self.fingerprint_by_subject
                .contains_key(&cp.get_encoded_issuer())
        }) {
            let cp = &leaf_chain[pos];
            let issuer = &cp.get_encoded_issuer();
            let fingerprint = self
                .fingerprint_by_subject
                .get(issuer)
                .unwrap()
                .value()
                .to_owned();
            let trusted = self
                .trust_anchors_by_fingerprint
                .get(&fingerprint)
                .unwrap()
                .value()
                .to_owned();
            let mut leaf_chain = leaf_chain[0..=pos].to_vec();
            leaf_chain.push(trusted);
            leaf_chain
        } else {
            return Err(CertificateValidationErrorKind::NotTrusted.error());
        };
        // Check that selected trust anchor is valid
        let selected_trust_anchor = chain_with_trust.last().unwrap();
        if !selected_trust_anchor
            .get_validity()
            .is_valid_at(at_epoch_seconds)
        {
            let msg = format!("Matching trust anchor is not valid at this point in time ({at_epoch_seconds} epoch seconds).");
            return Err(CertificateValidationErrorKind::InvalidLifeSpan.error_with_msg(&msg));
        }
        // Validate signatures up to trusted
        let mut current_issuer = chain_with_trust.last().unwrap();
        for current in chain_with_trust.iter().rev().skip(1) {
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
        Ok(())
    }
}
