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

use tyst::Tyst;
use upkit_common_util::testing::*;
use upkit_common_x509::cert::extensions::ExtendedKeyUsage;
use upkit_common_x509::cert::extensions::Extensions;
use upkit_common_x509::cert::types::DistinguishedName;
use upkit_common_x509::cert::types::WellKnownAttribute;
use upkit_common_x509::cert::types::WellKnownGeneralName;
use upkit_common_x509::encdec::pem::Marker;
use upkit_common_x509::pkcs10::build::CertificationRequest;
use upkit_common_x509::pkcs10::parse::CertificationRequestParser;
use upkit_common_x509::pkcs10::parse::CertificationRequestParsingError;

#[test]
fn test_pkcs10() {
    initialize_env_logger();

    let requested_name = "I want this name!";
    // ML-DSA-65: 2.16.840.1.101.3.4.18
    let signature_algorithm_oid = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
    let signature_algorithm_str = tyst::encdec::oid::as_string(signature_algorithm_oid);
    let mut se = Tyst::instance()
        .ses()
        .by_oid(&signature_algorithm_str)
        .unwrap();
    let (public_key, private_key) = se.generate_key_pair();
    let mut extensions = Extensions::default();
    extensions.add_subject_alternative_name(
        &[(WellKnownGeneralName::DnsName, "mydriatech.se".to_string())],
        false,
    );
    extensions.add_extended_key_usage(&[ExtendedKeyUsage::PkixServerAuth]);
    let certification_request = CertificationRequest::new(
        &DistinguishedName::new(vec![
            vec![WellKnownAttribute::CommonName.with_value(requested_name)],
            vec![WellKnownAttribute::CountryName.with_value("SE")],
        ])
        .unwrap(),
        signature_algorithm_oid,
        public_key.as_ref(),
        private_key.as_ref(),
        Some(&extensions),
    );
    let pkcs10 = CertificationRequestParser::from_bytes(certification_request.as_bytes()).unwrap();
    pkcs10.validate_signature().unwrap();
    let requested_subject_dn = pkcs10.get_subject().unwrap();
    let requested_name_present = requested_subject_dn.rnds().iter().any(|mv_rdn| {
        mv_rdn.iter().any(|identity_fragment| {
            identity_fragment
                .name
                .eq(&WellKnownAttribute::CommonName.as_name())
                && identity_fragment.value.eq(requested_name)
        })
    });
    assert!(
        requested_name_present,
        "Requested common_name was not present in PKCS#10 certification request."
    );
}

#[test]
fn test_pkcs10_real_world() {
    initialize_env_logger();

    check_pkcs10("pkcs10/globalsign.p10.pem", true);
    check_pkcs10("pkcs10/globalsign-msexc2010.p10.pem", false);
}

fn check_pkcs10(relative_path: &str, assert_valid_signature: bool) {
    // Load
    let pkcs10 = get_csr_from_pem(relative_path).unwrap();
    let requested_subject_dn = pkcs10.get_subject().unwrap();
    log::debug!(
        "CSR requests subject DN '{}'.",
        serde_json::to_string(&requested_subject_dn).unwrap()
    );
    let requested_subject_an = pkcs10.get_subject_alternative_name();
    log::debug!(
        "CSR requests subject AN '{}'.",
        serde_json::to_string(&requested_subject_an).unwrap()
    );
    let requested_ekus = pkcs10.get_extended_key_usage();
    log::debug!(
        "CSR requests EKUs '{}'.",
        serde_json::to_string(&requested_ekus).unwrap()
    );
    if let Err(e) = pkcs10.validate_signature() {
        if assert_valid_signature {
            assert!(false, "Signature validation failure: {e:?}")
        } else {
            log::info!("Expected signature validation failure: {e:?}");
        }
    }
}

fn get_csr_from_pem(
    relative_path: &str,
) -> Result<CertificationRequestParser, CertificationRequestParsingError> {
    CertificationRequestParser::from_bytes(&get_single_item(
        &load_resource_file_as_string(env!("CARGO_MANIFEST_DIR"), relative_path),
        &Marker::CertificationRequest,
    ))
}

/// Assert that PEM has correct marker and return the first such item in the pem_str
fn get_single_item(pem_str: &str, marker: &Marker) -> Vec<u8> {
    upkit_common_x509::encdec::pem::parse(&pem_str)
        .unwrap()
        .into_iter()
        .filter(|(item_marker, _)| item_marker.eq(&marker))
        .map(|(_marker, bytes)| bytes)
        .next()
        .unwrap()
}
