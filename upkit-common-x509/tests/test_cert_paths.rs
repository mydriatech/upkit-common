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

use std::path::PathBuf;
use std::sync::Arc;
use upkit_common_x509::cert::extensions::CertificatePolicy;
use upkit_common_x509::cert::extensions::ExtendedKeyUsage;
use upkit_common_x509::cert::extensions::WellKnownCertificatePolicy;
use upkit_common_x509::cert::parse::CertificateParser;
use upkit_common_x509::cert::validate::checkers::CertificatePoliciesChecker;
use upkit_common_x509::cert::validate::checkers::ExtendedKeyUsageChecker;
use upkit_common_x509::cert::validate::CertificatePathValidator;

pub fn init_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        //.filter(Some("rustls"), log::LevelFilter::Info)
        .try_init();
}

#[test]
fn test_cert_path() {
    init_logger();
    let now_epoch_seconds = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    // Hardcode a time where this should succeed
    let at_epoch_seconds = 1739555555;
    log::info!("Test at_epoch_seconds: {at_epoch_seconds} (now is {now_epoch_seconds}).");
    CertificatePathValidator::new(vec![load_b64_file("h1_root_ca.b64")])
        .unwrap()
        .add_standard_extension_checkers()
        .validate(
            vec![load_b64_file("h1_leaf.b64"), load_b64_file("h1_sub_ca.b64")],
            at_epoch_seconds,
            vec![],
        )
        .unwrap();
}

#[test]
fn test_cert_path_real_world() {
    init_logger();
    // Load github chain from PEM (to also test PEM-parsing)
    let contents = load_test_resource_file("github-com-chain.pem");
    let mut chain = upkit_common_x509::encdec::pem::parse(&contents)
        .unwrap()
        .into_iter()
        .map(|(_marker, bytes)| bytes)
        .collect::<Vec<_>>();
    let cp = CertificateParser::from_bytes(&chain[0]).unwrap();
    log::debug!(
        "Validating leaf certificate with subject dn: '{:?}'.",
        cp.get_subject()
    );
    // split chain into into leaf and trust anchor
    let trusted = chain.pop().unwrap();
    // Hardcode a time where this should succeed
    let at_epoch_seconds = 1738888000;
    CertificatePathValidator::new(vec![trusted])
        .unwrap()
        .add_standard_extension_checkers()
        .add_extension_checkers(vec![
            Arc::new(ExtendedKeyUsageChecker::new(&[
                ExtendedKeyUsage::PkixServerAuth,
            ])),
            Arc::new(CertificatePoliciesChecker::new(&[
                CertificatePolicy::OidPolicy {
                    oid: WellKnownCertificatePolicy::CabfDomainValidated
                        .as_oid()
                        .to_vec(),
                },
            ])),
        ])
        .validate(chain, at_epoch_seconds, vec![])
        .unwrap();
}

fn load_b64_file(relative_path: &str) -> Vec<u8> {
    let contents = load_test_resource_file(relative_path);
    let bytes = tyst::encdec::base64::decode(&contents).unwrap();
    bytes
}

fn load_test_resource_file(relative_path: &str) -> String {
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("resources/test");
    file_path.push(relative_path);
    let full_filename = file_path.display().to_string();
    std::fs::read_to_string(file_path).expect(&format!("Missing test data '{full_filename}'."))
}
