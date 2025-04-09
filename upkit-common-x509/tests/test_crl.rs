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

use upkit_common_util::testing::*;
use upkit_common_x509::cert::parse::CertificateParser;
use upkit_common_x509::cert::parse::CertificateParsingError;
use upkit_common_x509::crl::parse::CrlParser;
use upkit_common_x509::crl::parse::CrlParsingError;
use upkit_common_x509::crl::validate::CertificateCrlValidator;
use upkit_common_x509::encdec::pem::Marker;

#[test]
fn test_crl_real_world() {
    initialize_env_logger();

    // Load certs and CRLS
    let root_ca = get_certificate_from_pem("crl/globaltrust-2015.pem").unwrap();
    let sub_ca = get_certificate_from_pem("crl/globaltrust-2015-advanced-seal-1.pem").unwrap();
    let leaf = get_certificate_from_pem("crl/leaf.pem").unwrap();
    let root_ca_crl = get_crl_from_pem("crl/globaltrust-2015.crl.20250403.pem").unwrap();
    let sub_ca_crl =
        get_crl_from_pem("crl/globaltrust-2015-advanced-seal-1.crl.20250403.pem").unwrap();
    let point_in_time_epoch_seconds = 1743681764;
    // Verify CRL signatures and that it is issued by the right CA
    // Verify that CRL is valid at point in time
    // Verify subject's revocation status at point in time
    CertificateCrlValidator::validate(&root_ca, &sub_ca, &root_ca_crl, point_in_time_epoch_seconds)
        .unwrap();
    CertificateCrlValidator::validate(&sub_ca, &leaf, &sub_ca_crl, point_in_time_epoch_seconds)
        .unwrap();
    // Also ensure that just the CRL issuer validation part works
    CertificateCrlValidator::validate_crl_issuance(
        &root_ca,
        sub_ca.get_crl_distribution_point(),
        &root_ca_crl,
    )
    .unwrap();
    CertificateCrlValidator::validate_crl_issuance(
        &sub_ca,
        leaf.get_crl_distribution_point(),
        &sub_ca_crl,
    )
    .unwrap();
}

fn get_certificate_from_pem(
    relative_path: &str,
) -> Result<CertificateParser, CertificateParsingError> {
    CertificateParser::from_bytes(&get_single_item(
        &load_resource_file_as_string(env!("CARGO_MANIFEST_DIR"), relative_path),
        &Marker::Certificate,
    ))
}

fn get_crl_from_pem(relative_path: &str) -> Result<CrlParser, CrlParsingError> {
    CrlParser::from_bytes(&get_single_item(
        &load_resource_file_as_string(env!("CARGO_MANIFEST_DIR"), relative_path),
        &Marker::CertificateRevocationList,
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
