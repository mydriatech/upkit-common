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

use upkit_common_x509::cert::parse::CertificateParser;
use upkit_common_x509::cert::parse::CertificateParsingError;
use upkit_common_x509::encdec::pem::Marker;
use upkit_common_x509::ocsp::parse::OcspParsingError;
use upkit_common_x509::ocsp::parse::OcspRequestParser;
use upkit_common_x509::ocsp::parse::OcspResponseParser;
use upkit_common_x509::ocsp::validate::CertificateOcspValidator;

pub fn init_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        //.filter(Some("rustls"), log::LevelFilter::Info)
        .try_init();
}

#[test]
fn test_ocsp_real_world() {
    init_logger();

    // Load certs and CRLS
    let root_ca = get_certificate_from_pem("crl/globaltrust-2015.pem").unwrap();
    let sub_ca = get_certificate_from_pem("crl/globaltrust-2015-advanced-seal-1.pem").unwrap();
    let leaf = get_certificate_from_pem("crl/leaf.pem").unwrap();
    let sub_ca_ocsp_req =
        get_ocsp_req_from_b64("ocsp/globaltrust-2015-advanced-seal-1.ocsp.req.b64").unwrap();
    let sub_ca_ocsp_resp =
        get_ocsp_resp_from_b64("ocsp/globaltrust-2015-advanced-seal-1.ocsp.resp.b64").unwrap();
    let leaf_ocsp_req = get_ocsp_req_from_b64("ocsp/leaf.ocsp.req.b64").unwrap();
    let leaf_ocsp_resp = get_ocsp_resp_from_b64("ocsp/leaf.ocsp.resp.b64").unwrap();
    let point_in_time_epoch_seconds = 1743681764;
    // Verify cert using OCSP response
    CertificateOcspValidator::validate(
        &root_ca,
        &sub_ca,
        &sub_ca_ocsp_resp,
        point_in_time_epoch_seconds,
    )
    .unwrap();
    CertificateOcspValidator::validate(
        &sub_ca,
        &leaf,
        &leaf_ocsp_resp,
        point_in_time_epoch_seconds,
    )
    .unwrap();
    // Verify that the response was for the request
    CertificateOcspValidator::validate_response_to_request(&sub_ca_ocsp_req, &sub_ca_ocsp_resp)
        .unwrap();
    CertificateOcspValidator::validate_response_to_request(&leaf_ocsp_req, &leaf_ocsp_resp)
        .unwrap();
}

fn get_certificate_from_pem(
    relative_path: &str,
) -> Result<CertificateParser, CertificateParsingError> {
    CertificateParser::from_bytes(&get_single_item(
        &load_test_resource_file(relative_path),
        &Marker::Certificate,
    ))
}

fn get_ocsp_req_from_b64(relative_path: &str) -> Result<OcspRequestParser, OcspParsingError> {
    OcspRequestParser::from_bytes(
        &tyst::encdec::base64::decode(&load_test_resource_file(relative_path)).unwrap(),
    )
}

fn get_ocsp_resp_from_b64(relative_path: &str) -> Result<OcspResponseParser, OcspParsingError> {
    OcspResponseParser::from_bytes(
        &tyst::encdec::base64::decode(&load_test_resource_file(relative_path)).unwrap(),
    )
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

fn load_test_resource_file(relative_path: &str) -> String {
    let mut file_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("resources/test");
    file_path.push(relative_path);
    let full_filename = file_path.display().to_string();
    log::trace!("Loading '{full_filename}'.");
    std::fs::read_to_string(file_path).expect(&format!("Missing test data '{full_filename}'."))
}
