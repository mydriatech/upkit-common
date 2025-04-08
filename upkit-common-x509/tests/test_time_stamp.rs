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

use upkit_common_x509::tsp::parse::TimeStampReqParser;
use upkit_common_x509::tsp::parse::TimeStampRespParser;
use upkit_common_x509::tsp::validate::TimeStampResponseValidator;

pub fn init_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
}

#[test]
fn test_time_stamp_request_parser() {
    init_logger();
    let encoded_time_stamp_req = load_b64_file("tsp/http_tsa_baltstamp_lt-20250102.tsq.b64");
    let time_stamp_req = TimeStampReqParser::from_bytes(&encoded_time_stamp_req).unwrap();
    let expected_nonce = "3613593832132195395";
    let actual_nonce = time_stamp_req.get_nonce().as_ref().unwrap().to_string();
    log::debug!(
        "Nonce: {}",
        time_stamp_req.get_nonce().as_ref().unwrap().to_string()
    );
    assert_eq!(actual_nonce, expected_nonce);
}

#[test]
fn test_time_stamp_response_parser() {
    init_logger();
    let encoded_time_stamp_resp = load_b64_file("tsp/http_tsa_baltstamp_lt-20250102.tsr.b64");
    let time_stamp_resp = TimeStampRespParser::from_bytes(&encoded_time_stamp_resp).unwrap();
    let expected_nonce = "3613593832132195395";
    let tst_info = time_stamp_resp
        .get_time_stamp_token()
        .unwrap()
        .get_tst_info()
        .clone();
    let tst_info = tst_info.as_ref().unwrap();
    let actual_nonce = tst_info.get_nonce().as_ref().unwrap().to_string();
    log::debug!(
        "Epoch time (micros): {}",
        tst_info.get_epoch_time_micros().0
    );
    assert_eq!(actual_nonce, expected_nonce);
}

#[test]
fn test_time_stamp_response_validation() {
    init_logger();
    //
    let contents = load_test_resource_file("tsp/trust_anchor-globaltrust-2015.pem");
    let trust_anchor = upkit_common_x509::encdec::pem::parse(&contents)
        .unwrap()
        .into_iter()
        .map(|(_marker, bytes)| bytes)
        .next()
        .unwrap();
    let encoded_time_stamp_resp = load_b64_file("tsp/http_tsa_baltstamp_lt-20250102.tsr.b64");
    let encoded_time_stamp_req = load_b64_file("tsp/http_tsa_baltstamp_lt-20250102.tsq.b64");
    // Validate TSP signature and any bundled revocation info
    TimeStampResponseValidator::validate_at_point_of_timestamp(
        vec![trust_anchor],
        &encoded_time_stamp_resp,
    )
    .unwrap();
    // Validate nonce and timing of response
    TimeStampResponseValidator::validate_response_to_request(
        &encoded_time_stamp_req,
        &encoded_time_stamp_resp,
    )
    .unwrap();
}

fn load_b64_file(relative_path: &str) -> Vec<u8> {
    let contents = load_test_resource_file(relative_path);
    let bytes = tyst::encdec::base64::decode(&contents).unwrap();
    bytes
}

fn load_test_resource_file(relative_path: &str) -> String {
    let mut file_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("resources/test");
    file_path.push(relative_path);
    let full_filename = file_path.display().to_string();
    std::fs::read_to_string(file_path).expect(&format!("Missing test data '{full_filename}'."))
}
