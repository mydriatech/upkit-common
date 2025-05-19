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
use tyst::traits::se::ToPublicKey;
use upkit_common_util::testing::*;
use upkit_common_x509::cert::parse::CertificateParser;
use upkit_common_x509::cert::parse::CertificateParsingError;
use upkit_common_x509::encdec::pem::Marker;

#[test]
fn test_cert_parse() {
    initialize_env_logger();

    let filename = "cert/ejbca_mldsa_ca.pem";
    let cert = get_certificate_from_pem(filename).unwrap();
    let spki = cert.get_encoded_subject_public_key_info();
    let public_key = spki.to_public_key();
    let tbs_certificate = cert.get_encoded_tbs_certificate();
    let (oid, signature) = cert.get_encoded_signature();
    if let Some(mut se) = Tyst::instance().ses().by_oid(&oid) {
        if se.verify(public_key.as_ref(), &signature, &tbs_certificate) {
            return;
        }
    }
    panic!("Failed to verify self-signed certificate '{filename}'.");
}

fn get_certificate_from_pem(
    relative_path: &str,
) -> Result<CertificateParser, CertificateParsingError> {
    CertificateParser::from_bytes(&get_single_item(
        &load_resource_file_as_string(env!("CARGO_MANIFEST_DIR"), relative_path),
        &Marker::Certificate,
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
