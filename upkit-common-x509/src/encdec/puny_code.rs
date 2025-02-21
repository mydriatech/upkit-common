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

//! [RFC 3492](https://www.rfc-editor.org/rfc/rfc3492) Puny code

/// [RFC 3492](https://www.rfc-editor.org/rfc/rfc3492) Puny code implementation
pub fn encode(dns_name_utf8: &str) -> String {
    let dns_name_punycode = dns_name_utf8
        .to_lowercase()
        .split('.')
        .map(|part| {
            if part.is_ascii() {
                part.to_string()
            } else {
                // RFC 3492 implementation
                String::from("xn--") + idna::punycode::encode_str(part).unwrap().as_str()
            }
        })
        .collect::<Vec<_>>()
        .join(".");
    if log::log_enabled!(log::Level::Debug) {
        log::debug!(
            "dns_name. input: {}, punycode: {}",
            &dns_name_utf8,
            &dns_name_punycode
        );
    }
    dns_name_punycode
}

/// [RFC 3492](https://www.rfc-editor.org/rfc/rfc3492) Puny code implementation
pub fn decode(dns_name_punycode: &str) -> String {
    let dns_name_utf8 = dns_name_punycode
        .to_lowercase()
        .split('.')
        .map(|part| {
            if part.starts_with("xn--") {
                idna::punycode::decode_to_string(part.split_at(4).1).unwrap()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(".");
    if log::log_enabled!(log::Level::Debug) {
        log::debug!(
            "dns_name. punycode: {}, output: {}",
            &dns_name_punycode,
            &dns_name_utf8,
        );
    }
    dns_name_utf8
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn encdec_puny() {
        init_logger();
        let dns_name_utf8 = "übernice.fantastic.åäö";
        assert_eq!(dns_name_utf8, decode(&encode(dns_name_utf8)))
    }
}
