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

//! [RFC7468](https://datatracker.ietf.org/doc/html/rfc7468) Textual Encodings of PKIX, PKCS, and CMS Structures

mod pem_markers;

pub use self::pem_markers::Marker;
pub use super::DecodingError;

/// Parse the text as PEM encoded objects
///
/// The content is not vetted in any way to correspond to the claimed marker.
pub fn parse(textual_encoding: &str) -> Result<Vec<(Marker, Vec<u8>)>, DecodingError> {
    let mut ret = vec![];
    let lines = textual_encoding.lines();
    let mut content = None;
    for line in lines {
        if content.is_none()
            && line.starts_with(Marker::BEGIN_LINE_START)
            && line.ends_with(Marker::BEGIN_LINE_FINISH)
        {
            content = Some((Marker::from_begin_line(line), Vec::<u8>::new()));
        } else if line.starts_with(Marker::END_LINE_START)
            && line.ends_with(Marker::END_LINE_FINISH)
        {
            ret.push(content.take().unwrap());
        } else {
            // There should be 64 base64-chars on each line except for the last one
            let decoded = &tyst::encdec::base64::decode(line)
                .map_err(|e| DecodingError::with_msg(&e.to_string()))?;
            content.as_mut().unwrap().1.extend_from_slice(decoded);
        }
    }
    if content.is_some() {
        // Missing end..
        return Err(DecodingError::with_msg(
            "Unable to find any content in PEM.",
        ));
    }
    Ok(ret)
}

/// Encode the objects as RFC7468 textual representation (≃"PEM encoding").
///
/// The content is not vetted in any way to correspond to the claimed marker.
pub fn encode(encoded_objects: &[(Marker, &[u8])]) -> String {
    let mut ret = String::new();
    for (marker, data) in encoded_objects {
        ret.push_str(Marker::BEGIN_LINE_START);
        ret.push_str(marker.as_str());
        ret.push_str(Marker::BEGIN_LINE_FINISH);
        ret.push('\n');
        let b64 = tyst::encdec::base64::encode(data);
        for line in b64.as_bytes().chunks(64) {
            ret.push_str(core::str::from_utf8(line).unwrap());
            ret.push('\n');
        }
        ret.push_str(Marker::END_LINE_START);
        ret.push_str(marker.as_str());
        ret.push_str(Marker::END_LINE_FINISH);
        ret.push('\n');
    }
    ret
}
