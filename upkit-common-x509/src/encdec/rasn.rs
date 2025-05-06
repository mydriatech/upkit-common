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

//! Helper functions for interactions with the
//! [`rasn`](https://github.com/librasn/rasn) crates.

use chrono::TimeZone;
use rasn::types::Any;
use rasn::types::IntegerType;
use rasn::types::ObjectIdentifier;
use rasn_pkix::AlgorithmIdentifier;
use rasn_pkix::DisplayText;

/// Convert `rasn_pkix::DisplayText` to a regular Rust UTF-8 [String].
pub fn display_text_as_string(display_text: &DisplayText) -> String {
    match display_text {
        DisplayText::Ia5String(s) => s.to_string(),
        DisplayText::VisibleString(s) => s.to_string(),
        DisplayText::BmpString(s) => s
            .iter()
            .map(|c| char::from_u32(*c as u32).unwrap())
            .collect::<String>(),
        DisplayText::Utf8String(s) => s.to_string(),
    }
}

/// Convert `rasn::types::Integer` to [usize].
///
/// Panics if `value` is negative or too large.
pub fn integer_as_usize(value: &rasn::types::Integer) -> usize {
    /*
    match value {
        rasn::types::Integer::Primitive(value) => usize::try_from(*value).unwrap(),
        rasn::types::Integer::Variable(value) => {
            let (sign, dig) = value.to_u32_digits();
            if sign.eq(&num_bigint::Sign::Minus) || dig.len() != 1 {
                0
            } else {
                usize::try_from(*dig.first().unwrap()).unwrap()
            }
        }
    }
    */
    value.try_into().unwrap()
}

/// Convert `rasn::types::Integer` to [isize].
///
/// Panics if `value` is too large.
pub fn integer_as_isize(value: &rasn::types::Integer) -> isize {
    /*
    match value. {
        IntegerKind::Primitive(value) => *value,
        IntegerKind::Variable(value) => {
            let (sign, dig) = value.to_u32_digits();
            if sign.eq(&num_bigint::Sign::Minus) || dig.len() != 1 {
                -isize::try_from(*dig.first().unwrap()).unwrap()
            } else {
                isize::try_from(*dig.first().unwrap()).unwrap()
            }
        }
    }
    */
    value.try_into().unwrap()
}

/// Convert `rasn::types::Integer` to big endian encoded bytes.
pub fn integer_as_bytes_be(value: &rasn::types::Integer) -> Vec<u8> {
    value.to_signed_bytes_be().0.as_ref().to_vec()
    /*
    match value {
        rasn::types::Integer::Primitive(value) => (*value).to_be_bytes().to_vec(),
        rasn::types::Integer::Variable(value) => value.to_signed_bytes_be(),
    }
    */
}

/// Return a new `rasn_pkix::AlgorithmIdentifier` without parameters from the
/// provided Object Identifier.
// TODO: This is too simplified to support every alg, but its good enough for now...
pub fn oid_as_algorithm_identifier(oid: &[u32]) -> AlgorithmIdentifier {
    AlgorithmIdentifier {
        algorithm: ObjectIdentifier::new_unchecked(oid.to_vec().into()),
        parameters: Some(null()),
    }
}

pub fn null() -> Any {
    Any::new(rasn::der::encode(&()).unwrap())
}

/// Return Object Identifier without parameters from the provided
/// `rasn_pkix::AlgorithmIdentifier`.
// TODO: This is too simplified to support every alg, but its good enough for now...
pub fn algorithm_identifier_as_oid(algorithm_identifier: &AlgorithmIdentifier) -> Vec<u32> {
    algorithm_identifier.algorithm.to_vec()
}

/// Return the first extension with the supplied Object Identifier.
///
/// Additional extensions are ignored.
pub fn first_extension_by_oid(
    extensions: &rasn_pkix::Extensions,
    oid: &[u32],
) -> Option<rasn_pkix::Extension> {
    extensions
        .iter()
        .find(|extension| {
            rasn::types::ObjectIdentifier::new_unchecked(oid.to_vec().into()).eq(&extension.extn_id)
        })
        .cloned()
}

#[inline]
pub fn debug_assert_extension_oid(extension: &rasn_pkix::Extension, oid: &[u32]) {
    debug_assert!(
        rasn::types::ObjectIdentifier::new_unchecked(oid.to_vec().into()).eq(&extension.extn_id),
        "Wrong extension invoked. Expected OID {oid:?}. Actual OID: {}.",
        &extension.extn_id
    )
}

pub fn to_rasn_extension<T: rasn::Encode>(
    oid: &[u32],
    critical: bool,
    value: &T,
) -> rasn_pkix::Extension {
    rasn_pkix::Extension {
        extn_id: rasn::types::ObjectIdentifier::new_unchecked(oid.to_vec().into()),
        critical,
        extn_value: rasn::types::OctetString::from(rasn::der::encode(value).unwrap()),
    }
}

pub fn from_rasn_extension<T: rasn::Decode>(oid: &[u32], extension: &rasn_pkix::Extension) -> T {
    debug_assert_extension_oid(extension, oid);
    rasn::der::decode::<T>(&extension.extn_value).unwrap()
}

/// Return the time in epoch seconds from the `rasn` ASN.1 library type.
pub fn from_rasn_epoch_seconds(time: &rasn_pkix::Time) -> u64 {
    u64::try_from(match time {
        rasn_pkix::Time::Utc(datetime_utc) => datetime_utc.timestamp(),
        rasn_pkix::Time::General(datetime_fixed_offset) => datetime_fixed_offset.timestamp(),
    })
    .unwrap()
}

/// Return value in a form that is easy to process by the ASN.1 library `rasn`.
pub fn to_rasn_epoch_seconds(epoch_seconds: u64) -> rasn_pkix::Time {
    // Certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime
    //rasn_pkix::Time::Utc(date_time_utc)
    rasn_pkix::Time::General(to_generalized_time(epoch_seconds))
}

/// Return value in a form that is easy to process by the ASN.1 library `rasn`.
pub fn to_generalized_time(epoch_seconds: u64) -> rasn::types::GeneralizedTime {
    chrono::Utc
        .timestamp_micros(i64::try_from(epoch_seconds * 1_000_000).unwrap())
        .unwrap()
        .fixed_offset()
}
