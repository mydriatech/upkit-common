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

//! Encapsulated TSTInfo content.

use crate::cert::types::DistinguishedName;
use crate::cert::types::SerialNumber;
use crate::cert::types::WellKnownGeneralName;
use crate::tsp::parse::TimeStampReqParser;
use chrono::TimeZone;
use rasn::types::Integer;
use rasn::types::ObjectIdentifier;

/// Encapsulated TSTInfo content.
///
/// This contains among other things the actual time-stamp time.
#[derive(Debug, Clone)]
pub struct TstInfo {
    tst_info: rasn_cms::tsp::TstInfo,
}

impl TstInfo {
    /// Return a new instance based on the time-stamping request and time-data.
    pub fn new(
        time_stamp_req: &TimeStampReqParser,
        policy_oid: &[u32],
        point_in_time_epoch_micros: u64,
        accuracy_micros: u64,
    ) -> Self {
        let tst_info = rasn_cms::tsp::TstInfo {
            version: 1.into(),
            policy: ObjectIdentifier::new_unchecked(policy_oid.to_vec().into()),
            message_imprint: time_stamp_req.get_message_imprint().to_owned(),
            serial_number: SerialNumber::default().to_rasn_type(),
            gen_time: chrono::Utc
                .timestamp_micros(i64::try_from(point_in_time_epoch_micros).unwrap())
                .unwrap()
                .fixed_offset(),
            accuracy: Some(rasn_cms::tsp::Accuracy {
                seconds: Some(isize::try_from(accuracy_micros / 1_000_000).unwrap())
                    .filter(|value| value != &0)
                    .map(Integer::from),
                millis: Some(isize::try_from((accuracy_micros / 1_000) % 1_000).unwrap())
                    .filter(|value| value != &0)
                    .map(Integer::from),
                micros: Some(isize::try_from(accuracy_micros % 1_000).unwrap())
                    .filter(|value| value != &0)
                    .map(Integer::from),
            }),
            ordering: false,
            nonce: time_stamp_req.get_nonce().to_owned(),
            // the actual identification of the entity that signed the response will always occur through the use of the
            // certificate identifier ... inside a SigningCertificate attribute which is part of the signerInfo
            tsa: None,
            extensions: None,
        };
        Self { tst_info }
    }

    /// Set friendly (but unverified) name of the time-stamping unit that should
    /// be good enough to identify the unit.
    pub fn set_tsa_from_dn(&mut self, dn: &DistinguishedName) {
        self.tst_info.tsa = Some(rasn_pkix::GeneralName::DirectoryName(
            dn.as_rasn_type().unwrap(),
        ));
    }

    /// Get the friendly (but unverified) name of the time-stamping unit that
    /// could be good enough to identify the unit.
    pub fn get_tsa(&self) -> Option<(WellKnownGeneralName, String)> {
        self.tst_info
            .tsa
            .as_ref()
            .and_then(WellKnownGeneralName::from_rasn_type)
    }

    /// Return the policy object identifier that this time-stamping service
    /// adheres to when it produced the result.
    pub fn get_policy(&self) -> Vec<u32> {
        self.tst_info.policy.to_vec()
    }

    /// Serial number of the time stamp.
    pub fn get_serial_number(&self) -> SerialNumber {
        SerialNumber::from_rasn_type(&self.tst_info.serial_number)
    }

    /// Return the Unix epoch time with accuracy in µs.
    pub fn get_epoch_time_micros(&self) -> (u64, u64) {
        //let tst_info = self.get_tst_info().unwrap();
        let epoch_time_micros = u64::try_from(self.tst_info.gen_time.timestamp_micros()).unwrap();
        let mut accuracy_micros = 0;
        if let Some(accuracy) = &self.tst_info.accuracy {
            accuracy_micros += accuracy
                .seconds
                .as_ref()
                .map(|seconds| u64::try_from(seconds).unwrap() * 1_000_000)
                .unwrap_or_default();
            accuracy_micros += accuracy
                .millis
                .as_ref()
                .map(|millis| u64::try_from(millis).unwrap() * 1_000)
                .unwrap_or_default();
            accuracy_micros += accuracy
                .micros
                .as_ref()
                .map(|micros| u64::try_from(micros).unwrap())
                .unwrap_or_default();
        }
        (epoch_time_micros, accuracy_micros)
    }

    /// Get the digest algorithm and the protected digest
    pub fn get_encoded_message_imprint(&self) -> Vec<u8> {
        rasn::der::encode(&self.tst_info.message_imprint).unwrap()
    }

    /// Get the digest algorithm and the protected digest
    pub fn get_message_imprint(&self) -> (Vec<u32>, Vec<u8>) {
        //let tst_info = self.get_tst_info().unwrap();
        let digest_algorithm_oid = self
            .tst_info
            .message_imprint
            .hash_algorithm
            .algorithm
            .to_vec();
        let message_digest = self.tst_info.message_imprint.hashed_message.to_vec();
        (digest_algorithm_oid, message_digest)
    }

    // TODO: Abstract nonce
    /// Get the nonce that was used in the request when available.
    pub fn get_nonce(&self) -> &Option<Integer> {
        &self.tst_info.nonce
    }

    /// Return true of all time stamps from this service are ordered.
    ///
    /// See
    /// [RFC 3161 2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2)
    /// for additional details on how this can be leveraged if the service
    /// supports it.
    ///
    /// In practice however, this is hard to achieve on massive scale and is
    /// probably not very common.
    pub fn get_ordering(&self) -> bool {
        self.tst_info.ordering
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(tst_info: &rasn_cms::tsp::TstInfo) -> Self {
        Self {
            tst_info: tst_info.clone(),
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(self) -> rasn_cms::tsp::TstInfo {
        self.tst_info
    }
}
