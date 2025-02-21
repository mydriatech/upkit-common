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

//! Certificate Validity.

use chrono::TimeZone;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

/*
https://docs.rs/hifitime/latest/hifitime/index.html seems a bit overkill unless
we need to do timestamping.

`rasn` depends on `chrono`, os it is probably sane choice to keep down the
dependency tree.
*/

/** Certificate Validity

[RFC5280 4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5):

"CAs conforming to this profile MUST always encode certificate validity dates
through the year 2049 as UTCTime; certificate validity dates in 2050 or later
MUST be encoded as GeneralizedTime."

All times are in Unix Epoch seconds (seconds since 1970-01-01 00:00:00) and
encoded as `u64`.
*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Validity {
    not_before_epoch_seconds: u64,
    not_after_epoch_seconds: u64,
}

impl Validity {
    /// Return a new instance
    pub fn new(not_before: u64, not_after: u64) -> Self {
        if not_after < not_before {
            log::info!(
                "New validity can never be valid! not_before: {not_before}, not_after: {not_after}"
            );
        }
        Self {
            not_before_epoch_seconds: not_before,
            not_after_epoch_seconds: not_after,
        }
    }

    /// Return a new instance where `not_before` is 10 minutes before "now".
    ///
    /// Backdating certificates are commonly used to allow immidiate use of
    /// certificate despite imperfections and clock skew in the real world.
    pub fn with_backdated_not_before_now(not_after: u64) -> Self {
        let not_before = Self::now_epoch_seconds() - 10 * 60;
        Self::new(not_before, not_after)
    }

    /// Return "now" as number of seconds since 1970-01-01 00:00:00.
    pub fn now_epoch_seconds() -> u64 {
        u64::try_from(chrono::Utc::now().timestamp()).unwrap()
    }

    /// Return `not_after` as number of seconds since 1970-01-01 00:00:00.
    pub fn get_not_after(&self) -> u64 {
        self.not_after_epoch_seconds
    }

    /// Return true if the certificate is valid at `point_in_time_epoch_seconds`.
    pub fn is_valid_at(&self, point_in_time_epoch_seconds: u64) -> bool {
        if point_in_time_epoch_seconds > self.not_after_epoch_seconds {
            return false;
        }
        if point_in_time_epoch_seconds < self.not_before_epoch_seconds {
            return false;
        }
        true
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> rasn_pkix::Validity {
        rasn_pkix::Validity {
            not_before: Self::to_rasn_epoch_seconds(self.not_before_epoch_seconds),
            not_after: Self::to_rasn_epoch_seconds(self.not_after_epoch_seconds),
        }
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(validity: &rasn_pkix::Validity) -> Self {
        Self {
            not_before_epoch_seconds: Self::from_rasn_epoch_seconds(&validity.not_before),
            not_after_epoch_seconds: Self::from_rasn_epoch_seconds(&validity.not_after),
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    fn to_rasn_epoch_seconds(epoch_seconds: u64) -> rasn_pkix::Time {
        let date_time_utc = chrono::Utc
            .timestamp_micros(i64::try_from(epoch_seconds * 1_000_000).unwrap())
            .unwrap();
        // Certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime
        //rasn_pkix::Time::Utc(date_time_utc)
        rasn_pkix::Time::General(date_time_utc.fixed_offset())
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    fn from_rasn_epoch_seconds(time: &rasn_pkix::Time) -> u64 {
        u64::try_from(match time {
            rasn_pkix::Time::Utc(datetime_utc) => datetime_utc.timestamp(),
            rasn_pkix::Time::General(datetime_fixed_offset) => datetime_fixed_offset.timestamp(),
        })
        .unwrap()
    }
}
