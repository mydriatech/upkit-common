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

//! Time stamping response and failure codes.

use bitvec::vec::BitVec;
use rasn::types::BitString;
use rasn::types::Enumerated;

/** Time stamping PKIStatus response code.

This described the overall status of the requested operation.

[RFC 3161 2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2):

```text
PKIStatus ::= INTEGER {
   granted                (0),
   -- when the PKIStatus contains the value zero a TimeStampToken, as
      requested, is present.
   grantedWithMods        (1),
    -- when the PKIStatus contains the value one a TimeStampToken,
      with modifications, is present.
   rejection              (2),
   waiting                (3),
   revocationWarning      (4),
    -- this message contains a warning that a revocation is
    -- imminent
   revocationNotification (5)
    -- notification that a revocation has occurred  }
```

See [RFC 2510 3.2.3](https://www.rfc-editor.org/rfc/rfc2510#section-3.2.3) for
the original description of these status codes.

*/
pub enum PkiStatus {
    /// TimeStampToken, as requested, is present.
    Granted,
    /// TimeStampToken, with modifications, is present.
    GrantedWithMods,
    /// Request can't be fullfilled.
    Rejection,
    /// RFC 2510: "the request body part has not yet been processed, expect to
    /// hear more later"
    ///
    /// (In the context of time-stamping over HTTP RPC this message does not
    /// really make sense.)
    Waiting,
    /// A revocation is imminent.
    RevocationWarning,
    /// Notification that a revocation has occurred
    RevocationNotification,
}

impl PkiStatus {
    /// Return the numeric representation of the status code.
    pub fn as_value(&self) -> u64 {
        match self {
            Self::Granted => 0,
            Self::GrantedWithMods => 1,
            Self::Rejection => 2,
            Self::Waiting => 3,
            Self::RevocationWarning => 4,
            Self::RevocationNotification => 5,
        }
    }

    /// Return the snake-case name of the status code.
    pub fn name(&self) -> &str {
        match self {
            Self::Granted => "granted",
            Self::GrantedWithMods => "granted_with_mods",
            Self::Rejection => "rejection",
            Self::Waiting => "waiting",
            Self::RevocationWarning => "revocation_warning",
            Self::RevocationNotification => "revocation_notification",
        }
    }

    /// Return a new instance from the numeric representation of the status code.
    pub fn from_value(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Granted),
            1 => Some(Self::GrantedWithMods),
            2 => Some(Self::Rejection),
            3 => Some(Self::Waiting),
            4 => Some(Self::RevocationWarning),
            5 => Some(Self::RevocationNotification),
            _unsupported_status_code => None,
        }
    }
}

/** Time stamping PKIFailureInfo reason code.

This described the why the requested operation has failed.

[RFC 3161 2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2):

```text
PKIFailureInfo ::= BIT STRING {
    badAlg               (0),
      -- unrecognized or unsupported Algorithm Identifier
    badRequest           (2),
      -- transaction not permitted or supported
    badDataFormat        (5),
      -- the data submitted has the wrong format
    timeNotAvailable    (14),
      -- the TSA's time source is not available
    unacceptedPolicy    (15),
      -- the requested TSA policy is not supported by the TSA
    unacceptedExtension (16),
      -- the requested extension is not supported by the TSA
    addInfoNotAvailable (17)
      -- the additional information requested could not be understood
      -- or is not available
    systemFailure       (25)
      -- the request cannot be handled due to system failure  }
```
*/
pub enum PkiFailureInfo {
    /// Unrecognized or unsupported Algorithm Identifier.
    BadAlgo,
    /// Transaction not permitted or supported.
    BadRequest,
    /// The data submitted has the wrong format.
    BadDataFormat,
    /// The TSA's time source is not available.
    TimeNotAvailable,
    /// The requested TSA policy is not supported by the TSA.
    UnacceptedPolicy,
    /// The requested extension is not supported by the TSA.
    UnacceptedExtension,
    /// The additional information requested could not be understood or is not available
    AddInfoNotAvailable,
    /// The request cannot be handled due to system failure.
    SystemFailure,
}

impl PkiFailureInfo {
    /// Return the numeric bit-index representation of the failure code.
    pub fn as_index(&self) -> usize {
        match self {
            Self::BadAlgo => 0,
            Self::BadRequest => 2,
            Self::BadDataFormat => 5,
            Self::TimeNotAvailable => 14,
            Self::UnacceptedPolicy => 15,
            Self::UnacceptedExtension => 16,
            Self::AddInfoNotAvailable => 17,
            Self::SystemFailure => 25,
        }
    }

    /// Return the [BitString] representation of the failure code.
    pub fn as_value(&self) -> BitString {
        let index = self.as_index();
        let mut bv = BitVec::<u8, bitvec::order::Msb0>::repeat(false, index + 1);
        bv.set(index, true);
        bv
    }

    /// Return the snake-case name of the failure code.
    pub fn name(&self) -> &str {
        match self {
            Self::BadAlgo => "bad_alg",
            Self::BadRequest => "bad_request",
            Self::BadDataFormat => "bad_data_format",
            Self::TimeNotAvailable => "time_not_available",
            Self::UnacceptedPolicy => "unaccepted_policy",
            Self::UnacceptedExtension => "unaccepted_extension",
            Self::AddInfoNotAvailable => "add_info_not_available",
            Self::SystemFailure => "system_failure",
        }
    }

    /// Return a new instance from the `rasn` representation.
    pub fn from_value(value: &BitVec<u8, bitvec::order::Msb0>) -> Option<Self> {
        match value.first_one() {
            Some(0) => Some(Self::BadAlgo),
            Some(2) => Some(Self::BadRequest),
            Some(5) => Some(Self::BadDataFormat),
            Some(14) => Some(Self::TimeNotAvailable),
            Some(15) => Some(Self::UnacceptedPolicy),
            Some(16) => Some(Self::UnacceptedExtension),
            Some(17) => Some(Self::AddInfoNotAvailable),
            Some(25) => Some(Self::SystemFailure),
            _unsupported_failure_info => None,
        }
    }
}

/** Time stamping PkiStatusInfo.

This described the if the requested operation has succeeded or why it has failed.

[RFC 3161 2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2):

```text
PKIStatusInfo ::= SEQUENCE {
   status        PKIStatus,
   statusString  PKIFreeText     OPTIONAL,
   failInfo      PKIFailureInfo  OPTIONAL  }
```
*/
pub struct PkiStatusInfo {
    pki_status_info: rasn_cms::tsp::PkiStatusInfo,
}

impl PkiStatusInfo {
    /// Return a new instance.
    pub fn new(
        pki_status: &PkiStatus,
        status_string: &[String],
        fail_info: &Option<PkiFailureInfo>,
    ) -> Self {
        let status_string = if status_string.is_empty() {
            None
        } else {
            status_string.to_vec().into()
        };
        Self {
            pki_status_info: rasn_cms::tsp::PkiStatusInfo {
                status: rasn_cms::tsp::PkiStatus::from_discriminant(
                    isize::try_from(pki_status.as_value()).unwrap(),
                )
                .unwrap(),
                status_string,
                fail_info: fail_info.as_ref().map(PkiFailureInfo::as_value),
            },
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(self) -> rasn_cms::tsp::PkiStatusInfo {
        self.pki_status_info
    }
}
