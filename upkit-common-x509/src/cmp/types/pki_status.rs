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

//! CMP response and failure codes.

use crate::cmp::asn1;
use bitvec::vec::BitVec;
use rasn::types::BitString;

/** CMP PKIStatus response code.

This described the overall status of the requested operation.

[RFC 4210 F](https://www.rfc-editor.org/rfc/rfc4210#appendix-F):

```text
PKIStatus ::= INTEGER {
   accepted               (0),
   -- you got exactly what you asked for
   grantedWithMods        (1),
   -- you got something like what you asked for; the
   -- requester is responsible for ascertaining the differences
   rejection              (2),
   -- you don't get it, more information elsewhere in the message
   waiting                (3),
   -- the request body part has not yet been processed; expect to
   -- hear more later (note: proper handling of this status
   -- response MAY use the polling req/rep PKIMessages specified
   -- in Section 5.3.22; alternatively, polling in the underlying
   -- transport layer MAY have some utility in this regard)
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
    /// You got exactly what you asked for.
    Accepted,
    /// You got something like what you asked for; the requester is responsible
    /// for ascertaining the differences.
    GrantedWithMods,
    /// You don't get it, more information elsewhere in the message.
    Rejection,
    /// The request body part has not yet been processed; expect to hear more
    /// later
    ///
    /// Note: proper handling of this status response MAY use the polling
    /// req/rep PKIMessages ...; alternatively, polling in the underlying
    /// transport layer MAY have some utility in this regard.
    Waiting,
    /// This message contains a warning that a revocation is imminent.
    RevocationWarning,
    /// Notification that a revocation has occurred.
    RevocationNotification,
}

impl PkiStatus {
    /// Return the numeric representation of the status code.
    pub fn as_value(&self) -> u64 {
        match self {
            Self::Accepted => 0,
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
            Self::Accepted => "accepted",
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
            0 => Some(Self::Accepted),
            1 => Some(Self::GrantedWithMods),
            2 => Some(Self::Rejection),
            3 => Some(Self::Waiting),
            4 => Some(Self::RevocationWarning),
            5 => Some(Self::RevocationNotification),
            _unsupported_status_code => None,
        }
    }
}

/** CMP PKIFailureInfo reason code.

This described the why the requested operation has failed.

[RFC 4210 F](https://www.rfc-editor.org/rfc/rfc4210#appendix-F):

```text
   PKIFailureInfo ::= BIT STRING {
   -- since we can fail in more than one way!
   -- More codes may be added in the future if/when required.
       badAlg              (0),
       -- unrecognized or unsupported Algorithm Identifier
       badMessageCheck     (1),
       -- integrity check failed (e.g., signature did not verify)
       badRequest          (2),
       -- transaction not permitted or supported
       badTime             (3),
       -- messageTime was not sufficiently close to the system time,
       -- as defined by local policy
       badCertId           (4),
       -- no certificate could be found matching the provided criteria
       badDataFormat       (5),
       -- the data submitted has the wrong format
       wrongAuthority      (6),
       -- the authority indicated in the request is different from the
       -- one creating the response token
       incorrectData       (7),
       -- the requester's data is incorrect (for notary services)
       missingTimeStamp    (8),
       -- when the timestamp is missing but should be there
       -- (by policy)
       badPOP              (9),
       -- the proof-of-possession failed
       certRevoked         (10),
          -- the certificate has already been revoked
       certConfirmed       (11),
          -- the certificate has already been confirmed
       wrongIntegrity      (12),
          -- invalid integrity, password based instead of signature or
          -- vice versa
       badRecipientNonce   (13),
          -- invalid recipient nonce, either missing or wrong value
       timeNotAvailable    (14),
          -- the TSA's time source is not available
       unacceptedPolicy    (15), 5269 3146 7313 4
          -- the requested TSA policy is not supported by the TSA.
       unacceptedExtension (16),
          -- the requested extension is not supported by the TSA.
       addInfoNotAvailable (17),
          -- the additional information requested could not be
          -- understood or is not available
       badSenderNonce      (18),
          -- invalid sender nonce, either missing or wrong size
       badCertTemplate     (19),
          -- invalid cert. template or missing mandatory information
       signerNotTrusted    (20),
          -- signer of the message unknown or not trusted
       transactionIdInUse  (21),
          -- the transaction identifier is already in use
       unsupportedVersion  (22),
          -- the version of the message is not supported
       notAuthorized       (23),
          -- the sender was not authorized to make the preceding
          -- request or perform the preceding action
       systemUnavail       (24),
       -- the request cannot be handled due to system unavailability
       systemFailure       (25),
       -- the request cannot be handled due to system failure
       duplicateCertReq    (26)
       -- certificate cannot be issued because a duplicate
       -- certificate already exists
   }
```
*/
pub enum PkiFailureInfo {
    /// Unrecognized or unsupported Algorithm Identifier.
    BadAlgo,
    /// Integrity check failed (e.g., signature did not verify).
    BadMessageCheck,
    /// Transaction not permitted or supported.
    BadRequest,
    /// `messageTime` was not sufficiently close to the system time as defined
    /// by local policy.
    BadTime,
    /// No certificate could be found matching the provided criteria.
    BadCertId,
    /// The data submitted has the wrong format.
    BadDataFormat,
    /// The authority indicated in the request is different from the one
    /// creating the response token.
    WrongAuthority,
    /// The requester's data is incorrect (for notary services).
    IncorrectData,
    /// When the timestamp is missing but should be there (by policy).
    MissingTimeStamp,
    /// The proof-of-possession failed.
    BadPop,
    /// The certificate has already been revoked.
    CertRevoked,
    /// The certificate has already been confirmed.
    CertConfirmed,
    /// Invalid integrity, password based instead of signature or vice versa.
    WrongIntegrity,
    /// Invalid recipient nonce, either missing or wrong value.
    BadRecipientNonce,
    /// The TSA's time source is not available.
    TimeNotAvailable,
    /// The requested TSA policy is not supported by the TSA.
    UnacceptedPolicy,
    /// The requested extension is not supported by the TSA.
    UnacceptedExtension,
    /// The additional information requested could not be understood or is not
    /// available.
    AddInfoNotAvailable,
    /// Invalid sender nonce, either missing or wrong size.
    BadSenderNonce,
    /// Invalid cert. template or missing mandatory information.
    BadCertTemplate,
    /// Signer of the message unknown or not trusted.
    SignerNotTrusted,
    /// The transaction identifier is already in use.
    TransactionIdInUse,
    /// The version of the message is not supported.
    UnsupportedVersion,
    /// The sender was not authorized to make the preceding request or perform
    /// the preceding action.
    NotAuthorized,
    /// The request cannot be handled due to system unavailability.
    SystemUnavail,
    /// The request cannot be handled due to system failure.
    SystemFailure,
    /// Certificate cannot be issued because a duplicate certificate already
    /// exists.
    DuplicateCertReq,
}

impl PkiFailureInfo {
    /// Return the numeric bit-index representation of the failure code.
    pub fn as_index(&self) -> usize {
        match self {
            Self::BadAlgo => 0,
            Self::BadMessageCheck => 1,
            Self::BadRequest => 2,
            Self::BadTime => 3,
            Self::BadCertId => 4,
            Self::BadDataFormat => 5,
            Self::WrongAuthority => 6,
            Self::IncorrectData => 7,
            Self::MissingTimeStamp => 8,
            Self::BadPop => 9,
            Self::CertRevoked => 10,
            Self::CertConfirmed => 11,
            Self::WrongIntegrity => 12,
            Self::BadRecipientNonce => 13,
            Self::TimeNotAvailable => 14,
            Self::UnacceptedPolicy => 15,
            Self::UnacceptedExtension => 16,
            Self::AddInfoNotAvailable => 17,
            Self::BadSenderNonce => 18,
            Self::BadCertTemplate => 19,
            Self::SignerNotTrusted => 20,
            Self::TransactionIdInUse => 21,
            Self::UnsupportedVersion => 22,
            Self::NotAuthorized => 23,
            Self::SystemUnavail => 24,
            Self::SystemFailure => 25,
            Self::DuplicateCertReq => 26,
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
            Self::BadMessageCheck => "bad_message_check",
            Self::BadRequest => "bad_request",
            Self::BadTime => "bad_time",
            Self::BadCertId => "bad_cert_id",
            Self::BadDataFormat => "bad_data_format",
            Self::WrongAuthority => "wrong_authority",
            Self::IncorrectData => "incorrect_data",
            Self::MissingTimeStamp => "missing_time_stamp",
            Self::BadPop => "bad_pop",
            Self::CertRevoked => "cert_revoked",
            Self::CertConfirmed => "cert_confirmed",
            Self::WrongIntegrity => "wrong_integrity",
            Self::BadRecipientNonce => "bad_recipient_nonce",
            Self::TimeNotAvailable => "time_not_available",
            Self::UnacceptedPolicy => "unaccepted_policy",
            Self::UnacceptedExtension => "unaccepted_extension",
            Self::AddInfoNotAvailable => "add_info_not_available",
            Self::BadSenderNonce => "bad_sender_nonce",
            Self::BadCertTemplate => "bad_cert_template",
            Self::SignerNotTrusted => "signer_not_trusted",
            Self::TransactionIdInUse => "transaction_id_in_use",
            Self::UnsupportedVersion => "unsupported_version",
            Self::NotAuthorized => "not_authorized",
            Self::SystemUnavail => "system_unavail",
            Self::SystemFailure => "system_failure",
            Self::DuplicateCertReq => "duplicate_cert_req",
        }
    }

    /// Return a new instance from the `rasn` representation.
    pub fn from_value(value: &BitVec<u8, bitvec::order::Msb0>) -> Option<Self> {
        match value.first_one() {
            Some(0) => Some(Self::BadAlgo),
            Some(1) => Some(Self::BadMessageCheck),
            Some(2) => Some(Self::BadRequest),
            Some(3) => Some(Self::BadTime),
            Some(4) => Some(Self::BadCertId),
            Some(5) => Some(Self::BadDataFormat),
            Some(6) => Some(Self::WrongAuthority),
            Some(7) => Some(Self::IncorrectData),
            Some(8) => Some(Self::MissingTimeStamp),
            Some(9) => Some(Self::BadPop),
            Some(10) => Some(Self::CertRevoked),
            Some(11) => Some(Self::CertConfirmed),
            Some(12) => Some(Self::WrongIntegrity),
            Some(13) => Some(Self::BadRecipientNonce),
            Some(14) => Some(Self::TimeNotAvailable),
            Some(15) => Some(Self::UnacceptedPolicy),
            Some(16) => Some(Self::UnacceptedExtension),
            Some(17) => Some(Self::AddInfoNotAvailable),
            Some(18) => Some(Self::BadSenderNonce),
            Some(19) => Some(Self::BadCertTemplate),
            Some(20) => Some(Self::SignerNotTrusted),
            Some(21) => Some(Self::TransactionIdInUse),
            Some(22) => Some(Self::UnsupportedVersion),
            Some(23) => Some(Self::NotAuthorized),
            Some(24) => Some(Self::SystemUnavail),
            Some(25) => Some(Self::SystemFailure),
            Some(26) => Some(Self::DuplicateCertReq),
            _unsupported_failure_info => None,
        }
    }
}

/** CMP PkiStatusInfo.

This described the if the requested operation has succeeded or why it has failed.

[RFC 4210 5.2.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.3):

```text
PKIStatusInfo ::= SEQUENCE {
   status        PKIStatus,
   statusString  PKIFreeText     OPTIONAL,
   failInfo      PKIFailureInfo  OPTIONAL  }
```
*/
pub struct PkiStatusInfo {
    pki_status_info: asn1::PkiStatusInfo,
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
            pki_status_info: asn1::PkiStatusInfo {
                status: pki_status.as_value().into(),
                status_string,
                fail_info: fail_info.as_ref().map(PkiFailureInfo::as_value),
            },
        }
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(self) -> asn1::PkiStatusInfo {
        self.pki_status_info
    }
}
