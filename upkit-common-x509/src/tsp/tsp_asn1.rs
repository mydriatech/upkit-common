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

//! ASN.1 module for [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161).

use rasn::prelude::*;
use rasn::types::OctetString;
use rasn::{AsnType, Decode, Encode};
use rasn_cms::ContentInfo;
use rasn_pkix::{AlgorithmIdentifier, Extensions, GeneralName};

/** RFC 3161: TSAPolicyId

```text
   TSAPolicyId ::= OBJECT IDENTIFIER
```
*/
pub type TsaPolicyId = ObjectIdentifier;

/** RFC 3161: MessageImprint

```text
   MessageImprint ::= SEQUENCE  {
           hashAlgorithm                AlgorithmIdentifier,
           hashedMessage                OCTET STRING  }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifier,
    pub hashed_message: OctetString,
}

/** RFC 3161: TimeStampReq

```text
   TimeStampReq ::= SEQUENCE  {
      version                      INTEGER  { v1(1) },
      messageImprint               MessageImprint,
        --a hash algorithm OID and the hash value of the data to be
        --time-stamped
      reqPolicy             TSAPolicyId              OPTIONAL,
      nonce                 INTEGER                  OPTIONAL,
      certReq               BOOLEAN                  DEFAULT FALSE,
      extensions            [0] IMPLICIT Extensions  OPTIONAL  }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeStampReq {
    pub version: u64,
    pub message_imprint: MessageImprint,
    pub req_policy: Option<TsaPolicyId>,
    pub nonce: Option<Integer>,
    #[rasn(default = "default_false")]
    pub cert_req: bool,
    #[rasn(tag(0))]
    pub extensions: Option<Extensions>,
}

fn default_false() -> bool {
    false
}

/** RFC 3161: TimeStampResp

```text
   TimeStampResp ::= SEQUENCE  {
      status                  PKIStatusInfo,
      timeStampToken          TimeStampToken     OPTIONAL  }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeStampResp {
    pub status: PkiStatusInfo,
    pub time_stamp_token: Option<TimeStampToken>,
}

/** RFC 2510 3.2.3: PKIStatusInfo

```text
   PKIStatusInfo ::= SEQUENCE {
      status        PKIStatus,
      statusString  PKIFreeText     OPTIONAL,
      failInfo      PKIFailureInfo  OPTIONAL  }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PkiStatusInfo {
    pub status: PkiStatus,
    pub status_string: Option<PkiFreeText>,
    pub fail_info: Option<PkiFailureInfo>,
}

/** RFC 2510 3.2.3: PKIStatus

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

NOTE: This also exists in CMP (RFC 4210), where "granted" is named "accepted".
*/
pub type PkiStatus = u64;

/** RFC 2510 3.2.3: PKIFreeText

```text
   PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
       -- text encoded as UTF-8 String (note:  each UTF8String SHOULD
       -- include an RFC 1766 language tag to indicate the language
       -- of the contained text)
```

NOTE: This also exists in CMP (RFC 4210).
*/
pub type PkiFreeText = SequenceOf<Utf8String>;

/** RFC 2510 3.2.3: PKIFailureInfo

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

NOTE: This also exists in CMP (RFC 4210).
*/
pub type PkiFailureInfo = BitString;

/** RFC 3161: TimeStampToken

```text
   TimeStampToken ::= ContentInfo
     -- contentType is id-signedData ([CMS])
     -- content is SignedData ([CMS])
```
*/
pub type TimeStampToken = ContentInfo;

/** RFC 3161: TSTInfo

```text
   TSTInfo ::= SEQUENCE  {
      version                      INTEGER  { v1(1) },
      policy                       TSAPolicyId,
      messageImprint               MessageImprint,
        -- MUST have the same value as the similar field in
        -- TimeStampReq
      serialNumber                 INTEGER,
       -- Time-Stamping users MUST be ready to accommodate integers
       -- up to 160 bits.
      genTime                      GeneralizedTime,
      accuracy                     Accuracy                 OPTIONAL,
      ordering                     BOOLEAN             DEFAULT FALSE,
      nonce                        INTEGER                  OPTIONAL,
        -- MUST be present if the similar field was present
        -- in TimeStampReq.  In that case it MUST have the same value.
      tsa                          [0] GeneralName          OPTIONAL,
      extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct TstInfo {
    pub version: u64,
    pub policy: TsaPolicyId,
    pub message_imprint: MessageImprint,
    pub serial_number: Integer,
    pub gen_time: GeneralizedTime,
    pub accuracy: Option<Accuracy>,
    #[rasn(default = "default_false")]
    pub ordering: bool,
    pub nonce: Option<Integer>,
    #[rasn(tag(explicit(0)))]
    pub tsa: Option<GeneralName>,
    #[rasn(tag(1))]
    pub extensions: Option<Extensions>,
}

/** RFC 3161: Accuracy

```text
   Accuracy ::= SEQUENCE {
         seconds        INTEGER              OPTIONAL,
         millis     [0] INTEGER  (1..999)    OPTIONAL,
         micros     [1] INTEGER  (1..999)    OPTIONAL  }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Accuracy {
    // OpenSSL requires this to be Integer::Primitive
    pub seconds: Option<Integer>,
    #[rasn(tag(0))]
    pub millis: Option<Integer>,
    #[rasn(tag(1))]
    pub micros: Option<Integer>,
}
