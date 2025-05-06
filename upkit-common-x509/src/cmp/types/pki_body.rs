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

//! Certificate Management Protocol (CMP) PKIBody.

use super::ErrorMessage;
use super::InitializationRequest;
use super::InitializationResponse;
use crate::cmp::asn1;
use crate::cmp::error::CmpProcessingError;
use crate::cmp::error::CmpProcessingErrorKind;

/** CMP message inside `PKIMessage` suppported by this implementation.

[RFC 4210 5.1.2](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.2):

```text
   PKIBody ::= CHOICE {
     ir       [0]  CertReqMessages,       --Initialization Req
     ip       [1]  CertRepMessage,        --Initialization Resp
     cr       [2]  CertReqMessages,       --Certification Req
     cp       [3]  CertRepMessage,        --Certification Resp
     p10cr    [4]  CertificationRequest,  --PKCS #10 Cert.  Req.
     popdecc  [5]  POPODecKeyChallContent --pop Challenge
     popdecr  [6]  POPODecKeyRespContent, --pop Response
     kur      [7]  CertReqMessages,       --Key Update Request
     kup      [8]  CertRepMessage,        --Key Update Response
     krr      [9]  CertReqMessages,       --Key Recovery Req
     krp      [10] KeyRecRepContent,      --Key Recovery Resp
     rr       [11] RevReqContent,         --Revocation Request
     rp       [12] RevRepContent,         --Revocation Response
     ccr      [13] CertReqMessages,       --Cross-Cert.  Request
     ccp      [14] CertRepMessage,        --Cross-Cert.  Resp
     ckuann   [15] CAKeyUpdAnnContent,    --CA Key Update Ann.
     cann     [16] CertAnnContent,        --Certificate Ann.
     rann     [17] RevAnnContent,         --Revocation Ann.
     crlann   [18] CRLAnnContent,         --CRL Announcement
     pkiconf  [19] PKIConfirmContent,     --Confirmation
     nested   [20] NestedMessageContent,  --Nested Message
     genm     [21] GenMsgContent,         --General Message
     genp     [22] GenRepContent,         --General Response
     error    [23] ErrorMsgContent,       --Error Message
     certConf [24] CertConfirmContent,    --Certificate confirm
     pollReq  [25] PollReqContent,        --Polling request
     pollRep  [26] PollRepContent         --Polling response
     }
```
*/
pub enum PkiBody {
    /// See [InitializationRequest].
    Ir(Box<InitializationRequest>),
    /// See [InitializationResponse].
    Ip(Box<InitializationResponse>),
    /// See [ErrorMessage].
    Error(Box<ErrorMessage>),
}

impl PkiBody {
    /// Return the ASN.1 tag (≃type) of `PKIBody` in the `PKIMessage.body`.
    pub fn get_tag(body: &asn1::PkiBody) -> usize {
        match body {
            asn1::PkiBody::Ir(_) => 0,
            asn1::PkiBody::Ip(_) => 1,
            asn1::PkiBody::Cr(_) => 2,
            asn1::PkiBody::Cp(_) => 3,
            asn1::PkiBody::P10cr(_) => 4,
            asn1::PkiBody::Popdecc(_) => 5,
            asn1::PkiBody::Popdecr(_) => 6,
            asn1::PkiBody::Kur(_) => 7,
            asn1::PkiBody::Kup(_) => 8,
            asn1::PkiBody::Krr(_) => 9,
            asn1::PkiBody::Krp(_) => 10,
            asn1::PkiBody::Rr(_) => 11,
            asn1::PkiBody::Rp(_) => 12,
            asn1::PkiBody::Ccr(_) => 13,
            asn1::PkiBody::Ccp(_) => 14,
            asn1::PkiBody::Ckuann(_) => 15,
            asn1::PkiBody::Cann(_) => 16,
            asn1::PkiBody::Rann(_) => 17,
            asn1::PkiBody::Crlann(_) => 18,
            asn1::PkiBody::Pkiconf => 19,
            asn1::PkiBody::Nested(_) => 20,
            asn1::PkiBody::Genm(_) => 21,
            asn1::PkiBody::Genp(_) => 22,
            asn1::PkiBody::Error(_) => 23,
            asn1::PkiBody::CertConf(_) => 24,
            asn1::PkiBody::PollReq(_) => 25,
            asn1::PkiBody::PollRep(_) => 26,
        }
    }

    /// Return a new instance from the provided `rasn` type.
    pub fn from_rasn_type(body: &asn1::PkiBody) -> Result<Self, CmpProcessingError> {
        Ok(match body {
            asn1::PkiBody::Ir(cert_req_messages) => PkiBody::Ir(Box::new(
                InitializationRequest::from_rasn_type(cert_req_messages)?,
            )),
            asn1::PkiBody::Ip(cert_rep_message) => PkiBody::Ip(Box::new(
                InitializationResponse::from_rasn_type(cert_rep_message)?,
            )),
            asn1::PkiBody::Error(error_msg_content) => {
                PkiBody::Error(Box::new(ErrorMessage::from_rasn_type(error_msg_content)))
            }
            unknown => Err(
                CmpProcessingErrorKind::UnknownPkiBodyType.error_with_msg(&format!(
                    "Unsupported PKIBody with tag '{}'.",
                    Self::get_tag(unknown)
                )),
            )?,
        })
    }
}
