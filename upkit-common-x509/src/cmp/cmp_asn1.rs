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

//! ASN.1 module for Certificate Management Protocol.
//!
//! Objects here are defined in:
//!
//! * [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) Certificate Management
//!   Protocol (CMP)
//! * [RFC 4211](https://www.rfc-editor.org/rfc/rfc4211) Certificate Request
//!   Message Format (CRMF)
//! * [RFC 9480](https://www.rfc-editor.org/rfc/rfc9480) Certificate Management
//!   Protocol (CMP) Updates
//!
//! Related standards:
//!
//! * [RFC 6712](https://www.rfc-editor.org/rfc/rfc6712) HTTP Transfer for CMP
//! * [RFC 9481](https://www.rfc-editor.org/rfc/rfc9481) CMP Algorithms
//! * [RFC 9483](https://www.rfc-editor.org/rfc/rfc9483) Lightweight CMP Profile
//!
//! Expected changes:
//!
//! * [draft-ietf-lamps-rfc4210bis](https://www.ietf.org/archive/id/draft-ietf-lamps-rfc4210bis-18.html)
//!   will superseed RFC 4210.
//! * [draft-ietf-lamps-rfc6712bis](https://www.ietf.org/archive/id/draft-ietf-lamps-rfc6712bis-10.html)
//!   will superseed RFC 6712.

// TODO: Re-license and contribute this upstream to `rasn`?

use rasn::prelude::*;
use rasn::{AsnType, Decode, Encode};
use rasn_cms::EnvelopedData;
use rasn_pkix::{AttributeTypeAndValue, GeneralName};

/**

[RFC 4210 5.1](https://www.rfc-editor.org/rfc/rfc4210#section-5.1):

```text
   PKIMessage ::= SEQUENCE {
      header           PKIHeader,
      body             PKIBody,
      protection   [0] PKIProtection OPTIONAL,
      extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                        OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PkiMessage {
    pub header: PkiHeader,
    pub body: PkiBody,
    #[rasn(tag(0))]
    pub protection: Option<PkiProtection>,
    #[rasn(tag(1))]
    pub extra_certs: Option<SequenceOf<CmpCertificate>>,
}

/**

[RFC 4210 5.1](https://www.rfc-editor.org/rfc/rfc4210#section-5.1):

```text
   PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
```
*/
pub type PkiMessages = SequenceOf<PkiMessage>;

/**

[RFC 4210 5.1.1](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1) updated
by [RFC 9480 2.3](https://www.rfc-editor.org/rfc/rfc9480#section-2.3):

```text
   PKIHeader ::= SEQUENCE {
       pvno                INTEGER     { cmp1999(1), cmp2000(2),
                                         cmp2021(3) },
       sender              GeneralName,
       recipient           GeneralName,
       messageTime     [0] GeneralizedTime         OPTIONAL,
       protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
       senderKID       [2] KeyIdentifier           OPTIONAL,
       recipKID        [3] KeyIdentifier           OPTIONAL,
       transactionID   [4] OCTET STRING            OPTIONAL,
       senderNonce     [5] OCTET STRING            OPTIONAL,
       recipNonce      [6] OCTET STRING            OPTIONAL,
       freeText        [7] PKIFreeText             OPTIONAL,
       generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                           InfoTypeAndValue     OPTIONAL
   }
   PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PkiHeader {
    pub pvno: Integer,
    pub sender: GeneralName,
    pub recipient: GeneralName,
    #[rasn(tag(0))]
    pub message_time: Option<GeneralizedTime>,
    #[rasn(tag(1))]
    pub protection_alg: Option<rasn_pkix::AlgorithmIdentifier>,
    #[rasn(tag(2))]
    pub sender_kid: Option<rasn_pkix::KeyIdentifier>,
    #[rasn(tag(3))]
    pub recip_kid: Option<rasn_pkix::KeyIdentifier>,
    #[rasn(tag(4))]
    pub transaction_id: Option<OctetString>,
    #[rasn(tag(5))]
    pub sender_nonce: Option<OctetString>,
    #[rasn(tag(6))]
    pub recip_nonce: Option<OctetString>,
    #[rasn(tag(7))]
    pub free_text: Option<PkiFreeText>,
    #[rasn(tag(8))]
    pub general_info: Option<SequenceOf<InfoTypeAndValue>>,
}

/**

[RFC 4210 5.1.1](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1):

```text
   PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
```
*/
pub type PkiFreeText = SequenceOf<Utf8String>;

/**

[RFC 4210 5.1.1.2](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1.2):

```text
   ConfirmWaitTimeValue ::= GeneralizedTime
```
*/
pub type ConfirmWaitTimeValue = GeneralizedTime;

/**

[RFC 9480 2.4](https://www.rfc-editor.org/rfc/rfc9480#section-2.4):

```text
   id-it-certProfile  OBJECT IDENTIFIER ::= {id-it 21}
   CertProfileValue ::= SEQUENCE SIZE (1..MAX) OF UTF8String
```
*/
pub type CertProfileValue = SequenceOf<Utf8String>;

/**

[RFC 4210 5.1.2](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.2):

```text
   ConfirmWaitTimeValue ::= GeneralizedTime


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
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PkiBody {
    /// Initialization Req
    #[rasn(tag(0))]
    Ir(Box<CertReqMessages>),
    /// Initialization Resp
    #[rasn(tag(1))]
    Ip(Box<CertRepMessage>),
    /// Certification Req
    #[rasn(tag(2))]
    Cr(Box<CertReqMessages>),
    /// Certification Resp
    #[rasn(tag(3))]
    Cp(Box<CertRepMessage>),
    /// PKCS #10 Cert.  Req.
    #[rasn(tag(4))]
    P10cr(Box<crate::pkcs10::asn1::CertificationRequest>),
    /// pop Challenge
    #[rasn(tag(5))]
    Popdecc(Box<PopoDecKeyChallContent>),
    /// pop Response
    #[rasn(tag(6))]
    Popdecr(Box<PopoDecKeyRespContent>),
    /// Key Update Request
    #[rasn(tag(7))]
    Kur(Box<CertReqMessages>),
    /// Key Update Response
    #[rasn(tag(8))]
    Kup(Box<CertRepMessage>),
    /// Key Recovery Req
    #[rasn(tag(9))]
    Krr(Box<CertReqMessages>),
    /// Key Recovery Resp
    #[rasn(tag(10))]
    Krp(Box<KeyRecRepContent>),
    /// Revocation Request
    #[rasn(tag(11))]
    Rr(Box<RevReqContent>),
    /// Revocation Response
    #[rasn(tag(12))]
    Rp(Box<RevRepContent>),
    /// Cross-Cert.  Request
    #[rasn(tag(13))]
    Ccr(Box<CertReqMessages>),
    /// Cross-Cert.  Resp
    #[rasn(tag(14))]
    Ccp(Box<CertRepMessage>),
    /// CA Key Update Ann.
    #[rasn(tag(15))]
    Ckuann(Box<CaKeyUpdAnnContent>),
    /// Certificate Ann.
    #[rasn(tag(16))]
    Cann(Box<CertAnnContent>),
    /// Revocation Ann.
    #[rasn(tag(17))]
    Rann(Box<RevAnnContent>),
    /// CRL Announcement
    #[rasn(tag(18))]
    Crlann(Box<CrlAnnContent>),
    /// Confirmation
    ///
    /// ```text
    /// PKIConfirmContent ::= NULL
    /// ```
    #[rasn(tag(19))]
    Pkiconf,
    /// Nested Message
    #[rasn(tag(20))]
    Nested(Box<NestedMessageContent>),
    /// General Message
    #[rasn(tag(21))]
    Genm(Box<GenMsgContent>),
    /// General Response
    #[rasn(tag(22))]
    Genp(Box<GenRepContent>),
    /// Error Message
    #[rasn(tag(23))]
    Error(Box<ErrorMsgContent>),
    /// Certificate confirm
    #[rasn(tag(24))]
    CertConf(Box<CertConfirmContent>),
    /// Polling request
    #[rasn(tag(25))]
    PollReq(Box<PollReqContent>),
    /// Polling response
    #[rasn(tag(26))]
    PollRep(Box<PollRepContent>),
}

/**

[RFC 4210 5.1.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3):

```text
   PKIProtection ::= BIT STRING
```
*/
pub type PkiProtection = BitString;

/**

[RFC 4210 5.1.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3):

```text
   ProtectedPart ::= SEQUENCE {
       header    PKIHeader,
       body      PKIBody
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ProtectedPart {
    pub header: PkiHeader,
    pub body: PkiBody,
}

/**

[RFC 4210 5.1.3.2](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.2):

```text
   DHBMParameter ::= SEQUENCE {
       owf                 AlgorithmIdentifier,
       -- AlgId for a One-Way Function (SHA-1 recommended)
       mac                 AlgorithmIdentifier
       -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
   }   -- or HMAC [RFC2104, RFC2202])

```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct DhbmParameter {
    pub owf: rasn_pkix::AlgorithmIdentifier,
    pub mac: rasn_pkix::AlgorithmIdentifier,
}

/**

[RFC 4210 5.1.3.4](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.4):

```text
   NestedMessageContent ::= PKIMessages
```
*/
pub type NestedMessageContent = PkiMessages;

/**

[RFC 4210 5.2.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.3):

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

/**

[RFC 4210 5.2.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.3):

```text
   PKIStatus ::= INTEGER {
       accepted               (0),
       grantedWithMods        (1),
       rejection              (2),
       waiting                (3),
       revocationWarning      (4),
       revocationNotification (5),
       keyUpdateWarning       (6)
   }
```
*/
pub type PkiStatus = Integer;

/**

[RFC 4210 5.2.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.3):

```text
   PKIFailureInfo ::= BIT STRING {
       badAlg              (0),
       badMessageCheck     (1),
       badRequest          (2),
       badTime             (3),
       badCertId           (4),
       badDataFormat       (5),
       wrongAuthority      (6),
       incorrectData       (7),
       missingTimeStamp    (8),
       badPOP              (9),
       certRevoked         (10),
       certConfirmed       (11),
       wrongIntegrity      (12),
       badRecipientNonce   (13),
       timeNotAvailable    (14),
       unacceptedPolicy    (15),
       unacceptedExtension (16),
       addInfoNotAvailable (17),
       badSenderNonce      (18),
       badCertTemplate     (19),
       signerNotTrusted    (20),
       transactionIdInUse  (21),
       unsupportedVersion  (22),
       notAuthorized       (23),
       systemUnavail       (24),
       systemFailure       (25),
       duplicateCertReq    (26)
   }
```
*/
pub type PkiFailureInfo = BitString;

/**
[RFC 4210 5.2.5](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.5):

```text
   OOBCert ::= Certificate
```
*/
pub type OobCert = rasn_pkix::Certificate;

/**
[RFC 4210 5.2.5](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.5):

```text
   OOBCertHash ::= SEQUENCE {
       hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
       certId      [1] CertId                  OPTIONAL,
       hashVal         BIT STRING
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct OOBCertHash {
    #[rasn(tag(0))]
    pub hash_alg: Option<rasn_pkix::AlgorithmIdentifier>,
    #[rasn(tag(1))]
    pub cert_id: Option<CertId>,
    pub hash_val: BitString,
}

/**
[RFC 4210 5.2.8.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8.3):

```text
   POPODecKeyChallContent ::= SEQUENCE OF Challenge
```
*/
pub type PopoDecKeyChallContent = SequenceOf<Challenge>;

/**
[RFC 4210 5.2.8.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8.3):

```text
   Challenge ::= SEQUENCE {
       owf                 AlgorithmIdentifier  OPTIONAL,
       witness             OCTET STRING,
       challenge           OCTET STRING
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct Challenge {
    pub owf: Option<rasn_pkix::AlgorithmIdentifier>,
    pub witness: OctetString,
    pub challenge: OctetString,
}

/**
[RFC 4210 5.2.8.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8.3):

```text
   POPODecKeyRespContent ::= SEQUENCE OF INTEGER
```
*/
pub type PopoDecKeyRespContent = SequenceOf<Integer>;

/**
[RFC 4210 5.3.4](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.4) and
[RFC 9480 2.9](https://www.rfc-editor.org/rfc/rfc9480#section-2.9):

```text
   CertRepMessage ::= SEQUENCE {
       caPubs          [1] SEQUENCE SIZE (1..MAX) OF Certificate
                           OPTIONAL,
       response            SEQUENCE OF CertResponse
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertRepMessage {
    #[rasn(tag(1))]
    pub ca_pubs: Option<SequenceOf<rasn_pkix::Certificate>>,
    pub response: SequenceOf<CertResponse>,
}

/** Certification Response

[RFC 4210 5.3.4](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.4) and
[RFC 9480 2.9](https://www.rfc-editor.org/rfc/rfc9480#section-2.9):

```text
   CertResponse ::= SEQUENCE {
       certReqId           INTEGER,
       status              PKIStatusInfo,
       certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
       rspInfo             OCTET STRING        OPTIONAL
       -- analogous to the id-regInfo-utf8Pairs string defined
       -- for regInfo in CertReqMsg [RFC4211]
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertResponse {
    pub cert_req_id: Integer,
    pub status: PkiStatusInfo,
    pub certified_key_pair: Option<CertifiedKeyPair>,
    pub rsp_info: Option<OctetString>,
}

/**
[RFC 4210 5.3.4](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.4) and
[RFC 9480 2.9](https://www.rfc-editor.org/rfc/rfc9480#section-2.9):

```text
   CertifiedKeyPair ::= SEQUENCE {
       certOrEncCert       CertOrEncCert,
       -- privateKey      [0] EncryptedValue      OPTIONAL,
       privateKey      [0] EncryptedKey      OPTIONAL,
       -- see [RFC4211] for comment on encoding
       publicationInfo [1] PKIPublicationInfo  OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertifiedKeyPair {
    pub cert_or_enc_cert: CertOrEncCert,
    //#[deprecated]
    //#[rasn(tag(0))]
    //private_key: Option<EncryptedValue>,
    #[rasn(tag(0))]
    private_key: Option<EncryptedKey>,
    #[rasn(tag(1))]
    pub publication_info: Option<PkiPublicationInfo>,
}

/**
[RFC 4210 5.3.4](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.4) and
[RFC 9480 2.9](https://www.rfc-editor.org/rfc/rfc9480#section-2.9):

```text
   CertOrEncCert ::= CHOICE {
       -- certificate     [0] Certificate,
       certificate     [0] CMPCertificate,
       -- encryptedCert   [1] EncryptedValue
       encryptedCert   [1] EncryptedKey
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum CertOrEncCert {
    #[rasn(tag(0))]
    //Certificate(rasn_pkix::Certificate),
    Certificate(Box<CmpCertificate>),
    //#[deprecated]
    //#[rasn(tag(1))]
    //EncryptedCert(EncryptedValue),
    #[rasn(tag(1))]
    EncryptedCert(EncryptedKey),
}

/** Key Recovery Response Content

[RFC 4210 5.3.8](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.8):

```text
   KeyRecRepContent ::= SEQUENCE {
       status          PKIStatusInfo,
       newSigCert  [0] Certificate                   OPTIONAL,
       caCerts     [1] SEQUENCE SIZE (1..MAX) OF
                                    Certificate      OPTIONAL,
       keyPairHist [2] SEQUENCE SIZE (1..MAX) OF
                                    CertifiedKeyPair OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KeyRecRepContent {
    pub status: PkiStatusInfo,
    #[rasn(tag(0))]
    pub new_sig_cert: Option<rasn_pkix::Certificate>,
    #[rasn(tag(1))]
    pub ca_certs: Option<SequenceOf<rasn_pkix::Certificate>>,
    #[rasn(tag(2))]
    pub key_pair_hist: Option<SequenceOf<CertifiedKeyPair>>,
}

/**  Revocation Request Content

[RFC 4210 5.3.9](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.9):

```text
   RevReqContent ::= SEQUENCE OF RevDetails
```
*/
pub type RevReqContent = SequenceOf<RevDetails>;

/** Revocation Request Content details

[RFC 4210 5.3.9](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.9):

```text
   RevDetails ::= SEQUENCE {
       certDetails         CertTemplate,
       crlEntryDetails     Extensions       OPTIONAL
   }

```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct RevDetails {
    pub cert_details: CertTemplate,
    pub crl_entry_details: Option<rasn_pkix::Extensions>,
}

/** Revocation Response Content

[RFC 4210 5.3.10](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.10):

```text
   RevRepContent ::= SEQUENCE {
       status        SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
       revCerts  [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
       crls      [1] SEQUENCE SIZE (1..MAX) OF CertificateList
                     OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct RevRepContent {
    pub status: SequenceOf<PkiStatusInfo>,
    #[rasn(tag(0))]
    pub rev_certs: Option<SequenceOf<CertId>>,
    #[rasn(tag(1))]
    pub crls: Option<SequenceOf<rasn_pkix::CertificateList>>,
}

/** CA Key Update Announcement Content

[RFC 4210 5.3.13](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.13):

```text
   CAKeyUpdAnnContent ::= SEQUENCE {
      oldWithNew         Certificate,
      newWithOld         Certificate,
      newWithNew         Certificate
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CaKeyUpdAnnContent {
    pub old_with_new: rasn_pkix::Certificate,
    pub new_with_old: rasn_pkix::Certificate,
    pub new_with_new: rasn_pkix::Certificate,
}

/** Certificate Announcement

[RFC 4210 5.3.14](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.14):

```text
   CertAnnContent ::= Certificate
```
*/
pub type CertAnnContent = rasn_pkix::Certificate;

/** Revocation Announcement

[RFC 4210 5.3.15](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.15):

```text
   RevAnnContent ::= SEQUENCE {
       status              PKIStatus,
       certId              CertId,
       willBeRevokedAt     GeneralizedTime,
       badSinceDate        GeneralizedTime,
       crlDetails          Extensions  OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct RevAnnContent {
    pub status: PkiStatus,
    pub cert_id: CertId,
    pub will_be_revoked_at: GeneralizedTime,
    pub bad_since_date: GeneralizedTime,
    pub crl_details: Option<rasn_pkix::Extensions>,
}

/** CRL Announcement

[RFC 4210 5.3.16](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.16):

```text
   CRLAnnContent ::= SEQUENCE OF CertificateList
```
*/
pub type CrlAnnContent = SequenceOf<rasn_pkix::CertificateList>;

/** Certificate Confirmation Content

[RFC 4210 5.3.18](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.18) and
[RFC 9480 2.10](https://www.rfc-editor.org/rfc/rfc9480#section-2.10):

```text
   CertConfirmContent ::= SEQUENCE OF CertStatus
```
*/
pub type CertConfirmContent = SequenceOf<CertStatus>;

/**

[RFC 4210 5.3.18](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.18) and
[RFC 9480 2.10](https://www.rfc-editor.org/rfc/rfc9480#section-2.10):

```text
   CertStatus ::= SEQUENCE {
      certHash    OCTET STRING,
      certReqId   INTEGER,
      statusInfo  PKIStatusInfo OPTIONAL
      -- hashAlg is available in CMP version cmp2021(3).
      hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}}
                  OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertStatus {
    pub cert_hash: OctetString,
    pub cert_req_id: Integer,
    pub status_info: Option<PkiStatusInfo>,
    /// This field requires CMP version cmp2021(3).
    #[rasn(tag(0))]
    pub hash_alg: Option<rasn_pkix::AlgorithmIdentifier>,
}

/** PKI General Message Content

[RFC 4210 5.3.19](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.19):

```text
   InfoTypeAndValue ::= SEQUENCE {
       infoType               OBJECT IDENTIFIER,
       infoValue              ANY DEFINED BY infoType  OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct InfoTypeAndValue {
    pub info_type: ObjectIdentifier,
    pub info_value: Option<Any>,
}

/** PKI General Message Content

[RFC 4210 5.3.19](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.19):

```text
   -- where {id-it} = {id-pkix 4} = {1 3 6 1 5 5 7 4}
   GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
```
*/
pub type GenMsgContent = SequenceOf<InfoTypeAndValue>;

/** Root CA Certificate Update (GenMsg)

[RFC 9480 2.15](https://www.rfc-editor.org/rfc/rfc9480#section-2.15):

```text
   RootCaCertValue ::= CMPCertificate
```
*/
pub type RootCaCertValue = CmpCertificate;

/** Root CA Certificate Update (GenRep)

[RFC 9480 2.15](https://www.rfc-editor.org/rfc/rfc9480#section-2.15):

```text
   RootCaKeyUpdateValue ::= RootCaKeyUpdateContent
```
*/
pub type RootCaKeyUpdateValue = RootCaKeyUpdateContent;

/** Root CA Certificate Update (GenRep)

[RFC 9480 2.15](https://www.rfc-editor.org/rfc/rfc9480#section-2.15):

```text
   RootCaKeyUpdateContent ::= SEQUENCE {
      newWithNew       CMPCertificate,
      newWithOld   [0] CMPCertificate OPTIONAL,
      oldWithNew   [1] CMPCertificate OPTIONAL
      }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct RootCaKeyUpdateContent {
    pub new_with_new: CmpCertificate,
    #[rasn(tag(0))]
    pub new_with_old: Option<CmpCertificate>,
    #[rasn(tag(1))]
    pub old_with_new: Option<CmpCertificate>,
}

/** Certificate Request Template (GenRep)

[RFC 9480 2.16](https://www.rfc-editor.org/rfc/rfc9480#section-2.16):

```text
   CertReqTemplateValue  ::= CertReqTemplateContent
```
*/
pub type CertReqTemplateValue = CertReqTemplateContent;

/** Certificate Request Template (GenRep)

[RFC 9480 2.16](https://www.rfc-editor.org/rfc/rfc9480#section-2.16):

```text
   CertReqTemplateContent ::= SEQUENCE {
     certTemplate           CertTemplate,
     keySpec                Controls OPTIONAL }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertReqTemplateContent {
    pub cert_template: CertTemplate,
    pub key_spec: Option<Controls>,
}

/** Certificate Request Template (GenRep)

[RFC 9480 2.16](https://www.rfc-editor.org/rfc/rfc9480#section-2.16):

```text
   Controls  ::= SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue

   id-regCtrl-algId OBJECT IDENTIFIER ::= { iso(1)
      identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) pkip(5) regCtrl(1) 11 }

   AlgIdCtrl ::= AlgorithmIdentifier{ALGORITHM, {...}}
```
*/
pub type AlgIdCtrl = rasn_pkix::AlgorithmIdentifier;

/** Certificate Request Template (GenRep)

[RFC 9480 2.16](https://www.rfc-editor.org/rfc/rfc9480#section-2.16):

```text
   id-regCtrl-rsaKeyLen OBJECT IDENTIFIER ::= { iso(1)
      identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) pkip(5) regCtrl(1) 12 }

   RsaKeyLenCtrl ::= INTEGER (1..MAX)
```
*/
pub type RsaKeyLenCtrl = Integer;

/** CRL Update Retrieval (GenMsg)

[RFC 9480 2.17](https://www.rfc-editor.org/rfc/rfc9480#section-2.17):

```text
   CRLSource ::= CHOICE {
      dpn          [0] DistributionPointName,
      issuer       [1] GeneralNames }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum CrlSource {
    #[rasn(tag(0))]
    Dpn(rasn_pkix::DistributionPointName),
    #[rasn(tag(1))]
    Issuer(rasn_pkix::GeneralNames),
}

/** CRL Update Retrieval (GenMsg)

[RFC 9480 2.17](https://www.rfc-editor.org/rfc/rfc9480#section-2.17):

```text
   CRLStatus ::= SEQUENCE {
      source       CRLSource,
      thisUpdate   Time OPTIONAL }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CrlStatus {
    pub source: CrlSource,
    pub this_update: Option<Time>,
}

/** PKI General Response Content

[RFC 4210 5.3.20](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.20):

```text
   GenRepContent ::= SEQUENCE OF InfoTypeAndValue
```

See also [RFC 4210 5.3.19.x](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.19).
*/
pub type GenRepContent = SequenceOf<InfoTypeAndValue>;

/** Error Message Content

[RFC 4210 5.3.21](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.21):

```text
   ErrorMsgContent ::= SEQUENCE {
       pKIStatusInfo          PKIStatusInfo,
       errorCode              INTEGER           OPTIONAL,
       errorDetails           PKIFreeText       OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ErrorMsgContent {
    pki_status_info: PkiStatusInfo,
    error_code: Option<Integer>,
    error_details: Option<PkiFreeText>,
}

/** Polling Request

[RFC 4210 5.3.22](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.22) and
[RFC 9480 2.19](https://www.rfc-editor.org/rfc/rfc9480#section-2.19):

```text
   PollReqContent ::= SEQUENCE OF SEQUENCE {
       certReqId    INTEGER }
```
*/
pub type PollReqContent = SequenceOf<PollReqContentItem>;

/** Polling Request item

[RFC 4210 5.3.22](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.22) and
[RFC 9480 2.19](https://www.rfc-editor.org/rfc/rfc9480#section-2.19):

```text
   SEQUENCE {
       certReqId    INTEGER }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PollReqContentItem {
    cert_req_id: Integer,
}

/** Polling Response

[RFC 4210 5.3.22](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.22) and
[RFC 9480 2.19](https://www.rfc-editor.org/rfc/rfc9480#section-2.19):

```text
   PollRepContent ::= SEQUENCE OF SEQUENCE {
       certReqId    INTEGER,
       checkAfter   INTEGER,  -- time in seconds
       reason       PKIFreeText OPTIONAL }
```
*/
pub type PollRepContent = SequenceOf<PollRepContentItem>;

/** Polling Response item

[RFC 4210 5.3.22](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.22) and
[RFC 9480 2.19](https://www.rfc-editor.org/rfc/rfc9480#section-2.19):

```text
   SEQUENCE {
       certReqId    INTEGER,
       checkAfter   INTEGER,  -- time in seconds
       reason       PKIFreeText OPTIONAL }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PollRepContentItem {
    cert_req_id: Integer,
    /// Time in seconds
    check_after: Integer,
    reason: Option<PkiFreeText>,
}

/**

[RFC 4210 F](https://www.rfc-editor.org/rfc/rfc4210#appendix-F):

```text
   CMPCertificate ::= CHOICE {
      x509v3PKCert        Certificate
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum CmpCertificate {
    X509v3PKCert(rasn_pkix::Certificate),
}

/**

[RFC 4211 3](https://www.rfc-editor.org/rfc/rfc4211#section-3):

```text
   CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
```
*/
pub type CertReqMessages = SequenceOf<CertReqMsg>;

/**

[RFC 4211 3](https://www.rfc-editor.org/rfc/rfc4211#section-3):

```text
   CertReqMsg ::= SEQUENCE {
      certReq   CertRequest,
      popo       ProofOfPossession  OPTIONAL,
      -- content depends upon key type
      regInfo   SEQUENCE SIZE(1..MAX) of AttributeTypeAndValue OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertReqMsg {
    pub cert_req: CertRequest,
    pub popo: Option<ProofOfPossession>,
    pub reg_info: Option<SequenceOf<AttributeTypeAndValue>>,
}

/**

[RFC 4211 4](https://www.rfc-editor.org/rfc/rfc4211#section-4):

```text
   ProofOfPossession ::= CHOICE {
       raVerified        [0] NULL,
       signature         [1] POPOSigningKey,
       keyEncipherment   [2] POPOPrivKey,
       keyAgreement      [3] POPOPrivKey }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum ProofOfPossession {
    #[rasn(tag(0))]
    RaVerified,
    #[rasn(tag(1))]
    Signature(PopoSigningKey),
    #[rasn(tag(2))]
    KeyEncipherment(PopoPrivKey),
    #[rasn(tag(3))]
    KeyAgreement(PopoPrivKey),
}

/**

[RFC 4211 4.1](https://www.rfc-editor.org/rfc/rfc4211#section-4.1):

```text
   POPOSigningKey ::= SEQUENCE {
       poposkInput         [0] POPOSigningKeyInput OPTIONAL,
       algorithmIdentifier     AlgorithmIdentifier,
       signature               BIT STRING }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PopoSigningKey {
    #[rasn(tag(0))]
    pub poposk_input: Option<PopoSigningKeyInput>,
    pub algorithm_identifier: rasn_pkix::AlgorithmIdentifier,
    pub signature: BitString,
}

/**

[RFC 4210 5.2.8](https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8) and
[RFC 4211 4.1](https://www.rfc-editor.org/rfc/rfc4211#section-4.1):

```text
   POPOSigningKeyInput ::= SEQUENCE {
       authInfo            CHOICE {
           sender              [0] GeneralName,
           -- used only if an authenticated identity has been
           -- established for the sender (e.g., a DN from a
           -- previously-issued and currently-valid certificate)
           publicKeyMAC        PKMACValue },
           -- used if no authenticated GeneralName currently exists for
           -- the sender; publicKeyMAC contains a password-based MAC
           -- on the DER-encoded value of publicKey
       publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PopoSigningKeyInput {
    pub auth_info: PopoSigningKeyInputAuthInfo,
    pub public_key: rasn_pkix::SubjectPublicKeyInfo,
}

/// See [PopoSigningKeyInput].
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PopoSigningKeyInputAuthInfo {
    #[rasn(tag(0))]
    Sender(GeneralName),
    PublicKeyMac(PkmacValue),
}

/**

[RFC 4211 4.1](https://www.rfc-editor.org/rfc/rfc4211#section-4.1):

```text
   PKMACValue ::= SEQUENCE {
      algId  AlgorithmIdentifier,
      value  BIT STRING }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PkmacValue {}

/**

[RFC 4211 4.2](https://www.rfc-editor.org/rfc/rfc4211#section-4.2):

```text
   POPOPrivKey ::= CHOICE {
       thisMessage       [0] BIT STRING,   -- deprecated
       subsequentMessage [1] SubsequentMessage,
       dhMAC             [2] BIT STRING,   -- deprecated
       agreeMAC          [3] PKMACValue,
       encryptedKey      [4] EnvelopedData }
     -- for keyAgreement (only), possession is proven in this message
     -- (which contains a MAC (over the DER-encoded value of the
     -- certReq parameter in CertReqMsg, which must include both subject
     -- and publicKey) based on a key derived from the end entity's
     -- private DH key and the CA's public DH key);
     -- the dhMAC value MUST be calculated as per the directions given
     -- in RFC 2875 for static DH proof-of-possession.
```

[RFC 9480 2.20](https://www.rfc-editor.org/rfc/rfc9480#section-2.20) mandates
CMPv3 when using EnvelopedData.
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PopoPrivKey {
    //#[deprecated(note = "See RFC 4211 4.2.")]
    //#[rasn(tag(0))]
    //ThisMessage(BitString),
    #[rasn(tag(1))]
    SubsequentMessage(SubsequentMessage),
    //#[deprecated(note = "See RFC 4211 4.2.")]
    //#[rasn(tag(2))]
    //DhMac(BitString),
    #[rasn(tag(3))]
    AgreeMac(PkmacValue),
    #[rasn(tag(4))]
    EncryptedKey(EnvelopedData),
}

/**

[RFC 4211 4.2](https://www.rfc-editor.org/rfc/rfc4211#section-4.2):

```text
   SubsequentMessage ::= INTEGER {
       encrCert (0),
       challengeResp (1) }
```
*/
pub type SubsequentMessage = Integer;

/** Private Key Info content type.

[RFC 4211 4.2.1](https://www.rfc-editor.org/rfc/rfc4211#section-4.2.1):

```text
   id-ct-encKeyWithID OBJECT IDENTIFIER ::= {id-ct 21}

   EncKeyWithID ::= SEQUENCE {
     privateKey           PrivateKeyInfo,
     identifier CHOICE {
       string               UTF8String,
       generalName          GeneralName
     } OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncKeyWithId {
    pub private_key: PrivateKeyInfo,
    pub identifier: Option<EncKeyWithIdIdentifier>,
}

/// See [EncKeyWithId].
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum EncKeyWithIdIdentifier {
    String(Utf8String),
    GeneralName(GeneralName),
}

/** Private Key Info content type.

[RFC 4211 4.2.1](https://www.rfc-editor.org/rfc/rfc4211#section-4.2.1):

```text
   PrivateKeyInfo ::= SEQUENCE {
      version                   INTEGER,
      privateKeyAlgorithm       AlgorithmIdentifier,
      privateKey                OCTET STRING,
      attributes                [0] IMPLICIT Attributes OPTIONAL
   }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PrivateKeyInfo {
    pub version: Integer,
    pub private_key_algorithm: rasn_cms::AlgorithmIdentifier,
    pub private_key: OctetString,
    #[rasn(tag(0))]
    pub attributes: Option<SetOf<rasn_cms::Attribute>>,
}

/** Password-Based MAC.

[RFC 4210 5.1.3](https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3):
[RFC 4211 4.2.1](https://www.rfc-editor.org/rfc/rfc4211#section-4.2.1):

```text
   id-PasswordBasedMAC OBJECT IDENTIFIER ::=
                                      { 1 2 840 113533 7 66 13}

   PBMParameter ::= SEQUENCE {
      salt                OCTET STRING,
      owf                 AlgorithmIdentifier,
      iterationCount      INTEGER,
      mac                 AlgorithmIdentifier
      )
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PbmParameter {
    pub salt: OctetString,
    pub owf: rasn_pkix::AlgorithmIdentifier,
    pub iteration_count: Integer,
    pub mac: rasn_pkix::AlgorithmIdentifier,
}

/**

[RFC 4211 5](https://www.rfc-editor.org/rfc/rfc4211#section-5):

```text
   CertRequest ::= SEQUENCE {
      certReqId     INTEGER,        -- ID for matching request and reply
      certTemplate  CertTemplate, --Selected fields of cert to be issued
      controls      Controls OPTIONAL } -- Attributes affecting issuance
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertRequest {
    pub cert_req_id: Integer,
    pub cert_template: CertTemplate,
    pub controls: Option<Controls>,
}

/**

[RFC 4211 5](https://www.rfc-editor.org/rfc/rfc4211#section-5):

```text
   CertTemplate ::= SEQUENCE {
      version      [0] Version               OPTIONAL,
      serialNumber [1] INTEGER               OPTIONAL,
      signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
      issuer       [3] Name                  OPTIONAL,
      validity     [4] OptionalValidity      OPTIONAL,
      subject      [5] Name                  OPTIONAL,
      publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
      issuerUID    [7] UniqueIdentifier      OPTIONAL,
      subjectUID   [8] UniqueIdentifier      OPTIONAL,
      extensions   [9] Extensions            OPTIONAL }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertTemplate {
    #[rasn(tag(0))]
    pub version: Option<Version>,
    #[rasn(tag(1))]
    pub serial_number: Option<Integer>,
    #[rasn(tag(2))]
    pub signing_alg: Option<rasn_pkix::AlgorithmIdentifier>,
    #[rasn(tag(3))]
    pub issuer: Option<rasn_pkix::Name>,
    #[rasn(tag(4))]
    pub validity: Option<OptionalValidity>,
    #[rasn(tag(5))]
    pub subject: Option<rasn_pkix::Name>,
    #[rasn(tag(6))]
    pub public_key: Option<rasn_pkix::SubjectPublicKeyInfo>,
    #[rasn(tag(7))]
    pub issuer_uid: Option<rasn_pkix::UniqueIdentifier>,
    #[rasn(tag(8))]
    pub subject_uid: Option<rasn_pkix::UniqueIdentifier>,
    #[rasn(tag(9))]
    pub extensions: Option<rasn_pkix::Extensions>,
}

pub type Version = Integer;

/**

[RFC 4211 5](https://www.rfc-editor.org/rfc/rfc4211#section-5):

```text
   OptionalValidity ::= SEQUENCE {
      notBefore  [0] Time OPTIONAL,
      notAfter   [1] Time OPTIONAL } --at least one must be present
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct OptionalValidity {
    #[rasn(tag(0))]
    pub not_before: Option<Time>,
    #[rasn(tag(1))]
    pub not_after: Option<Time>,
}

/**

[RFC 4211 5](https://www.rfc-editor.org/rfc/rfc4211#section-5):

```text
   Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }
```
*/
pub type Time = rasn_pkix::Time;

/**

[RFC 4211 6](https://www.rfc-editor.org/rfc/rfc4211#section-6):

```text
   Controls  ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue

```
*/
pub type Controls = SequenceOf<AttributeTypeAndValue>;

/**

[RFC 4211 6.3](https://www.rfc-editor.org/rfc/rfc4211#section-6.3):

```text
   PKIPublicationInfo ::= SEQUENCE {
        action     INTEGER {
                     dontPublish (0),
                     pleasePublish (1) },
        pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PkiPublicationInfo {
    pub action: Integer,
    pub pub_infos: Option<SequenceOf<SinglePubInfo>>,
}

/**

[RFC 4211 6.3](https://www.rfc-editor.org/rfc/rfc4211#section-6.3):

```text
   SinglePubInfo ::= SEQUENCE {
         pubMethod    INTEGER {
             dontCare    (0),
             x500        (1),
             web         (2),
             ldap        (3) },
         pubLocation  GeneralName OPTIONAL }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SinglePubInfo {
    pub_method: Integer,
    pub_location: Option<GeneralName>,
}

/**

[RFC 4211 6.4](https://www.rfc-editor.org/rfc/rfc4211#section-6.4):

```text
   PKIArchiveOptions ::= CHOICE {
      encryptedPrivKey     [0] EncryptedKey,
      -- the actual value of the private key
      keyGenParameters     [1] KeyGenParameters,
      -- parameters which allow the private key to be re-generated
      archiveRemGenPrivKey [2] BOOLEAN }
      -- set to TRUE if sender wishes receiver to archive the private
      -- key of a key pair that the receiver generates in response to
      -- this request; set to FALSE if no archival is desired.
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PkiArchiveOptions {
    #[rasn(tag(0))]
    EncryptedPrivKey(EncryptedKey),
    #[rasn(tag(1))]
    KeyGenParameters(KeyGenParameters),
    #[rasn(tag(2))]
    ArchiveRemGenPrivKey(bool),
}

/**

[RFC 4211 6.4](https://www.rfc-editor.org/rfc/rfc4211#section-6.4) and
[RFC 9480 2.7](https://www.rfc-editor.org/rfc/rfc9480#section-2.7):

```text
   EncryptedKey ::= CHOICE {
      encryptedValue        EncryptedValue, -- deprecated
      envelopedData     [0] EnvelopedData }
      -- The encrypted private key MUST be placed in the envelopedData
      -- encryptedContentInfo encryptedContent OCTET STRING.
```

[RFC 9480 2.20](https://www.rfc-editor.org/rfc/rfc9480#section-2.20) mandates
CMPv3 when using EnvelopedData.
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum EncryptedKey {
    //#[deprecated]
    //EncryptedValue(EncryptedValue),
    #[rasn(tag(0))]
    EnvelopedData(EnvelopedData),
}

/*
/**

[RFC 4211 6.4](https://www.rfc-editor.org/rfc/rfc4211#section-6.4):

```text
   EncryptedValue ::= SEQUENCE {
      intendedAlg   [0] AlgorithmIdentifier  OPTIONAL,
      -- the intended algorithm for which the value will be used
      symmAlg       [1] AlgorithmIdentifier  OPTIONAL,
      -- the symmetric algorithm used to encrypt the value
      encSymmKey    [2] BIT STRING           OPTIONAL,
      -- the (encrypted) symmetric key used to encrypt the value
      keyAlg        [3] AlgorithmIdentifier  OPTIONAL,
      -- algorithm used to encrypt the symmetric key
      valueHint     [4] OCTET STRING         OPTIONAL,
      -- a brief description or identifier of the encValue content
      -- (may be meaningful only to the sending entity, and used only
      -- if EncryptedValue might be re-examined by the sending entity
      -- in the future)
      encValue       BIT STRING }
   -- The use of the EncryptedValue field has been deprecated in favor
   -- of the EnvelopedData structure.
   --
   -- When EncryptedValue is used to carry a private key (as opposed to
   -- a certificate), implementations MUST support the encValue field
   -- containing an encrypted PrivateKeyInfo as defined in [PKCS11],
   -- section 12.11.  If encValue contains some other format/encoding
   -- for the private key, the first octet of valueHint MAY be used
   -- to indicate the format/encoding (but note that the possible values
   -- of this octet are not specified at this time).  In all cases, the
   -- intendedAlg field MUST be used to indicate at least the OID of
   -- the intended algorithm of the private key, unless this information
   -- is known a priori to both sender and receiver by some other means.
```
*/
#[deprecated]
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncryptedValue {
    #[rasn(tag(0))]
    pub intended_alg: Option<rasn_cms::AlgorithmIdentifier>,
    #[rasn(tag(1))]
    pub symm_alg: Option<rasn_cms::AlgorithmIdentifier>,
    #[rasn(tag(2))]
    pub enc_symm_key: Option<BitString>,
    #[rasn(tag(3))]
    pub key_alg: Option<rasn_cms::AlgorithmIdentifier>,
    #[rasn(tag(4))]
    pub value_hint: Option<OctetString>,
    pub enc_value: BitString,
}
*/

/**

[RFC 4211 6.4](https://www.rfc-editor.org/rfc/rfc4211#section-6.4):

```text
   KeyGenParameters ::= OCTET STRING
```
*/
pub type KeyGenParameters = OctetString;

/**

[RFC 4211 6.5](https://www.rfc-editor.org/rfc/rfc4211#section-6.5):

```text
   CertId ::= SEQUENCE {
         issuer           GeneralName,
         serialNumber     INTEGER
     }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CertId {
    pub issuer: GeneralName,
    pub serial_number: Integer,
}
