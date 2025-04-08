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

//! ASN.1 module for [RFC 6211](https://www.rfc-editor.org/rfc/rfc6211).

// TODO: Re-license and contribute upstream.

use rasn::prelude::*;
use rasn::AsnType;
use rasn::Decode;
use rasn::Encode;
use rasn_cms::DigestAlgorithmIdentifier;
use rasn_cms::MessageAuthenticationCodeAlgorithm;
use rasn_cms::SignatureAlgorithmIdentifier;

// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) cmsAlgorithmProtection(52)
//pub const ISO_MEMBER_BODY_US_RSADSI_PKCS9_CMS_ALGORITHM_PROTECTION: &[u32] = &[1, 2, 840, 113549, 1, 9, 52];

/** RFC 6211: CMSAlgorithmProtection

```text

   aa-cmsAlgorithmProtection ATTRIBUTE ::= {
       TYPE CMSAlgorithmProtection
       IDENTIFIED BY { id-aa-CMSAlgorithmProtection }
   }

   id-aa-CMSAlgorithmProtection OBJECT IDENTIFIER ::= { iso(1)
        member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) 52 }

   CMSAlgorithmProtection ::= SEQUENCE {
       digestAlgorithm         DigestAlgorithmIdentifier,
       signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
       macAlgorithm        [2] MessageAuthenticationCodeAlgorithm
                                        OPTIONAL
   }
   (WITH COMPONENTS { signatureAlgorithm PRESENT,
                      macAlgorithm ABSENT } |
    WITH COMPONENTS { signatureAlgorithm ABSENT,
                      macAlgorithm PRESENT })
```
*/
#[allow(missing_docs)]
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CmsAlgorithmProtection {
    pub digest_algorithm: DigestAlgorithmIdentifier,
    #[rasn(tag(1))]
    pub signature_algorithm: Option<SignatureAlgorithmIdentifier>,
    #[rasn(tag(2))]
    pub mac_algorithm: Option<MessageAuthenticationCodeAlgorithm>,
}
