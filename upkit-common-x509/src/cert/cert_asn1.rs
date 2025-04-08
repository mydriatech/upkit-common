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

//! ASN.1 module for [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).

// TODO: Re-license and contribute upstream.

use rasn::prelude::*;
use rasn::AsnType;
use rasn::Decode;
use rasn::Encode;

/** PrivateKeyUsagePeriod

[RFC 5280 A.2](https://www.rfc-editor.org/rfc/rfc5280#appendix-A.2):

```text
   -- private key usage period extension OID and syntax

   id-ce-privateKeyUsagePeriod OBJECT IDENTIFIER ::=  { id-ce 16 }

   PrivateKeyUsagePeriod ::= SEQUENCE {
        notBefore       [0]     GeneralizedTime OPTIONAL,
        notAfter        [1]     GeneralizedTime OPTIONAL }
        -- either notBefore or notAfter MUST be present
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivateKeyUsagePeriod {
    #[rasn(tag(0))]
    pub not_before: Option<GeneralizedTime>,
    #[rasn(tag(1))]
    pub not_after: Option<GeneralizedTime>,
}
