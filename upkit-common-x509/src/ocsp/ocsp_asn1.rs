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

//! ASN.1 module for [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960).

// TODO: Re-license and contribute upstream.

use rasn::prelude::*;
use rasn::{AsnType, Decode, Encode};
use rasn_pkix::AlgorithmIdentifier;

/** RFC 6960 4.4.7.1: PreferredSignatureAlgorithms

```text
   PreferredSignatureAlgorithms ::= SEQUENCE OF
                                    PreferredSignatureAlgorithm
```
*/
pub type PreferredSignatureAlgorithms = SequenceOf<PreferredSignatureAlgorithm>;

/** RFC 6960 4.4.7.1: PreferredSignatureAlgorithm

```text
   PreferredSignatureAlgorithm ::= SEQUENCE {
      sigIdentifier        AlgorithmIdentifier,
      pubKeyAlgIdentifier  SMIMECapability OPTIONAL
      }
```
*/
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreferredSignatureAlgorithm {
    pub sig_identifier: AlgorithmIdentifier,
    pub pub_key_alg_identifier: Option<rasn_smime::Capability>,
}
