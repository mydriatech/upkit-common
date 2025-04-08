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

//! X.509 Certificate Private Key Usage Period.

use crate::cert::cert_asn1 as asn1;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

/** Private Key Usage Period.

This extensions was deprecated in
[RFC3280 4.2.1.4](https://www.rfc-editor.org/rfc/rfc3280#section-4.2.1.4) but
this is reverted by
[RFC5280 1](https://www.rfc-editor.org/rfc/rfc5280#section-1).

```text
   -- private key usage period extension OID and syntax

   id-ce-privateKeyUsagePeriod OBJECT IDENTIFIER ::=  { id-ce 16 }

   PrivateKeyUsagePeriod ::= SEQUENCE {
        notBefore       [0]     GeneralizedTime OPTIONAL,
        notAfter        [1]     GeneralizedTime OPTIONAL }
        -- either notBefore or notAfter MUST be present
```

For example
[ETSI EN 319 422 V1.1.1 (2016-03) 6.4](https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf)
states that

```text
    The TSU certificate private key usage period extension should be used in
    order to limit the validity of the TSU's signing key.
```

*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
//#[serde(untagged)]
//#[serde(rename_all = "snake_case")]
pub struct PrivateKeyUsagePeriod {
    not_before_epoch_seconds: Option<u64>,
    not_after_epoch_seconds: Option<u64>,
}

impl PrivateKeyUsagePeriod {
    // joint-iso-ccitt(2) ds(5) ce(29) privateKeyUsagePeriod(16)
    /// Private Key Usage Period object identifier
    pub const OID: &[u32] = &[2, 5, 29, 16];

    /// Return a new instance
    pub fn new(
        not_before_epoch_seconds: Option<u64>,
        not_after_epoch_seconds: Option<u64>,
    ) -> Option<Self> {
        if not_before_epoch_seconds.is_none() && not_after_epoch_seconds.is_none() {
            // "either notBefore or notAfter MUST be present"
            None
        } else {
            Some(Self {
                not_before_epoch_seconds,
                not_after_epoch_seconds,
            })
        }
    }

    /// The private key associated with the certificate SHOULD NOT be used to
    /// sign objects before this point in time.
    pub fn get_not_before(&self) -> Option<u64> {
        self.not_before_epoch_seconds
    }

    /// The private key associated with the certificate SHOULD NOT be used to
    /// sign objects after this point in time.
    pub fn get_not_after(&self) -> Option<u64> {
        self.not_after_epoch_seconds
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self) -> asn1::PrivateKeyUsagePeriod {
        asn1::PrivateKeyUsagePeriod {
            not_before: self
                .not_before_epoch_seconds
                .map(crate::encdec::rasn::to_generalized_time),
            not_after: self
                .not_after_epoch_seconds
                .map(crate::encdec::rasn::to_generalized_time),
        }
    }

    /// Return a Vec of new instances.
    pub fn from_rasn_type(private_key_usage_period: &asn1::PrivateKeyUsagePeriod) -> Self {
        Self {
            not_before_epoch_seconds: private_key_usage_period
                .not_before
                .map(|not_before| u64::try_from(not_before.timestamp()).unwrap()),
            not_after_epoch_seconds: private_key_usage_period
                .not_after
                .map(|not_after| u64::try_from(not_after.timestamp()).unwrap()),
        }
    }
}
