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

//! PKCS#10 extension request attribute.

use crate::cert::{
    extensions::{AlternativeName, ExtendedKeyUsage},
    types::WellKnownGeneralName,
};

/** PKCS#10 extension request attribute.

[RFC 2985 5.4.2](https://www.rfc-editor.org/rfc/rfc2985.html#section-5):

May be used to carry information about certificate extensions the requester
wishes to be included in a certificate.

```text
   extensionRequest ATTRIBUTE ::= {
           WITH SYNTAX ExtensionRequest
           SINGLE VALUE TRUE
           ID pkcs-9-at-extensionRequest
   }

   ExtensionRequest ::= Extensions
```

The Microsoft
[szOID_CERT_EXTENSIONS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/c4f9baf0-f4a6-4977-adb8-4c1454747167)
attribute can also be parsed using [ExtensionRequestAttribute].

*/
pub struct ExtensionRequestAttribute {
    extensions: rasn_pkix::Extensions,
}

impl ExtensionRequestAttribute {
    /// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) extensionRequest(14)
    pub const OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 14];

    /// iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 311 2 1 szOID-CERT-EXTENSIONS(14)
    pub const OID_MS_CERT_EXTENSIONS: &[u32] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 14];

    /// Return a new instance.
    pub fn new(extensions: &crate::cert::extensions::Extensions) -> Option<Self> {
        extensions
            .to_rasn_type()
            .map(|extensions| Self { extensions })
    }

    fn first_extension_by_oid(&self, oid: &[u32]) -> Option<rasn_pkix::Extension> {
        crate::encdec::rasn::first_extension_by_oid(&self.extensions, oid)
    }

    /// Return the all [ExtendedKeyUsage]s if present.
    pub fn get_extended_key_usage(&self) -> Vec<ExtendedKeyUsage> {
        self.first_extension_by_oid(ExtendedKeyUsage::OID)
            .map(ExtendedKeyUsage::from_rasn_extension)
            .unwrap_or_default()
    }

    /// Return the all [WellKnownGeneralName] if present.
    pub fn get_subject_alternative_name(&self) -> Vec<(WellKnownGeneralName, String)> {
        self.first_extension_by_oid(AlternativeName::OID_SUBJECT_AN)
            .map(AlternativeName::from_rasn_extension)
            .unwrap_or_default()
    }

    /// Return a new instance from the DER encoded attribute value.
    pub fn from_encoded(der_encoded: &[u8]) -> Option<Self> {
        rasn::der::decode::<rasn_pkix::Extensions>(der_encoded)
            .map_err(|e| {
                log::debug!("Failed to decode PKCS#10 attribute 'extensionRequest': {e:?}")
            })
            .map(|extensions| Self { extensions })
            .ok()
    }

    /// Return the DER encoded attribute value.
    pub fn to_encoded(&self) -> Vec<u8> {
        rasn::der::encode(&self.extensions).unwrap()
    }
}
