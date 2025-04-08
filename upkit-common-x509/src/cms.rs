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

//! Cryptographic Message Syntax (CMS) utilities.
//!
//! See also:
//!
//! * [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) Cryptographic Message Syntax (CMS)
//! * [RFC 2634](https://www.rfc-editor.org/rfc/rfc2634) Enhanced Security Services for S/MIME
//! * [RFC 5035](https://www.rfc-editor.org/rfc/rfc5035) ESS Update: Adding CertID Algorithm Agility
//! * [RFC 8933](https://www.rfc-editor.org/rfc/rfc8933) Update to the CMS for Algorithm Identifier Protection
//! * [RFC 6211](https://www.rfc-editor.org/rfc/rfc6211) CMS Algorithm Identifier Protection Attribute

pub mod cms_asn1;
pub mod types {
    //! Cryptographic Message Syntax (CMS) types.

    pub mod signed_attributes;

    pub use self::signed_attributes::SignedAttributes;
}
