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

//! Certificate Management Protocol (CMP) utilities.
//!
//! CMPv2:
//!
//! * [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) Certificate Management Protocol (CMP)
//! * [RFC 4211](https://www.rfc-editor.org/rfc/rfc4211) Certificate Request Message Format (CRMF)
//! * [RFC 6712](https://www.rfc-editor.org/rfc/rfc6712) HTTP Transfer for the Certificate Management Protocol (CMP)
//!
//! CMPv3:
//!
//! * [RFC 9480](https://www.rfc-editor.org/rfc/rfc9480) Certificate Management Protocol (CMP) Updates
//! * [RFC 9481](https://www.rfc-editor.org/rfc/rfc9481) Certificate Management Protocol (CMP) Algorithms
//! * [RFC 9483](https://www.rfc-editor.org/rfc/rfc9483) Lightweight Certificate Management Protocol (CMP) Profile
//!
//! In progress:
//!
//! * [draft-ietf-lamps-rfc6712bis-10](https://www.ietf.org/archive/id/draft-ietf-lamps-rfc6712bis-10.html) HTTP Transfer for the Certificate Management Protocol (CMP)
//! * [draft-ietf-lamps-rfc4210bis-18](https://www.ietf.org/archive/id/draft-ietf-lamps-rfc4210bis-18.html) Certificate Management Protocol (CMP)

#[allow(dead_code)]
pub(crate) mod cmp_asn1;

#[allow(unused_imports)]
pub(crate) use cmp_asn1 as asn1;

pub mod build {
    //! Certificate Management Protocol (CMP) builders.

    mod pki_message;

    pub use self::pki_message::*;
}

pub mod error {
    //! Certificate Management Protocol (CMP) processing errors.

    mod cmp_processing_error;

    pub use self::cmp_processing_error::*;
}

pub mod types {
    //! Certificate Management Protocol (CMP) types.

    mod error_msg_content;
    mod initialization_request;
    mod initialization_response;
    mod pki_body;
    mod pki_status;

    pub use self::error_msg_content::*;
    pub use self::initialization_request::*;
    pub use self::initialization_response::*;
    pub use self::pki_body::*;
    pub use self::pki_status::*;
}
