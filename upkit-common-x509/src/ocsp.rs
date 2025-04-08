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

//! Online Certificate Status Protocol (OCSP) utilities.
//!
//! See also:
//!
//! * [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) Online Certificate Status Protocol - OCSP
//! * [RFC 9654](https://www.rfc-editor.org/rfc/rfc9654) Online Certificate Status Protocol (OCSP) Nonce Extension
//! * [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019) The Lightweight OCSP Profile for High-Volume Environments

mod ocsp_asn1;
pub mod parse {
    //! OCSP request and response parsing.
    mod ocsp_parsing_error;
    mod ocsp_request_parser;
    mod ocsp_response_parser;

    pub use ocsp_parsing_error::*;
    pub use ocsp_request_parser::*;
    pub use ocsp_response_parser::*;
}
pub mod response_extensions {
    //! OCSP response extensions.
    mod nonce;

    pub use nonce::*;
}
pub mod types {
    //! OCSP request and response types.
    mod cert_id;
    mod cert_status;
    mod ocsp_response_status;
    mod responder_id;
    mod single_request;
    mod single_response;

    pub use cert_id::*;
    pub use cert_status::*;
    pub use ocsp_response_status::*;
    pub use responder_id::*;
    pub use single_request::*;
    pub use single_response::*;
}
pub mod validate {
    //! OCSP validation.
    mod ocsp_validator;

    pub use ocsp_validator::*;
}
