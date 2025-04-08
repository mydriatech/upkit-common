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

//! Time-Stamp Protocol (TSP) utilities.
//!
//! See also:
//!
//! * [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) Time-Stamp Protocol (TSP)
//! * [RFC 3628](https://www.rfc-editor.org/rfc/rfc3628) Policy Requirements for Time-Stamping Authorities (TSAs)
//! * [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816) ESSCertIDv2 Update for RFC 3161 (allow non-SHA1)
//! * [crate::cms] Cryptographic Message Syntax (CMS) utilities.
//!
//! Additional context:
//! * [RFC 5126](https://www.rfc-editor.org/rfc/rfc5126) CMS Advanced Electronic Signatures (CAdES)

pub mod build {
    //! Time-Stamp Protocol (TSP) building.
    mod time_stamp_req;
    mod time_stamp_resp;
    mod tst_signer;

    pub use self::time_stamp_req::*;
    pub use self::time_stamp_resp::*;
    pub use self::tst_signer::*;
}
pub mod parse {
    //! Time-Stamp Protocol (TSP) parsing.
    mod time_stamp_request_parser;
    mod time_stamp_response_parser;
    mod ts_parsing_error;

    pub use self::time_stamp_request_parser::*;
    pub use self::time_stamp_response_parser::*;
    pub use self::ts_parsing_error::*;
}
mod tsp_asn1;
pub mod types {
    //! X.509 Time-Stamp Protocol (TSP) types.
    mod pki_status;
    mod time_stamp_token;
    mod tst_info;

    pub use self::pki_status::*;
    pub use self::time_stamp_token::*;
    pub use self::tst_info::*;
}
pub mod validate {
    //! X.509 Time-Stamp Protocol (TSP) validation.
    mod tsr_validator;

    pub use tsr_validator::*;
}
