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

//! X.509 Certificate Revocation List (CRL) utilities.

pub mod crl_entry_extensions;
pub mod crl_extensions;
pub mod parse {
    //! X.509 Certificate Revocation List (CRL) parser.
    mod crl_parser;
    mod parsing_error;

    pub use crl_parser::*;
    pub use parsing_error::*;
}
pub mod validate {
    //! X.509 Certificate Revocation List (CRL) validation.
    mod crl_validator;

    pub use crl_validator::*;
}
