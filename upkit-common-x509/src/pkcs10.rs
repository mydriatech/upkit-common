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

//! PKCS #10: Certification Request Syntax Specification v1.7.

pub mod build {
    //! PKCS #10: Certification Request Syntax build.
    mod pkcs10_build;

    #[allow(unused_imports)]
    pub use pkcs10_build::*;
}

pub mod parse {
    //! PKCS #10: Certification Request Syntax parser.
    mod pkcs10_parser;
    mod pkcs10_parsing_error;

    pub use pkcs10_parser::*;
    pub use pkcs10_parsing_error::*;
}

pub mod types {
    //! PKCS #10: Certification Request Syntax parser.
    mod pkcs10_attributes;

    #[allow(unused_imports)]
    pub use pkcs10_attributes::*;
}

mod pkcs10_asn1;
