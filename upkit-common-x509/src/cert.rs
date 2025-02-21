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

//! X.509 Certificate utilities.

pub mod build;
pub mod extensions;
pub mod parse;
pub mod validate;
pub mod types {
    //! X.509 Certificate types.

    mod distinguished_name;
    mod general_name;
    mod identity_fragment;
    mod serial_number;
    mod validity;

    pub use self::distinguished_name::*;
    pub use self::general_name::general_name_as_string;
    pub use self::general_name::WellKnownGeneralName;
    pub use self::identity_fragment::*;
    pub use self::serial_number::SerialNumber;
    pub use self::validity::Validity;
}
