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

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod cert;
pub mod encdec;
mod named_enum;

use tyst::{encdec::hex::ToHex, Tyst};

/// Create a lower case hex encoded SHA3-512 fingerprint of the `data`.
pub fn fingerprint_data(data: &[u8]) -> String {
    Tyst::instance()
        .digests()
        .by_name("SHA3-512")
        .unwrap()
        .hash(data)
        .to_hex()
}

#[cfg(test)]
pub mod test_utils {
    //! Common testing utilities.

    /// Initialize `env_logger` for testing purposes.
    pub fn init_logger() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            //.filter(Some("rustls"), log::LevelFilter::Info)
            .try_init();
    }
}
