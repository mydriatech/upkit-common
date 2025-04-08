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

//! CRL entry extension InvalidityDate.

/** CRL entry extension InvalidityDate.

[RFC 5280 5.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2):

```text
   Non-critical CRL entry extension that provides the date on which it is known
   or suspected that the private key was compromised or that the certificate
   otherwise became invalid.
```
*/
pub struct InvalidityDate {
    invalidity_date_epoch_seconds: u64,
}

impl InvalidityDate {
    /// joint-iso-itu-t(2) ds(5) certificateExtension(29) invalidityDate(24)
    pub const OID: &[u32] = &[2, 5, 29, 24];

    /// Return the invalidity date in epoch seconds.
    pub fn get_invalidity_date_epoch_seconds(&self) -> u64 {
        self.invalidity_date_epoch_seconds
    }

    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(generalized_time: &rasn_pkix::InvalidityDate) -> Self {
        Self {
            invalidity_date_epoch_seconds: u64::try_from(generalized_time.timestamp()).unwrap(),
        }
    }
}
