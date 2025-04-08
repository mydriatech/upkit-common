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

//! OCSP Single Request.

use super::CertId;

/** OCSP Single Request.

An OCSP request has one SingleRequest for each certificate to get revocation
status for.

[RFC 6960 4.1.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1):

```text
   Request         ::=     SEQUENCE {
       reqCert                     CertID,
       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
```

No `singleRequestExtensions` are defined in RFC 6960.
*/
pub struct SingleRequest {
    req_cert: CertId,
}
impl SingleRequest {
    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(request: &rasn_ocsp::Request) -> Self {
        Self {
            req_cert: CertId::from_rasn_type(&request.req_cert),
        }
    }

    /// Return the identifier for the certificate.
    pub fn get_req_cert(&self) -> &CertId {
        &self.req_cert
    }
}
