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

//! OCSP Certificate Identifier.

use crate::cert::types::SerialNumber;

/** OCSP request and response CertID

[RFC 6960 4.1.1](https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1):

```text
   CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
       serialNumber        CertificateSerialNumber }
```
*/
#[derive(Clone, PartialEq, Eq)]
pub struct CertId {
    hash_algorithm: Vec<u32>,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial_number: SerialNumber,
}

impl CertId {
    /// Return a new instance from the `rasn` ASN.1 library type.
    pub fn from_rasn_type(cert_id: &rasn_ocsp::CertId) -> Self {
        Self {
            // Bravly ignore hash algo parameters... :/
            hash_algorithm: cert_id.hash_algorithm.algorithm.to_vec(),
            issuer_name_hash: cert_id.issuer_name_hash.to_vec(),
            issuer_key_hash: cert_id.issuer_key_hash.to_vec(),
            serial_number: SerialNumber::from_rasn_type(&cert_id.serial_number),
        }
    }

    /// Return the used message digest algorithm.
    pub fn get_hash_algorithm(&self) -> String {
        tyst::encdec::oid::as_string(&self.hash_algorithm)
    }

    /// Return the message digest of the certificates DER encoded issuer.
    pub fn get_issuer_name_hash(&self) -> &[u8] {
        &self.issuer_name_hash
    }

    /// Return the message digest of the certificates issuer's DER encoded
    /// public key.
    pub fn get_issuer_key_hash(&self) -> &[u8] {
        &self.issuer_key_hash
    }

    /// Return the certificates serial number.
    pub fn get_serial_number(&self) -> &SerialNumber {
        &self.serial_number
    }
}
