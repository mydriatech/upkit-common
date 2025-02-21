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

//! Common markers from [RFC7468 4](https://datatracker.ietf.org/doc/html/rfc7468#section-4)

/// See [RFC7468 4](https://datatracker.ietf.org/doc/html/rfc7468#section-4).
pub enum Marker {
    /// Data is of ASN.1 Type RFC5280 Certificate.
    Certificate,
    /// Data is of ASN.1 Type RFC5280 CertificateList.
    CertificateRevocationList,
    /// Data is of ASN.1 Type RFC2986 CertificationRequest.
    CertificationRequest,
    /// Data is of ASN.1 Type RFC5652 ContentInfo.
    CryptographicMessageSyntax,
    /// Data is of ASN.1 Type RFC5208 PrivateKeyInfo or RFC5958 OneAsymmetricKey.
    PrivateKey,
    /// Data is of ASN.1 Type RFC5958 EncryptedPrivateKeyInfo.
    EncryptedPrivateKey,
    /// Data is of ASN.1 Type RFC5755 AttributeCertificate.
    AttributeCertificate,
    /// Data is of ASN.1 Type RFC5280 SubjectPublicKeyInfo.
    PublicKey,
    /// A non-standard marker
    Custom(String),
}

impl Marker {
    /// Start of  `BEGIN` line
    pub const BEGIN_LINE_START: &str = "-----BEGIN ";
    /// End of  `BEGIN` line
    pub const BEGIN_LINE_FINISH: &str = "-----";
    /// Start of  `END` line
    pub const END_LINE_START: &str = "-----END ";
    /// End of  `END` line
    pub const END_LINE_FINISH: &str = Self::BEGIN_LINE_FINISH;

    /// Return the `&str` represenation of the enum
    pub fn as_str(&self) -> &str {
        match self {
            Self::Certificate => "CERTIFICATE",
            Self::CertificateRevocationList => "X509 CRL",
            Self::CertificationRequest => "CERTIFICATE REQUEST",
            Self::CryptographicMessageSyntax => "CMS",
            Self::PrivateKey => "PRIVATE KEY",
            Self::EncryptedPrivateKey => "ENCRYPTED PRIVATE KEY",
            Self::AttributeCertificate => "ATTRIBUTE CERTIFICATE",
            Self::PublicKey => "PUBLIC KEY",
            Self::Custom(marker) => marker.as_str(),
        }
    }

    /// Return a new instance from a PEM complete begin line
    pub fn from_begin_line(begin_line: &str) -> Self {
        match begin_line
            .split_at(begin_line.len() - Self::BEGIN_LINE_FINISH.len())
            .0
            .split_at(Self::BEGIN_LINE_START.len())
            .1
        {
            "CERTIFICATE" => Self::Certificate,
            "X509 CRL" => Self::CertificateRevocationList,
            "CERTIFICATE REQUEST" => Self::CertificationRequest,
            "CMS" => Self::CryptographicMessageSyntax,
            "PRIVATE KEY" => Self::PrivateKey,
            "ENCRYPTED PRIVATE KEY" => Self::EncryptedPrivateKey,
            "ATTRIBUTE CERTIFICATE" => Self::AttributeCertificate,
            "PUBLIC KEY" => Self::PublicKey,
            unknown_marker => Self::Custom(unknown_marker.to_string()),
        }
    }
}
