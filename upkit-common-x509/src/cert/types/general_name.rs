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

//! X.509 Certificate well-known GeneralNames.

use crate::named_enum::NamedEnum;
use rasn::types::Ia5String;
use rasn::types::ObjectIdentifier;
use rasn::types::OctetString;
use rasn_pkix::GeneralName;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;
use std::net::IpAddr;
use std::sync::LazyLock;
use strum::EnumIter;

#[doc(hidden)]
static NAMED_ENUM: LazyLock<NamedEnum<WellKnownGeneralName>> = LazyLock::new(NamedEnum::default);

/*
GeneralName ::= CHOICE {
     otherName                       [0]     OtherName,
     rfc822Name                      [1]     IA5String,
     dNSName                         [2]     IA5String,
     x400Address                     [3]     ORAddress,
     directoryName                   [4]     Name,
     ediPartyName                    [5]     EDIPartyName,
     uniformResourceIdentifier       [6]     IA5String,
     iPAddress                       [7]     OCTET STRING,
     registeredID                    [8]     OBJECT IDENTIFIER }

OtherName ::= SEQUENCE {
     type-id    OBJECT IDENTIFIER,
     value      [0] EXPLICIT ANY DEFINED BY type-id }

EDIPartyName ::= SEQUENCE {
     nameAssigner            [0]     DirectoryString OPTIONAL,
     partyName               [1]     DirectoryString }


Some random OtherNames that might be of interest:
    * RFC 4683 Subject Identification Method (SIM)
    * UPN 1.3.6.1.4.1.311.20.2.3
    * XmppAddr 1.3.6.1.5.5.7.8.5
    * SrvName 1.3.6.1.5.5.7.8.7
    * permanentIdentifier 1.3.6.1.5.5.7.8.3
    * GUID 1.3.6.1.4.1.311.25.1
    * KRB5PrincipalName 1.3.6.1.5.2.2
    * fascN=<FIPS 201-2 PIV FASC-N> 2.16.840.1.101.3.6.6
    * SmtpUTF8Mailbox https://datatracker.ietf.org/doc/html/rfc9598
*/

/// Well-known GeneralName types.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Ord, PartialOrd, EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum WellKnownGeneralName {
    /// `rfc822_name`: Internet mail address in Mailbox format.
    Rfc822Name,
    /// `dns_name`: Domain name system label
    DnsName,
    /// `uri`: Fully qualified Uniform Resource Identifier (URI).
    Uri,
    /// `ip_address`: IPv4 or IPv6 address
    IpAddress,
    /// `registered_id`: Registered Identifier
    RegisteredId,
    //OtherNameUpn,
    //OtherNameGuid,
}
impl WellKnownGeneralName {
    /// Convert to a recognizable label
    pub fn as_name(&self) -> String {
        std::ops::Deref::deref(&NAMED_ENUM).to_name(self)
    }

    /// Convert from a recognizable label
    pub fn by_name(name: &str) -> Option<Self> {
        std::ops::Deref::deref(&NAMED_ENUM).by_name(name)
    }

    /// Return a new instance from the [GeneralName] if it is of a well known type.
    #[allow(clippy::match_single_binding)]
    pub fn from_rasn_type(general_name: &GeneralName) -> Option<(Self, String)> {
        match general_name {
            GeneralName::OtherName(other_name) => {
                let o = other_name.type_id.to_vec();
                let _v = &other_name.value;
                match o {
                    // TODO
                    _unknown_oid => None,
                }
            }
            GeneralName::Rfc822Name(rfc822_name) => Some(Self::to_rfc822_name(rfc822_name)),
            GeneralName::DnsName(dns_name) => Some(Self::to_dns_name(dns_name)),
            GeneralName::X400Address(_) => None,
            // TODO
            GeneralName::DirectoryName(_distinguished_name) => todo!(),
            GeneralName::EdiPartyName(_) => None,
            GeneralName::Uri(uri) => Some(Self::to_uri(uri)),
            GeneralName::IpAddress(ip_address) => Some(Self::to_ip_address(ip_address)),
            GeneralName::RegisteredId(oid) => Some(Self::to_registrered_id(oid)),
        }
    }

    fn to_rfc822_name(rfc822_name: &Ia5String) -> (Self, String) {
        let rfc822_name = rfc822_name.to_string();
        let parts = rfc822_name.split('@').collect::<Vec<_>>();
        if parts.len() != 2 {
            panic!()
        }
        let local = parts.first().unwrap();
        let domain = parts.get(1).unwrap();
        let domain_utf8 = crate::encdec::puny_code::decode(domain);
        let rfc822_name = format!("{local}@{domain_utf8}");
        (WellKnownGeneralName::Rfc822Name, rfc822_name)
    }

    fn to_dns_name(dns_name: &Ia5String) -> (Self, String) {
        let dns_name_utf8 = crate::encdec::puny_code::decode(dns_name.to_string().as_str());
        (WellKnownGeneralName::DnsName, dns_name_utf8)
    }

    fn to_uri(uri: &Ia5String) -> (Self, String) {
        (WellKnownGeneralName::Uri, uri.to_string())
    }

    fn to_ip_address(ip_address: &OctetString) -> (Self, String) {
        (
            WellKnownGeneralName::IpAddress,
            match ip_address.len() {
                4 => {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(&ip_address[0..4]);
                    IpAddr::from(bytes).to_string()
                }
                16 => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&ip_address[0..16]);
                    IpAddr::from(bytes).to_string()
                }
                _ => panic!(),
            },
        )
    }

    fn to_registrered_id(oid: &ObjectIdentifier) -> (Self, String) {
        (
            WellKnownGeneralName::RegisteredId,
            crate::encdec::oid::as_string(oid),
        )
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(&self, value: &str) -> GeneralName {
        match self {
            Self::Rfc822Name => Self::as_rfc822_name(value),
            Self::DnsName => Self::as_dns_name(value),
            Self::Uri => Self::as_uri(value),
            Self::IpAddress => Self::as_ip_address(value),
            Self::RegisteredId => Self::as_registrered_id(value),
        }
    }

    fn as_rfc822_name(rfc822_name: &str) -> GeneralName {
        let parts = rfc822_name.split('@').collect::<Vec<_>>();
        if parts.len() != 2 {
            panic!()
        }
        let local = parts.first().unwrap();
        let domain = parts.get(1).unwrap();
        let domain_punycode = crate::encdec::puny_code::encode(domain);
        let rfc822_name = format!("{local}@{domain_punycode}");
        GeneralName::Rfc822Name(Ia5String::try_from(rfc822_name).unwrap())
    }

    fn as_dns_name(dns_name_utf8: &str) -> GeneralName {
        let dns_name_punycode = crate::encdec::puny_code::encode(dns_name_utf8);
        GeneralName::DnsName(Ia5String::try_from(dns_name_punycode).unwrap())
    }

    fn as_uri(uri: &str) -> GeneralName {
        GeneralName::Uri(Ia5String::try_from(uri).unwrap())
    }

    fn as_ip_address(ip_address: &str) -> GeneralName {
        let octets = match ip_address.parse() {
            // 4 octets
            Ok(IpAddr::V4(ipv4)) => ipv4.octets().to_vec(),
            // 16 octets
            Ok(IpAddr::V6(ipv6)) => ipv6.octets().to_vec(),
            _ => panic!(),
        };
        GeneralName::IpAddress(octets.into())
    }

    fn as_registrered_id(oid: &str) -> GeneralName {
        let oid = crate::encdec::oid::from_string(oid).unwrap();
        GeneralName::RegisteredId(ObjectIdentifier::new(oid).unwrap())
    }
}

/// Return the String representation of the [GeneralName] type if it is well-known.
pub fn general_name_as_string(general_name: &rasn_pkix::GeneralName) -> Option<String> {
    WellKnownGeneralName::from_rasn_type(general_name).map(|(wkgn, _)| wkgn.as_name())
}
