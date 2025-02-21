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

//! Distinguished Name.

mod attributes;

pub use self::attributes::Asn1EncodingType;
pub use self::attributes::AttributeTypeAndValueInfo;
pub use self::attributes::WellKnownAttribute;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;

use super::IdentityFragment;
use super::IdentityFragmentError;

/*
TODO?: unsorted or optional sort by LDAP or Inetz order

https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
https://cabforum.org/working-groups/server/baseline-requirements/requirements/#7141-name-encoding
*/

/** Distinguished Name.

A Distinguished Name (DN) can (fully or partially) represent an entity's
identity.

## Common use

In X.509 certificates you will find this as the "main" descriptor for the
identity of Certificate Authorities and an important one for leaf certificates.
Additionally, the `GeneralName`'s `directoryName` can also appear in certificate
extensions.

## Structure

With its roots in Directory Services, it is structured in the following way:

```text
DistinguishedName: [
  RelativeDistinguishedName [
    AttributeTypeAndValue,
  ],
]
```

This structure allows each `RelativeDistinguishedName` to be constructed with
multiple `AttributeTypeAndValue` to ensure relative uniqness ("distinguished").
This is referred to as Multi-valued `RelativeDistinguishedName`.

## Multi-valued RDNs are discouraged

In X.509 Certificates MV RDNs are allowed, but extremely rare in practice.
This implementation supports MV RDNs, but consider them discouraged and higher
level API will not neccessarly expose this functionality.

## Opinionated `String` interpretation as UTF-8

When ever an attribute allow UTF-8 and other encodings, `Utf8String` will be
used. This takes away complexity at the expense of some older systems.

## Reference by name

By referencing well-known attributes by name instead of the enum directly, this
can be extended in the future to (also) load attribute definitions from another
resource.
*/
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DistinguishedName {
    dn: Vec<Vec<IdentityFragment>>,
}

impl TryFrom<Vec<Vec<(String, String)>>> for DistinguishedName {
    type Error = IdentityFragmentError;
    fn try_from(value: Vec<Vec<(String, String)>>) -> Result<Self, Self::Error> {
        Ok(Self {
            dn: value
                .into_iter()
                .map(|rdn| {
                    rdn.into_iter()
                        .map(|value| IdentityFragment::try_from(value).unwrap())
                        .collect()
                })
                .collect(),
        })
    }
}

impl DistinguishedName {
    /// Return a new instance
    pub fn new_unchecked(dn: Vec<Vec<IdentityFragment>>) -> Self {
        Self { dn }
    }

    /// Return a new instance
    pub fn new(dn: Vec<Vec<IdentityFragment>>) -> Result<Self, IdentityFragmentError> {
        dn.iter().for_each(|rdn| {
            rdn.iter()
                .for_each(|idf| WellKnownAttribute::validate(idf).unwrap())
        });
        Ok(Self::new_unchecked(dn))
    }

    /// Return a hash of the ASN.1 DER encoded [DistinguishedName].
    ///
    /// Order of the DN is assumed to be constant.
    pub fn fingerprint(&self) -> String {
        crate::fingerprint_data(&self.to_der())
    }

    /// Return `true` when no attributes are present.
    pub fn is_empty(&self) -> bool {
        self.dn.is_empty() || !self.dn.iter().any(|rdn| !rdn.is_empty())
    }

    /// Return the multi-valued representation
    /// `[RelativeDistinguishedName [AttributeTypeAndValue(name,value)]]`
    pub fn rnds(&self) -> &Vec<Vec<IdentityFragment>> {
        &self.dn
    }

    /// Return a new [Self] from a [rasn_pkix::Name] of well-known attributes.
    pub fn from_rasn_type(name: &rasn_pkix::Name) -> Result<Self, IdentityFragmentError> {
        let dn = match name {
            // Only a single choice exist in RFC5280
            rasn_pkix::Name::RdnSequence(rdns) => rdns
                .iter()
                .map(|rdn| {
                    rdn.to_vec()
                        .into_iter()
                        .map(|atav| WellKnownAttribute::from_rasn_type(atav).unwrap())
                        .collect()
                })
                .collect(),
        };
        Ok(Self::new_unchecked(dn))
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn as_rasn_type(&self) -> Result<rasn_pkix::Name, IdentityFragmentError> {
        Self::to_rasn_type(&self.dn)
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(
        dn: &[Vec<IdentityFragment>],
    ) -> Result<rasn_pkix::Name, IdentityFragmentError> {
        let mut v = vec![];
        for rdn in dn.iter() {
            let mut rdn_sequence_set = rasn::types::SetOf::new();
            for idf in rdn {
                rdn_sequence_set.insert(WellKnownAttribute::to_rasn_type(idf).unwrap());
            }
            v.push(rdn_sequence_set.into());
        }
        Ok(rasn_pkix::Name::RdnSequence(v))
    }

    /// Return the DER encoded version.
    pub fn to_der(&self) -> Vec<u8> {
        rasn::der::encode(&Self::to_rasn_type(&self.dn).unwrap()).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_encode_without_error() {
        DistinguishedName::new(vec![
            vec![WellKnownAttribute::CommonName.with_value("An entity")],
            vec![WellKnownAttribute::JurisdictionCountry.with_value("SE")],
        ])
        .unwrap()
        .as_rasn_type()
        .unwrap();
    }
}
