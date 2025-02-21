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

//! Distinguished Name attributes.

use crate::cert::types::IdentityFragment;
use crate::cert::types::IdentityFragmentError;
use crate::cert::types::IdentityFragmentErrorKind;
use crate::named_enum::NamedEnum;
use crossbeam_skiplist::SkipMap;
use rasn::prelude::Utf8String;
use rasn::types::Any;
use rasn::types::Ia5String;
use rasn::types::ObjectIdentifier;
use rasn::types::PrintableString;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;
use std::sync::LazyLock;
use strum::EnumIter;

struct AttributeLookup {
    atavi_by_name: SkipMap<String, AttributeTypeAndValueInfo>,
    name_by_oid: SkipMap<Vec<u32>, String>,
}

impl AttributeLookup {
    pub fn new() -> Self {
        let atavi_by_name = SkipMap::default();
        let name_by_oid = SkipMap::default();
        // TODO: Load all these from file instead?
        for (name, atavi) in WellKnownAttribute::attributes_common()
            .into_iter()
            .chain(WellKnownAttribute::attributes_extended_validation())
        {
            name_by_oid.insert(atavi.oid.to_vec(), name.to_owned());
            atavi_by_name.insert(name, atavi);
        }
        Self {
            atavi_by_name,
            name_by_oid,
        }
    }

    fn by_name(&self, name: &str) -> Option<AttributeTypeAndValueInfo> {
        self.atavi_by_name
            .get(name)
            .map(|entry| entry.value().clone())
    }

    fn by_oid(&self, oid: &[u32]) -> Result<String, IdentityFragmentError> {
        self.name_by_oid
            .get(oid)
            .map(|entry| entry.value().to_owned())
            .ok_or_else(|| {
                IdentityFragmentErrorKind::UnknownAttribute
                    .error_with_msg(&format!("'{oid:?}' is not a known attribute."))
            })
    }
}

#[doc(hidden)]
static INSTANCE_NAMED_ENUM: LazyLock<NamedEnum<WellKnownAttribute>> =
    LazyLock::new(NamedEnum::default);

#[doc(hidden)]
static INSTANCE_ATTRIBUTE_METADATA: LazyLock<AttributeLookup> = LazyLock::new(AttributeLookup::new);

/// Preferred encoding of an [WellKnownAttribute].
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum Asn1EncodingType {
    /// ASN.1 IA5String
    IA5String,
    /// ASN.1 PrintableString
    PrintableString,
    /// ASN.1 Utf8String
    Utf8String,
}

/// Meta data about an [WellKnownAttribute].
#[derive(Debug, Clone)]
pub struct AttributeTypeAndValueInfo {
    /// Attribute object identifier.
    pub oid: &'static [u32],
    /// Preferred encoding of attributes value.
    pub encoding: Asn1EncodingType,
    /// Maximum number of chars in the attribute value's preferred encoding.
    pub max_char_len: usize,
}

/*
Rec. ITU-T X.520 (10/2019):
    https://www.itu.int/rec/T-REC-X.520-201910-I/en

CA/Browser Forum EV Guidelines:
    https://cabforum.org/working-groups/server/extended-validation/guidelines/

RFC4519 Lightweight Directory Access Protocol (LDAP)
    https://www.rfc-editor.org/rfc/rfc4519
*/

/// Well-known Distinguished Name attributes.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Ord, PartialOrd, EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum WellKnownAttribute {
    /// Serial number
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.9:
    ///
    /// "An identifier or the serial number of an object."
    ///
    /// Implementation of RFC5280 MUST tolerate certs with this attribute.
    ///
    /// CA/Browser Forum EV Guidelines 7.1.4.2.5:
    ///
    /// "Registration (or similar) Number assigned to the Subject by the
    /// Incorporating or Registration Agency in its Jurisdiction."
    SerialNumber,
    /// Domain Component (RFC3490 puny coded)
    ///
    /// RFC4519 2.4:
    ///
    /// "Holding one component, a label, of a DNS domain name."
    ///
    /// Implementation of RFC5280 MUST tolerate certs with this attribute.
    DomainComponent,
    /// Country in ISO 3166-1 alpha-2 format (2 chars upper-case).
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.3.1:
    ///
    /// "A country. When used as a component of a directory name, it identifies
    /// the country in which the named object is physically located or with
    /// which it is associated in some other important way.
    ///
    /// Country name is a string chosen from ISO 3166-1 alpha-2."
    ///
    /// Implementation of RFC5280 MUST tolerate certs with this attribute.
    CountryName,
    /// Part of country.
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.3.5:
    ///
    /// "Identifies a geographical subdivision in which the named object is
    /// physically located or with which it is associated in some other
    /// important way."
    ///
    /// Implementation of RFC5280 MUST tolerate certs with this attribute.
    StateOrProvinceName,
    /// City or similar area.
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.4:
    ///
    /// "Identifies a geographical area or locality in which the named object is
    /// physically located or with which it is associated in some other
    /// important way."
    ///
    /// Implementation of RFC5280 SHOULD tolerate certs with this attribute.
    LocalityName,
    /// Postal code.
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.6.2:
    ///
    /// "The postal code of the named object. It will be part of the object's
    /// postal addres part of the object's postal address."
    PostalCode,
    /// Address tied to the entity.
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.6:
    ///
    /// "Site for the local distribution and physical delivery in a postal
    /// address, i.e., the street name, place, avenue and house number."
    StreetAddress,
    /// Orginization
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.4.1:
    ///
    /// "Identifies an organization with which the named object is affiliated."
    ///
    /// Implementation of RFC5280 MUST tolerate certs with this attribute.
    OrganizationName,
    /// Last name
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.3:
    ///
    /// "The linguistic construct which normally is inherited by an individual
    /// from the individual's parent or assumed by marriage, and by which the
    /// individual is commonly known."
    ///
    /// Implementation of RFC5280 SHOULD tolerate certs with this attribute.
    Surname,
    /// First name
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.4:
    ///
    /// "The linguistic construct which is normally given to an individual by
    /// the individual's parent, or is chosen by the individual, or by which the
    /// individual is commonly known"
    ///
    /// Implementation of RFC5280 SHOULD tolerate certs with this attribute.
    GivenName,
    /// Orginizational Unit Name
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.4.2:
    ///
    /// "Part of an organization designated by an organizationName attribute."
    ///
    /// Implementation of RFC5280 MUST tolerate certs with this attribute.
    OrganizationalUnitName,
    /// What the entity is called in the context where the cert is used.
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.2:
    ///
    /// "A (possibly ambiguous) name by which the object is commonly known in
    /// some limited scope (such as an organization) and conforms to the naming
    /// conventions of the country or culture with which it is associated."
    ///
    /// CA/Browser Forum EV Guidelines 7.1.4.2.2:
    ///
    /// "Deprecated (Discouraged, but not prohibited)"
    ///
    /// Implementation of RFC5280 MUST tolerate certs with this attribute.
    CommonName,
    /*
    /// Qualifier to avoid collision in directory services.
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.8:
    ///
    /// "Disambiguating information to add to the relative distinguished name of
    /// an entry."
    ///
    /// Implementation of RFC5280 MUST tolerate certs with this attribute.
    DistinguishedNameQualifier
    /// Organizational title.
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.4.3:
    ///
    /// "Specifies the designated position or function of the object within an
    /// organization."
    ///
    /// Implementation of RFC5280 SHOULD tolerate certs with this attribute.
    Title
    /// Initials of individual
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.4.5:
    ///
    /// "The initials of some or all of an individual's names, but not the
    /// surname(s)."
    ///
    /// Implementation of RFC5280 SHOULD tolerate certs with this attribute.
    Initials
    /// Pseudonym
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.10:
    ///
    /// "A pseudonym for an object. It is used for naming an object when it is
    /// to be made clear that its name is a pseudonym."
    ///
    /// Implementation of RFC5280 SHOULD tolerate certs with this attribute.
    Psuedonym
    /// "Jr." or "II"
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.6:
    ///
    /// "A string which is used to provide generation information to qualify an
    /// individual's name."
    ///
    /// Implementation of RFC5280 SHOULD tolerate certs with this attribute.
    GenerationQualifier
    */
    // Extended Validation (note that SerialNumber is also defined in this scope)
    /// Business Category
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.2.5:
    ///
    /// "Information concerning the occupation of some common objects, e.g.,
    /// people."
    ///
    /// CA/Browser Forum EV Guidelines 7.1.4.2.3:
    ///
    /// "MUST contain one of the following strings: 'Private Organization',
    /// 'Government Entity', 'Business Entity', or 'Non-Commercial Entity'"
    BusinessCategory,
    /// Jurisdiction of Incorporation or Registration Country
    ///
    /// CA/Browser Forum EV Guidelines 7.1.4.2.4:
    ///
    /// "These fields MUST NOT contain information that is not relevant to the
    /// level of the Incorporating Agency or Registration Agency."
    /// "Country information MUST be specified using the applicable ISO country
    /// code."
    JurisdictionCountry,
    /// Jurisdiction of Incorporation or Registration State or Province.
    ///
    /// CA/Browser Forum EV Guidelines 7.1.4.2.4:
    ///
    /// "These fields MUST NOT contain information that is not relevant to the
    /// level of the Incorporating Agency or Registration Agency."
    JurisdictionStateOrProvince,
    /// Jurisdiction of Incorporation or Registration State or Province.
    ///
    /// CA/Browser Forum EV Guidelines 7.1.4.2.4:
    ///
    /// "These fields MUST NOT contain information that is not relevant to the
    /// level of the Incorporating Agency or Registration Agency."
    JurisdictionLocality,
    /// Unique organization identifier
    ///
    /// Rec. ITU-T X.520 (10/2019) 6.4.4:
    ///
    /// "Identification of an organization different from the organization name."
    ///
    /// CA/Browser Forum EV Guidelines 7.1.4.2.8:
    ///
    /// "Registration Reference for a Legal Entity assigned in accordance to the
    /// identified Registration Scheme."
    ///
    /// Example: `VATDE-123456789`
    OrganizationIdentifier,
}

impl WellKnownAttribute {
    /// Convert to a recognizable label
    pub fn as_name(&self) -> String {
        std::ops::Deref::deref(&INSTANCE_NAMED_ENUM).to_name(self)
    }

    /// Convert from a recognizable label
    pub fn by_name(name: &str) -> Result<Self, IdentityFragmentError> {
        std::ops::Deref::deref(&INSTANCE_NAMED_ENUM)
            .by_name(name)
            .ok_or(
                IdentityFragmentErrorKind::UnknownAttribute
                    .error_with_msg(&format!("'{name}' is not a known attribute.")),
            )
    }

    /// Convert from a recognizable label
    pub fn by_oid(oid: &[u32]) -> Result<Self, IdentityFragmentError> {
        let name = std::ops::Deref::deref(&INSTANCE_ATTRIBUTE_METADATA)
            .by_oid(oid)
            .unwrap();
        Self::by_name(&name)
    }

    /// Turn this attribute into an [IdentityFragment] with the specified value.
    pub fn with_value(&self, value: &str) -> IdentityFragment {
        IdentityFragment::new_unchecked(&self.as_name(), value)
    }

    /// Return [AttributeTypeAndValueInfo] for a [WellKnownAttribute].
    pub fn meta_data_by_name(
        name: &str,
    ) -> Result<AttributeTypeAndValueInfo, IdentityFragmentError> {
        std::ops::Deref::deref(&INSTANCE_ATTRIBUTE_METADATA)
            .by_name(name)
            .ok_or(
                IdentityFragmentErrorKind::UnknownAttribute
                    .error_with_msg(&format!("'{name}' is not a known attribute.")),
            )
    }

    /// Check that the `value` is well-formed for the attribute named `name`.
    ///
    /// This check has no concept of the meaning of the `value`.
    pub fn validate(idf: &IdentityFragment) -> Result<(), IdentityFragmentError> {
        let atavi = Self::meta_data_by_name(&idf.name).unwrap();
        // Check for invalid chars and length
        let len = match atavi.encoding {
            Asn1EncodingType::IA5String => {
                rasn::types::Ia5String::from_iso646_bytes(idf.value.as_bytes())
                    .map_err(|e| {
                        IdentityFragmentErrorKind::InvalidAttributeValue.error_with_msg(&format!(
                            "Attribute '{}' has invalid value '{}': {e:?}",
                            idf.name, idf.value,
                        ))
                    })
                    .unwrap()
                    .len()
            }
            Asn1EncodingType::PrintableString => {
                rasn::types::PrintableString::from_bytes(idf.value.as_bytes())
                    .map_err(|e| {
                        IdentityFragmentErrorKind::InvalidAttributeValue.error_with_msg(&format!(
                            "Attribute '{}' has invalid value '{}': {e:?}",
                            idf.name, idf.value,
                        ))
                    })
                    .unwrap()
                    .len()
            }
            Asn1EncodingType::Utf8String => idf.value.len(),
        };
        if len > atavi.max_char_len {
            return Err(
                IdentityFragmentErrorKind::InvalidAttributeValue.error_with_msg(&format!(
                    "Attribute '{}' has value '{}' that exceeds {} chars as {:?}.",
                    idf.name, idf.value, atavi.max_char_len, atavi.encoding
                )),
            );
        }
        Ok(())
    }

    /// Return a new [IdentityFragment] from the
    /// [rasn_pkix::AttributeTypeAndValue] if it is of a well known type.
    pub fn from_rasn_type(
        atav: &rasn_pkix::AttributeTypeAndValue,
    ) -> Result<IdentityFragment, IdentityFragmentError> {
        let oid = atav.r#type.to_vec();
        let attribute = Self::by_oid(&oid)?;
        let name = attribute.as_name();
        let value = atav.value.as_bytes();
        let value_as_string = match Self::meta_data_by_name(&name).unwrap().encoding {
            Asn1EncodingType::IA5String => rasn::der::decode::<Ia5String>(value)
                .map_err(|e| {
                    IdentityFragmentErrorKind::DecodingFailure.error_with_msg(&format!(
                        "Failed to decode IA5String for attribute '{name}': {e:?}"
                    ))
                })
                .unwrap()
                .to_string(),
            Asn1EncodingType::PrintableString => String::from_utf8(
                rasn::der::decode::<PrintableString>(value)
                    .map_err(|e| {
                        IdentityFragmentErrorKind::DecodingFailure.error_with_msg(&format!(
                            "Failed to decode PrintableString for attribute '{name}': {e:?}"
                        ))
                    })
                    .unwrap()
                    .to_vec(),
            )
            .unwrap(),
            Asn1EncodingType::Utf8String => {
                let res = rasn::der::decode::<Utf8String>(value);
                match res {
                    Ok(v) => v,
                    Err(e1) => {
                        String::from_utf8(
                        rasn::der::decode::<PrintableString>(value)
                            .map_err(|e2| {
                                IdentityFragmentErrorKind::DecodingFailure.error_with_msg(&format!(
                                    "Failed to decode Utf8String for attribute '{name}'. Even PrintableString decoding failed.: {e1:?} {e2:?}"
                                ))
                            })
                            .unwrap()
                            .to_vec()
                        ).unwrap()
                    }
                }
            }
        };
        Ok(IdentityFragment::new_unchecked(&name, &value_as_string))
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(
        idf: &IdentityFragment,
    ) -> Result<rasn_pkix::AttributeTypeAndValue, IdentityFragmentError> {
        let atavi = Self::meta_data_by_name(&idf.name).unwrap();
        let encoded_value = match atavi.encoding {
            Asn1EncodingType::IA5String => rasn::der::encode(
                &Ia5String::try_from(idf.value.to_owned())
                    .map_err(|e| {
                        IdentityFragmentErrorKind::InvalidAttributeValue.error_with_msg(&format!(
                            "Attribute '{}' has invalid value '{}': {e:?}",
                            idf.name, idf.value,
                        ))
                    })
                    .unwrap(),
            ),
            Asn1EncodingType::PrintableString => rasn::der::encode(
                &PrintableString::try_from(idf.value.to_owned())
                    .map_err(|e| {
                        IdentityFragmentErrorKind::InvalidAttributeValue.error_with_msg(&format!(
                            "Attribute '{}' has invalid value '{}': {e:?}",
                            idf.name, idf.value,
                        ))
                    })
                    .unwrap(),
            ),
            Asn1EncodingType::Utf8String => rasn::der::encode(&idf.value),
        }
        .map_err(|e| {
            IdentityFragmentErrorKind::EncodingFailure.error_with_msg(&format!(
                "Encoding of attribute '{}' with value '{}' failed: {e:?}",
                idf.name, idf.value,
            ))
        })
        .unwrap();
        Ok(rasn_pkix::AttributeTypeAndValue {
            r#type: ObjectIdentifier::new_unchecked(atavi.oid.into()),
            value: Any::new(encoded_value),
        })
    }

    fn attributes_common() -> Vec<(String, AttributeTypeAndValueInfo)> {
        vec![
            // RFC 5280
            (
                Self::SerialNumber.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 5],
                    encoding: Asn1EncodingType::PrintableString,
                    max_char_len: 64,
                },
            ),
            // RFC 4519
            (
                Self::DomainComponent.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[0, 9, 2342, 19200300, 100, 1, 25],
                    encoding: Asn1EncodingType::IA5String,
                    max_char_len: 63,
                },
            ),
            // RFC 5280
            (
                Self::CountryName.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 6],
                    encoding: Asn1EncodingType::PrintableString,
                    max_char_len: 2,
                },
            ),
            // RFC 5280
            (
                Self::StateOrProvinceName.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 8],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 128,
                },
            ),
            // RFC 5280
            (
                Self::LocalityName.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 7],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 128,
                },
            ),
            // X.520
            (
                Self::PostalCode.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 17],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 40,
                },
            ),
            // X.520
            (
                Self::StreetAddress.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 9],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 128,
                },
            ),
            // RFC 5280
            (
                Self::OrganizationName.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 10],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 64,
                },
            ),
            // RFC 5280
            (
                Self::Surname.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 4],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 64,
                },
            ),
            // RFC 5280
            (
                Self::GivenName.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 42],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 64,
                },
            ),
            // RFC 5280
            (
                Self::OrganizationalUnitName.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 11],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 64,
                },
            ),
            // RFC 5280
            (
                Self::CommonName.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 3],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 64,
                },
            ),
        ]
    }

    fn attributes_extended_validation() -> Vec<(String, AttributeTypeAndValueInfo)> {
        vec![
            // X.520
            (
                Self::BusinessCategory.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 15],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 128,
                },
            ),
            // Guidelines for the Issuance and Management of EV Certificates
            (
                Self::JurisdictionCountry.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3],
                    encoding: Asn1EncodingType::PrintableString,
                    max_char_len: 2,
                },
            ),
            // Guidelines for the Issuance and Management of EV Certificates
            (
                Self::JurisdictionStateOrProvince.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 128,
                },
            ),
            // Guidelines for the Issuance and Management of EV Certificates
            (
                Self::JurisdictionLocality.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: 128,
                },
            ),
            // X.520
            (
                Self::OrganizationIdentifier.as_name(),
                AttributeTypeAndValueInfo {
                    oid: &[2, 5, 4, 97],
                    encoding: Asn1EncodingType::Utf8String,
                    max_char_len: usize::MAX,
                },
            ),
        ]
    }
}
