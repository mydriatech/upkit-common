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

//! X.509 Extended Key Usage extension.

use crossbeam_skiplist::SkipMap;
use rasn::types::ObjectIdentifier;
use rasn::types::SequenceOf;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;
use std::ops::Deref;
use std::sync::LazyLock;

#[doc(hidden)]
#[derive(Default)]
struct ExtendedKeyUsageLookup {
    oid_by_enum: SkipMap<ExtendedKeyUsage, &'static [u32]>,
    enum_by_oid: SkipMap<&'static [u32], ExtendedKeyUsage>,
}

#[doc(hidden)]
static INSTANCE: LazyLock<ExtendedKeyUsageLookup> = LazyLock::new(|| {
    // TODO: Load all these from file instead?
    let ret = ExtendedKeyUsageLookup::default();
    [
        // RFC 5280
        (
            ExtendedKeyUsage::AnyExtendedKeyUsage,
            [2, 5, 29, 37, 0].as_slice(),
        ),
        // RFC 4556
        (
            ExtendedKeyUsage::PkinitClientAuth,
            &[1, 3, 6, 1, 5, 2, 3, 4],
        ),
        (
            ExtendedKeyUsage::PkinitKeyDistributionCenter,
            &[1, 3, 6, 1, 5, 2, 3, 5],
        ),
        // RFC 5280
        (
            ExtendedKeyUsage::PkixServerAuth,
            &[1, 3, 6, 1, 5, 5, 7, 3, 1],
        ),
        (
            ExtendedKeyUsage::PkixClientAuth,
            &[1, 3, 6, 1, 5, 5, 7, 3, 2],
        ),
        (
            ExtendedKeyUsage::PkixCodeSigning,
            &[1, 3, 6, 1, 5, 5, 7, 3, 3],
        ),
        (
            ExtendedKeyUsage::PkixEmailProtection,
            &[1, 3, 6, 1, 5, 5, 7, 3, 4],
        ),
        (
            ExtendedKeyUsage::PkixTimeStamping,
            &[1, 3, 6, 1, 5, 5, 7, 3, 8],
        ),
        (
            ExtendedKeyUsage::PkixOcspSigning,
            &[1, 3, 6, 1, 5, 5, 7, 3, 9],
        ),
        // RFC 4334
        (
            ExtendedKeyUsage::PkixEapOverPpp,
            &[1, 3, 6, 1, 5, 5, 7, 3, 13],
        ),
        (
            ExtendedKeyUsage::PkixEapOverLan,
            &[1, 3, 6, 1, 5, 5, 7, 3, 14],
        ),
        // RFC 5055
        (
            ExtendedKeyUsage::PkixScvpServer,
            &[1, 3, 6, 1, 5, 5, 7, 3, 15],
        ),
        (
            ExtendedKeyUsage::PkixScvpClient,
            &[1, 3, 6, 1, 5, 5, 7, 3, 16],
        ),
        // RFC 4945
        (
            ExtendedKeyUsage::PkixIpsecIke,
            &[1, 3, 6, 1, 5, 5, 7, 3, 17],
        ),
        // RFC 5924
        (
            ExtendedKeyUsage::PkixSipDomain,
            &[1, 3, 6, 1, 5, 5, 7, 3, 20],
        ),
        // RFC 6187
        (
            ExtendedKeyUsage::PkixSecureShellClient,
            &[1, 3, 6, 1, 5, 5, 7, 3, 21],
        ),
        (
            ExtendedKeyUsage::PkixSecureShellServer,
            &[1, 3, 6, 1, 5, 5, 7, 3, 22],
        ),
        // RFC 9336
        (
            ExtendedKeyUsage::PkixDocumentSigning,
            &[1, 3, 6, 1, 5, 5, 7, 3, 36],
        ),
        // ETSI
        (ExtendedKeyUsage::EtsiTlsSigning, &[0, 4, 0, 2231, 3, 0]),
        // ICAO
        (
            ExtendedKeyUsage::IcaoCscaMasterListSigningKey,
            &[2, 23, 136, 1, 1, 3],
        ),
        (
            ExtendedKeyUsage::IcaoDeviationListSigningKey,
            &[2, 23, 136, 1, 1, 8],
        ),
        // NIST
        (
            ExtendedKeyUsage::NistPivCardAuth,
            &[2, 16, 840, 1, 101, 3, 6, 8],
        ),
        // Microsoft
        (
            ExtendedKeyUsage::MsIndividualCodeSigning,
            &[1, 3, 6, 1, 4, 1, 311, 2, 1, 21],
        ),
        (
            ExtendedKeyUsage::MsCommercialCodeSigning,
            &[1, 3, 6, 1, 4, 1, 311, 2, 1, 22],
        ),
        (
            ExtendedKeyUsage::MsEncryptedFileSystem,
            &[1, 3, 6, 1, 4, 1, 311, 10, 3, 4],
        ),
        (
            ExtendedKeyUsage::MsEncryptedFileSystemRecovery,
            &[1, 3, 6, 1, 4, 1, 311, 10, 3, 4, 1],
        ),
        (
            ExtendedKeyUsage::MsDocumentSigning,
            &[1, 3, 6, 1, 4, 1, 311, 10, 3, 12],
        ),
        (
            ExtendedKeyUsage::MsSmartCardLogon,
            &[1, 3, 6, 1, 4, 1, 311, 20, 2, 2],
        ),
        (
            ExtendedKeyUsage::MsKeyExchangeCertificate,
            &[1, 3, 6, 1, 4, 1, 311, 21, 5],
        ),
        // Intel
        (
            ExtendedKeyUsage::IntelAmt,
            &[2, 16, 840, 1, 113741, 1, 2, 3],
        ),
        // Adobe
        (
            ExtendedKeyUsage::AdobeAuthenticDocumentsTrust,
            &[1, 2, 840, 113583, 1, 1, 5],
        ),
    ]
    .into_iter()
    .for_each(|(eku, oid)| {
        ret.oid_by_enum.insert(eku.clone(), oid);
        ret.enum_by_oid.insert(oid, eku);
    });
    ret
});

#[doc(hidden)]
fn instance() -> &'static ExtendedKeyUsageLookup {
    INSTANCE.deref()
}

/** Common Extended Key Usages.

See [RFC5280 4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12).
 */
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ExtendedKeyUsage {
    // joint-iso-itu-t(2) ds(5) certificateExtension(29) extKeyUsage(37) anyExtendedKeyUsage(0)
    // iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) kp(3)
    // See also https://zakird.com/2012/12/09/microsoft-oids
    /// RFC 5280 `2.5.29.37.0` `anyExtendedKeyUsage`
    AnyExtendedKeyUsage,
    /// RFC 4556 `1.3.6.1.5.2.3.4` `id-pkinit-KPClientAuth`
    PkinitClientAuth,
    /// RFC 4556 `1.3.6.1.5.2.3.5` `id-pkinit-KPKdc`
    PkinitKeyDistributionCenter,
    /// RFC 5280 `1.3.6.1.5.5.7.3.1` `id-kp-serverAuth`
    PkixServerAuth,
    /// RFC 5280 `1.3.6.1.5.5.7.3.2` `id-kp-clientAuth`
    PkixClientAuth,
    /// RFC 5280 `1.3.6.1.5.5.7.3.3` `id-kp-codeSigning`
    PkixCodeSigning,
    /// RFC 5280 `1.3.6.1.5.5.7.3.4` `id-kp-emailProtection`
    PkixEmailProtection,
    /// RFC 5280 `1.3.6.1.5.5.7.3.8` `id-kp-timeStamping`
    PkixTimeStamping,
    /// RFC 5280 `1.3.6.1.5.5.7.3.9` `id-kp-OCSPSigning`
    PkixOcspSigning,
    /// RFC 4334 `1.3.6.1.5.5.7.3.13` `id-kp-eapOverPPP`
    PkixEapOverPpp,
    /// RFC 4334 `1.3.6.1.5.5.7.3.14` `id-kp-eapOverLAN`
    PkixEapOverLan,
    /// RFC 5055 `1.3.6.1.5.5.7.3.15` `id-kp-scvpServer`
    PkixScvpServer,
    /// RFC 5055 `1.3.6.1.5.5.7.3.16` `id-kp-scvpClient`
    PkixScvpClient,
    /// RFC 4945 `1.3.6.1.5.5.7.3.17` `id-kp-ipsecIKE`
    PkixIpsecIke,
    /// RFC 5924 `1.3.6.1.5.5.7.3.20` `id-kp-sipDomain`
    PkixSipDomain,
    /// RFC 6187 `1.3.6.1.5.5.7.3.21` `id-kp-secureShellClient`
    PkixSecureShellClient,
    /// RFC 6187 `1.3.6.1.5.5.7.3.22` `id-kp-secureShellServer`
    PkixSecureShellServer,
    /// RFC 9336 `1.3.6.1.5.5.7.3.36` `id-kp-documentSigning`
    PkixDocumentSigning,
    /// ETSI TS 102 231 TSL Signing `0.4.0.2231.3.0` `id-tsl-kp-tslSigning`
    EtsiTlsSigning,
    /// ICAO MRTD `2.23.136.1.1.3` `cscaMasterListSigningKey`
    IcaoCscaMasterListSigningKey,
    /// ICAO MRTD `2.23.136.1.1.8` `deviationListSigningKey`
    IcaoDeviationListSigningKey,
    /// NIST PIV-I `2.16.840.1.101.3.6.8` `id-PIV-cardAuth`
    NistPivCardAuth,
    /* Only make this generally available is someone actually asks for it...
    /// CSN 36 9791 TSL Client `1.2.203.7064.1.1.369791.1` `id-csn-369791-tls-client`
    CsnTlsClient,
    /// CSN 36 9791 TSL Server `1.2.203.7064.1.1.369791.2` `id-csn-369791-tls-server`
    CsnTlsServer,
    */
    /// Microsoft `1.3.6.1.4.1.311.2.1.21` `SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID`
    MsIndividualCodeSigning,
    /// Microsoft `1.3.6.1.4.1.311.2.1.22` `SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID`
    MsCommercialCodeSigning,
    /// Microsoft `1.3.6.1.4.1.311.10.3.4` `szOID_EFS_CRYPTO`
    MsEncryptedFileSystem,
    /// Microsoft `1.3.6.1.4.1.311.10.3.4.1` `szOID_EFS_RECOVERY`
    MsEncryptedFileSystemRecovery,
    /// Microsoft `1.3.6.1.4.1.311.10.3.12` `szOID_KP_DOCUMENT_SIGNING`
    MsDocumentSigning,
    /// Microsoft `1.3.6.1.4.1.311.20.2.2` `szOID_KP_SMARTCARD_LOGON`
    MsSmartCardLogon,
    /// Microsoft `1.3.6.1.4.1.311.21.5` `szOID_KP_CA_EXCHANGE`
    MsKeyExchangeCertificate,
    /// Intel AMT `2.16.840.1.113741.1.2.3`
    IntelAmt,
    /// Adobe Authentic Documents Trust (PDF signing) `1.2.840.113583.1.1.5`
    AdobeAuthenticDocumentsTrust,
    /// Unknown EKU with OID
    Custom {
        /// Object identifier
        oid: Vec<u32>,
    },
}
impl ExtendedKeyUsage {
    /// joint-iso-ccitt(2) ds(5) ce(29) extKeyUsage (37)
    pub const OID: &[u32] = &[2, 5, 29, 37];

    /// Return the corresponding OID
    pub fn value(&self) -> &'static [u32] {
        instance()
            .oid_by_enum
            .get(self)
            .map(|entry| *entry.value())
            .unwrap()
    }

    /// Return [ExtendedKeyUsage] from the provided OID.
    pub fn from_oid(oid: &[u32]) -> Self {
        instance()
            .enum_by_oid
            .get(oid)
            .map(|entry| entry.value().clone())
            .unwrap_or_else(|| ExtendedKeyUsage::Custom { oid: oid.to_vec() })
    }

    /// Return value in a form that is easy to process by the ASN.1 library `rasn`.
    pub fn to_rasn_type(ekus: &[ExtendedKeyUsage]) -> SequenceOf<ObjectIdentifier> {
        ekus.iter()
            .map(|eku| eku.value().into())
            .map(ObjectIdentifier::new_unchecked)
            .collect::<Vec<_>>()
    }
}
