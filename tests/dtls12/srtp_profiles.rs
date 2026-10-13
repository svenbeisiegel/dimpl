//! The configured SRTP protection profiles (`ConfigBuilder::srtp_profiles`):
//! a client offers only those, a server picks by its own order.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, ConfigError, Dtls, DtlsCertificate, Error, SrtpProfile};

use crate::common::{deliver_packets, drain_outputs};
use crate::ossl_helper::{DtlsCertOptions, OsslDtlsCert};

use SrtpProfile::{AEAD_AES_128_GCM, AEAD_AES_256_GCM, AES128_CM_SHA1_80};

#[derive(Clone, Copy, Debug)]
enum Version {
    Dtls12,
    Dtls13,
}

fn certificate() -> DtlsCertificate {
    let cert = OsslDtlsCert::new(DtlsCertOptions::default());
    DtlsCertificate {
        certificate: cert.x509.to_der().unwrap(),
        private_key: cert.pkey.private_key_to_der().unwrap(),
    }
}

fn config(profiles: Option<&[SrtpProfile]>) -> Arc<Config> {
    let builder = Config::builder();
    let builder = match profiles {
        Some(profiles) => builder.srtp_profiles(profiles),
        None => builder,
    };
    Arc::new(builder.build().expect("config"))
}

/// The profile each side reports once both are connected (`None` without
/// keying material).
fn negotiate(
    version: Version,
    client_profiles: Option<&[SrtpProfile]>,
    server_profiles: Option<&[SrtpProfile]>,
) -> (Option<SrtpProfile>, Option<SrtpProfile>) {
    let mut now = Instant::now();
    let new = |config, now| match version {
        Version::Dtls12 => Dtls::new_12(config, certificate(), now),
        Version::Dtls13 => Dtls::new_13(config, certificate(), now),
    };
    let mut client = new(config(client_profiles), now);
    client.set_active(true);
    let mut server = new(config(server_profiles), now);
    server.set_active(false);

    let (mut client_connected, mut server_connected) = (false, false);
    let (mut client_profile, mut server_profile) = (None, None);
    for _ in 0..60 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);
        client_connected |= client_out.connected;
        server_connected |= server_out.connected;
        client_profile = client_profile.or(client_out.keying_material.map(|(_, p)| p));
        server_profile = server_profile.or(server_out.keying_material.map(|(_, p)| p));
        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);
        if client_connected && server_connected {
            return (client_profile, server_profile);
        }
        now += Duration::from_millis(50);
    }
    panic!("{version:?} handshake did not complete");
}

#[test]
fn default_profiles_prefer_aes256_gcm() {
    for version in [Version::Dtls12, Version::Dtls13] {
        let profiles = negotiate(version, None, None);
        assert_eq!(
            profiles,
            (Some(AEAD_AES_256_GCM), Some(AEAD_AES_256_GCM)),
            "{version:?}"
        );
    }
}

#[test]
fn server_picks_by_its_configured_order() {
    for version in [Version::Dtls12, Version::Dtls13] {
        let server = [AES128_CM_SHA1_80, AEAD_AES_128_GCM];
        let profiles = negotiate(version, None, Some(&server));
        assert_eq!(
            profiles,
            (Some(AES128_CM_SHA1_80), Some(AES128_CM_SHA1_80)),
            "{version:?}"
        );
    }
}

#[test]
fn client_offers_only_its_configured_profiles() {
    for version in [Version::Dtls12, Version::Dtls13] {
        let client = [AEAD_AES_128_GCM];
        let profiles = negotiate(version, Some(&client), None);
        assert_eq!(
            profiles,
            (Some(AEAD_AES_128_GCM), Some(AEAD_AES_128_GCM)),
            "{version:?}"
        );
    }
}

#[test]
fn no_common_profile_gives_no_keying_material() {
    let client = [AES128_CM_SHA1_80];
    let server = [AEAD_AES_256_GCM];
    let profiles = negotiate(Version::Dtls12, Some(&client), Some(&server));
    assert_eq!(profiles, (None, None));
}

#[test]
fn an_empty_profile_list_is_a_config_error() {
    let result = Config::builder().srtp_profiles(&[]).build();
    assert!(
        matches!(result, Err(Error::ConfigError(ConfigError::NoSrtpProfiles))),
        "{result:?}"
    );
    // Duplicates are ignored.
    let config = Config::builder()
        .srtp_profiles(&[AEAD_AES_128_GCM, AEAD_AES_128_GCM, AES128_CM_SHA1_80])
        .build()
        .unwrap();
    assert_eq!(
        config.srtp_profiles(),
        [AEAD_AES_128_GCM, AES128_CM_SHA1_80]
    );
}
