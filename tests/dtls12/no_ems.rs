//! DTLS 1.2 with a peer that does not support Extended Master Secret
//! (RFC 7627), like the DTLS stack of some SIP desk phones: refused by
//! default, accepted with `require_extended_master_secret(false)`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, Output};

use crate::ossl_helper::{DtlsCertOptions, DtlsEvent, OsslDtlsCert, OsslDtlsImpl};

/// What both sides saw.
#[derive(Default, Debug)]
struct Outcome {
    dimpl_connected: bool,
    ossl_connected: bool,
    dimpl_keying_material: Option<Vec<u8>>,
    ossl_keying_material: Option<Vec<u8>>,
    dimpl_received: Vec<u8>,
    ossl_received: Vec<u8>,
    dimpl_error: Option<String>,
}

fn config(require_ems: bool) -> Arc<Config> {
    Arc::new(
        Config::builder()
            .require_extended_master_secret(require_ems)
            .build()
            .unwrap(),
    )
}

/// A dimpl endpoint (client when `dimpl_client`) against OpenSSL, with or
/// without EMS on the OpenSSL side.
fn handshake(dimpl_client: bool, require_ems: bool, ossl_ems: bool) -> Outcome {
    env_logger::try_init().ok();
    let dimpl_cert = OsslDtlsCert::new(DtlsCertOptions::default());
    let ossl_cert = OsslDtlsCert::new(DtlsCertOptions::default());
    let mut ossl = if ossl_ems {
        OsslDtlsImpl::new(ossl_cert).unwrap()
    } else {
        OsslDtlsImpl::new_without_ems(ossl_cert).unwrap()
    };
    ossl.set_active(!dimpl_client);

    let mut dimpl = Dtls::new_12(
        config(require_ems),
        dimpl::DtlsCertificate {
            certificate: dimpl_cert.x509.to_der().unwrap(),
            private_key: dimpl_cert.pkey.private_key_to_der().unwrap(),
        },
        Instant::now(),
    );
    dimpl.set_active(dimpl_client);

    let mut outcome = Outcome::default();
    let mut events = VecDeque::new();
    let mut buf = vec![0u8; 2048];
    if !dimpl_client {
        ossl.handle_handshake(&mut events).unwrap();
    }
    for _ in 0..40 {
        while let Some(datagram) = ossl.poll_datagram() {
            if let Err(e) = dimpl.handle_packet(&datagram) {
                outcome.dimpl_error = Some(format!("{e:?}"));
                return outcome;
            }
        }
        dimpl.handle_timeout(Instant::now()).unwrap();
        loop {
            match dimpl.poll_output(&mut buf) {
                Output::Packet(data) => {
                    // OpenSSL errors (e.g. an alert) end the exchange.
                    if ossl.handle_receive(data, &mut events).is_err() {
                        return outcome;
                    }
                }
                Output::Connected => outcome.dimpl_connected = true,
                Output::KeyingMaterial(km, _) => {
                    outcome.dimpl_keying_material = Some(km.to_vec());
                    dimpl.send_application_data(b"from dimpl").unwrap();
                }
                Output::ApplicationData(data) => outcome.dimpl_received.extend_from_slice(data),
                Output::Timeout(_) => break,
                _ => {}
            }
        }
        while let Some(event) = events.pop_front() {
            match event {
                DtlsEvent::Connected => outcome.ossl_connected = true,
                DtlsEvent::SrtpKeyingMaterial(km, _) => {
                    outcome.ossl_keying_material = Some(km.to_vec());
                    ossl.handle_input(b"from openssl").unwrap();
                }
                DtlsEvent::Data(data) => outcome.ossl_received.extend_from_slice(&data),
                _ => {}
            }
        }
        if !outcome.dimpl_received.is_empty() && !outcome.ossl_received.is_empty() {
            break;
        }
    }
    outcome
}

fn assert_connected(outcome: &Outcome) {
    assert_eq!(outcome.dimpl_error, None);
    assert!(
        outcome.dimpl_connected && outcome.ossl_connected,
        "{outcome:?}"
    );
    // Same keys on both sides: the master secret was derived the same way.
    assert!(outcome.dimpl_keying_material.is_some());
    assert_eq!(outcome.dimpl_keying_material, outcome.ossl_keying_material);
    assert_eq!(outcome.dimpl_received, b"from openssl");
    assert_eq!(outcome.ossl_received, b"from dimpl");
}

fn assert_refused(outcome: &Outcome) {
    assert!(!outcome.dimpl_connected, "{outcome:?}");
    let error = outcome
        .dimpl_error
        .as_deref()
        .expect("dimpl reports an error");
    assert!(
        error.contains("ExtendedMasterSecretNotNegotiated"),
        "{error}"
    );
}

#[test]
fn client_refuses_a_server_without_ems_by_default() {
    assert_refused(&handshake(true, true, false));
}

#[test]
fn server_refuses_a_client_without_ems_by_default() {
    assert_refused(&handshake(false, true, false));
}

#[test]
fn client_accepts_a_server_without_ems_when_allowed() {
    assert_connected(&handshake(true, false, false));
}

#[test]
fn server_accepts_a_client_without_ems_when_allowed() {
    // OpenSSL aborts on an unsolicited EMS extension, so this also shows
    // that the ServerHello leaves it out.
    assert_connected(&handshake(false, false, false));
}

#[test]
fn ems_is_still_used_when_the_peer_has_it() {
    for dimpl_client in [true, false] {
        assert_connected(&handshake(dimpl_client, false, true));
        assert_connected(&handshake(dimpl_client, true, true));
    }
}
