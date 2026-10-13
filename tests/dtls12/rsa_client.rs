//! DTLS 1.2 server against an OpenSSL client with an RSA certificate.
//!
//! A SIP endpoint that takes the DTLS client role (`a=setup:active`) may
//! authenticate with an RSA certificate. The dimpl server keeps its ECDSA
//! certificate and verifies the client's CertificateVerify with RSA PKCS#1.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, Output, SrtpProfile};

use crate::ossl_helper::{DtlsCertOptions, DtlsEvent, DtlsPKeyType, OsslDtlsCert};

/// What a dimpl server saw from an OpenSSL client.
#[derive(Default)]
struct Outcome {
    client_connected: bool,
    server_connected: bool,
    client_profile: Option<SrtpProfile>,
    server_profile: Option<SrtpProfile>,
    client_received: Vec<u8>,
    server_received: Vec<u8>,
    server_saw_peer_cert: bool,
    server_error: Option<String>,
}

#[test]
fn dtls12_server_with_rsa2048_client() {
    let outcome = handshake_with_rsa_client(DtlsPKeyType::Rsa2048, false);
    assert_connected(&outcome);
}

#[test]
fn dtls12_server_with_rsa1536_client() {
    let outcome = handshake_with_rsa_client(DtlsPKeyType::Rsa1536, false);
    assert_connected(&outcome);
}

#[test]
fn dtls12_server_rejects_tampered_rsa_certificate_verify() {
    let outcome = handshake_with_rsa_client(DtlsPKeyType::Rsa2048, true);
    assert!(
        !outcome.server_connected,
        "a forged signature must not connect"
    );
    let error = outcome.server_error.expect("the server reports an error");
    assert!(
        error.contains("RsaSignatureVerificationFailed"),
        "unexpected error: {error}"
    );
}

#[test]
fn dtls12_server_rejects_rsa_client_keys_under_1024_bits() {
    let outcome = handshake_with_rsa_client(DtlsPKeyType::Rsa768, false);
    assert!(!outcome.server_connected, "a 768-bit key must not connect");
    let error = outcome.server_error.expect("the server reports an error");
    assert!(
        error.contains("UnsupportedRsaVerification"),
        "unexpected error: {error}"
    );
}

fn assert_connected(outcome: &Outcome) {
    assert_eq!(outcome.server_error, None);
    assert!(
        outcome.server_saw_peer_cert,
        "server should report the peer certificate"
    );
    assert!(outcome.server_connected, "server should connect");
    assert!(outcome.client_connected, "client should connect");
    assert!(outcome.server_profile.is_some());
    assert_eq!(outcome.server_profile, outcome.client_profile);
    assert_eq!(outcome.server_received, b"Hello from client");
    assert_eq!(outcome.client_received, b"Hello from server");
}

/// Runs a default-config dimpl server (ECDSA certificate, client certificate
/// required) against an OpenSSL client with an RSA certificate. With
/// `tamper`, the last byte of the client's CertificateVerify signature is
/// flipped on its way to the server.
fn handshake_with_rsa_client(client_key: DtlsPKeyType, tamper: bool) -> Outcome {
    env_logger::try_init().ok();

    let server_cert = OsslDtlsCert::new(DtlsCertOptions::default());
    let client_cert = OsslDtlsCert::new(DtlsCertOptions {
        common_name: "Boba Fett".into(),
        pkey_type: client_key,
    });

    let mut client = client_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS client");
    client.set_active(true);

    let mut server = Dtls::new_12(
        Arc::new(Config::default()),
        dimpl::DtlsCertificate {
            certificate: server_cert.x509.to_der().unwrap(),
            private_key: server_cert.pkey.private_key_to_der().unwrap(),
        },
        Instant::now(),
    );
    server.set_active(false);

    let mut outcome = Outcome::default();
    let mut client_events = VecDeque::new();
    let mut out_buf = vec![0u8; 2048];

    // OpenSSL sends its ClientHello once it is asked to handshake.
    client
        .handle_handshake(&mut client_events)
        .expect("Client failed to start");

    for _ in 0..40 {
        while let Some(datagram) = client.poll_datagram() {
            let mut datagram = datagram.to_vec();
            if tamper {
                tamper_certificate_verify(&mut datagram);
            }
            if let Err(e) = server.handle_packet(&datagram) {
                outcome.server_error = Some(format!("{e:?}"));
                return outcome;
            }
        }

        server.handle_timeout(Instant::now()).unwrap();
        loop {
            match server.poll_output(&mut out_buf) {
                Output::Packet(data) => client
                    .handle_receive(data, &mut client_events)
                    .expect("Client failed to handle server packet"),
                Output::Connected => outcome.server_connected = true,
                Output::PeerCert(_) => outcome.server_saw_peer_cert = true,
                Output::KeyingMaterial(_, profile) => {
                    outcome.server_profile = Some(profile);
                    server.send_application_data(b"Hello from server").unwrap();
                }
                Output::ApplicationData(data) => outcome.server_received.extend_from_slice(data),
                Output::Timeout(_) => break,
                _ => {}
            }
        }

        while let Some(event) = client_events.pop_front() {
            match event {
                DtlsEvent::Connected => outcome.client_connected = true,
                DtlsEvent::SrtpKeyingMaterial(_, profile) => {
                    outcome.client_profile = Some(profile);
                    client.handle_input(b"Hello from client").unwrap();
                }
                DtlsEvent::Data(data) => outcome.client_received.extend_from_slice(&data),
                _ => {}
            }
        }

        if outcome.client_connected
            && outcome.server_connected
            && !outcome.client_received.is_empty()
            && !outcome.server_received.is_empty()
        {
            break;
        }
    }
    outcome
}

/// Flips the last byte of a complete, unfragmented CertificateVerify (epoch 0).
fn tamper_certificate_verify(packet: &mut [u8]) {
    let mut rec = 0usize;
    while rec + 13 <= packet.len() {
        let content_type = packet[rec];
        let rec_len = u16::from_be_bytes([packet[rec + 11], packet[rec + 12]]) as usize;
        let rec_end = rec + 13 + rec_len;
        if rec_end > packet.len() {
            return;
        }
        let epoch = u16::from_be_bytes([packet[rec + 3], packet[rec + 4]]);
        if content_type == 22 && epoch == 0 {
            let mut hs = rec + 13;
            while hs + 12 <= rec_end {
                let hs_type = packet[hs];
                let hs_len = read_u24(&packet[hs + 1..hs + 4]);
                let frag_offset = read_u24(&packet[hs + 6..hs + 9]);
                let frag_len = read_u24(&packet[hs + 9..hs + 12]);
                let body_end = hs + 12 + frag_len;
                if body_end > rec_end {
                    break;
                }
                if hs_type == 15 && frag_offset + frag_len == hs_len && frag_len > 0 {
                    packet[body_end - 1] ^= 0x01;
                }
                hs = body_end;
            }
        }
        rec = rec_end;
    }
}

fn read_u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | (bytes[2] as usize)
}
