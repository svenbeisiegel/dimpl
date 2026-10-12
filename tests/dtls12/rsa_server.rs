//! DTLS 1.2 client against an OpenSSL server with an RSA certificate.
//!
//! Mirrors a Mitel MiVoice Border Gateway (MBG) as captured with a browser:
//! a self-signed RSA 1536-bit certificate, ECDHE_RSA_AES128_GCM_SHA256, a
//! CertificateRequest (our client authenticates with ECDSA) and only the
//! SRTP_AES128_CM_SHA1_80 profile.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::crypto::HashAlgorithm;
use dimpl::crypto::SignatureAlgorithm;
use dimpl::{Config, Dtls, Output, SrtpProfile};

use crate::ossl_helper::{DtlsCertOptions, DtlsEvent, DtlsPKeyType, OsslDtlsCert};

const ECDHE_RSA_AES128_GCM_SHA256: u16 = 0xC02F;
const RSA_PKCS1_SHA256: u16 = 0x0401;

/// What a dimpl client saw from an OpenSSL server.
#[derive(Default)]
struct Outcome {
    client_connected: bool,
    server_connected: bool,
    client_profile: Option<SrtpProfile>,
    server_profile: Option<SrtpProfile>,
    client_received: Vec<u8>,
    server_received: Vec<u8>,
    cipher_suite: Option<u16>,
    ske_signature_algorithm: Option<u16>,
    client_error: Option<String>,
}

#[test]
fn dtls12_client_with_rsa1536_server_like_mitel_mbg() {
    let outcome = handshake_with_rsa_server(DtlsPKeyType::Rsa1536, false);
    assert_connected_like_mbg(&outcome);
}

#[test]
fn dtls12_client_with_rsa2048_server() {
    let outcome = handshake_with_rsa_server(DtlsPKeyType::Rsa2048, false);
    assert_connected_like_mbg(&outcome);
}

#[test]
fn dtls12_client_rejects_tampered_rsa_server_key_exchange() {
    let outcome = handshake_with_rsa_server(DtlsPKeyType::Rsa2048, true);
    assert!(
        !outcome.client_connected,
        "a forged signature must not connect"
    );
    let error = outcome.client_error.expect("the client reports an error");
    assert!(
        error.contains("RsaSignatureVerificationFailed"),
        "unexpected error: {error}"
    );
}

#[test]
fn rsa_signature_verification_vectors() {
    use openssl::hash::MessageDigest;
    use openssl::sign::Signer;

    let verifier = Config::default().crypto_provider().signature_verification;
    let data = b"ServerKeyExchange params";

    for bits in [1024, 1536, 2048, 4096] {
        let (cert, pkey) = rsa_cert(bits);
        for (hash, digest) in [
            (HashAlgorithm::SHA256, MessageDigest::sha256()),
            (HashAlgorithm::SHA384, MessageDigest::sha384()),
        ] {
            let mut signer = Signer::new(digest, &pkey).unwrap();
            signer.update(data).unwrap();
            let mut signature = signer.sign_to_vec().unwrap();

            let result =
                verifier.verify_signature(&cert, data, &signature, hash, SignatureAlgorithm::RSA);
            // aws-lc-rs has no SHA-384 variant below 2048 bits.
            if cfg!(feature = "aws-lc-rs") && hash == HashAlgorithm::SHA384 && bits < 2048 {
                assert!(result.is_err(), "{bits} bits {hash:?}");
                continue;
            }
            result.unwrap_or_else(|e| panic!("{bits} bits {hash:?}: {e:?}"));

            *signature.last_mut().unwrap() ^= 0x01;
            let err = verifier
                .verify_signature(&cert, data, &signature, hash, SignatureAlgorithm::RSA)
                .unwrap_err();
            assert!(
                format!("{err:?}").contains("RsaSignatureVerificationFailed"),
                "{bits} bits {hash:?}: {err:?}"
            );
        }
    }

    // Too small a key is refused before verifying.
    let (cert, pkey) = rsa_cert(768);
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(data).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let err = verifier
        .verify_signature(
            &cert,
            data,
            &signature,
            HashAlgorithm::SHA256,
            SignatureAlgorithm::RSA,
        )
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("UnsupportedRsaVerification"),
        "{err:?}"
    );

    // An RSA signature algorithm with an EC certificate is refused.
    let ec = OsslDtlsCert::new(DtlsCertOptions::default());
    let err = verifier
        .verify_signature(
            &ec.x509.to_der().unwrap(),
            data,
            &signature,
            HashAlgorithm::SHA256,
            SignatureAlgorithm::RSA,
        )
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("UnsupportedPublicKeyAlgorithm"),
        "{err:?}"
    );
}

fn assert_connected_like_mbg(outcome: &Outcome) {
    assert_eq!(outcome.client_error, None);
    assert!(outcome.client_connected, "client should connect");
    assert!(outcome.server_connected, "server should connect");
    assert_eq!(outcome.cipher_suite, Some(ECDHE_RSA_AES128_GCM_SHA256));
    assert_eq!(outcome.ske_signature_algorithm, Some(RSA_PKCS1_SHA256));
    assert_eq!(outcome.client_profile, Some(SrtpProfile::AES128_CM_SHA1_80));
    assert_eq!(outcome.server_profile, Some(SrtpProfile::AES128_CM_SHA1_80));
    assert_eq!(outcome.server_received, b"Hello from client");
    assert_eq!(outcome.client_received, b"Hello from server");
}

/// Runs a default-config dimpl client (ECDSA certificate) against an OpenSSL
/// server with an RSA certificate. With `tamper`, the last byte of the
/// ServerKeyExchange signature is flipped on its way to the client.
fn handshake_with_rsa_server(server_key: DtlsPKeyType, tamper: bool) -> Outcome {
    env_logger::try_init().ok();

    let client_cert = OsslDtlsCert::new(DtlsCertOptions::default());
    let server_cert = OsslDtlsCert::new(DtlsCertOptions {
        common_name: "Bobba Fett".into(),
        pkey_type: server_key,
    });

    // The OpenSSL helper requires a client certificate, like the MBG.
    let mut server = server_cert
        .new_dtls_impl_with_srtp_profiles(&[SrtpProfile::AES128_CM_SHA1_80])
        .expect("Failed to create DTLS server");
    server.set_active(false);

    let mut client = Dtls::new_12(
        Arc::new(Config::default()),
        dimpl::DtlsCertificate {
            certificate: client_cert.x509.to_der().unwrap(),
            private_key: client_cert.pkey.private_key_to_der().unwrap(),
        },
        Instant::now(),
    );
    client.set_active(true);

    let mut outcome = Outcome::default();
    let mut server_events = VecDeque::new();
    let mut out_buf = vec![0u8; 2048];
    let mut ske = Vec::new();

    for _ in 0..40 {
        client.handle_timeout(Instant::now()).unwrap();
        loop {
            match client.poll_output(&mut out_buf) {
                Output::Packet(data) => server
                    .handle_receive(data, &mut server_events)
                    .expect("Server failed to handle client packet"),
                Output::Connected => outcome.client_connected = true,
                Output::KeyingMaterial(_, profile) => {
                    outcome.client_profile = Some(profile);
                    client.send_application_data(b"Hello from client").unwrap();
                }
                Output::ApplicationData(data) => outcome.client_received.extend_from_slice(data),
                Output::Timeout(_) => break,
                _ => {}
            }
        }

        while let Some(event) = server_events.pop_front() {
            match event {
                DtlsEvent::Connected => outcome.server_connected = true,
                DtlsEvent::SrtpKeyingMaterial(_, profile) => {
                    outcome.server_profile = Some(profile);
                    server.handle_input(b"Hello from server").unwrap();
                }
                DtlsEvent::Data(data) => outcome.server_received.extend_from_slice(&data),
                _ => {}
            }
        }

        while let Some(datagram) = server.poll_datagram() {
            let mut datagram = datagram.to_vec();
            inspect_server_flight(&mut datagram, &mut outcome, tamper, &mut ske);
            if let Err(e) = client.handle_packet(&datagram) {
                outcome.client_error = Some(format!("{e:?}"));
                return outcome;
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

/// Notes the ServerHello's cipher suite and the ServerKeyExchange's signature
/// algorithm (epoch 0; the ServerKeyExchange may arrive in fragments), and
/// optionally corrupts the last byte of the ServerKeyExchange signature.
fn inspect_server_flight(
    packet: &mut [u8],
    outcome: &mut Outcome,
    tamper: bool,
    ske: &mut Vec<u8>,
) {
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
                let body = hs + 12;
                let body_end = body + frag_len;
                if body_end > rec_end {
                    break;
                }
                if hs_type == 2 && frag_offset == 0 && frag_len == hs_len {
                    // version(2) random(32) session_id(1 + n) cipher_suite(2)
                    let sid_len = packet[body + 34] as usize;
                    let cs = body + 35 + sid_len;
                    outcome.cipher_suite = Some(u16::from_be_bytes([packet[cs], packet[cs + 1]]));
                }
                if hs_type == 12 {
                    if tamper && frag_offset + frag_len == hs_len && frag_len > 0 {
                        packet[body_end - 1] ^= 0x01;
                    }
                    if ske.len() < hs_len {
                        ske.resize(hs_len, 0);
                    }
                    ske[frag_offset..frag_offset + frag_len]
                        .copy_from_slice(&packet[body..body_end]);
                    if frag_offset + frag_len == hs_len && ske[0] == 3 {
                        // curve_type(1) named_group(2) pubkey(1 + n) sig_alg(2) sig(2 + n)
                        let alg = 4 + ske[3] as usize;
                        outcome.ske_signature_algorithm =
                            Some(u16::from_be_bytes([ske[alg], ske[alg + 1]]));
                    }
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

/// A self-signed RSA certificate (DER) of the given size and its key.
fn rsa_cert(bits: u32) -> (Vec<u8>, openssl::pkey::PKey<openssl::pkey::Private>) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509Name};

    let e = BigNum::from_u32(0x10001).unwrap();
    let pkey = PKey::from_rsa(Rsa::generate_with_e(bits, &e).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "rsa test").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    (builder.build().to_der().unwrap(), pkey)
}
