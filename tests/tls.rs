//! End to end tests for the TLS paths, driven against a loopback rustls server.
//!
//! Nothing else in the suite opens a TLS connection, and the TLS layer is where a configuration
//! mistake turns into a panic rather than an error, which in a release build aborts the process.
//! These run the real binary against a real handshake: the CA file, the client certificate, and
//! the refusals when either is wrong.
//!
//! Certificates are generated per run and written to a temporary directory, so no key material is
//! ever committed.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use assert_cmd::Command;
use predicates::prelude::*;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::crypto::ring::default_provider;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const VAULT_BODY: &str = r#"{"data":{"data":{"password":"hunter2"},"metadata":{"version":1}}}"#;

/// A certificate authority, and what it has issued.
struct Pki {
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: Vec<u8>,
    client_cert_pem: String,
    client_key_pem: String,
    /// A key that belongs to no certificate here.
    stranger_key_pem: String,
}

fn name(common: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("empty subject names");
    params.distinguished_name.push(DnType::CommonName, common);
    params
}

fn pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = name("sealref test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = name("sealref test server");
    server_params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = server_params.signed_by(&server_key, &issuer).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = name("sealref test client");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client = client_params.signed_by(&client_key, &issuer).unwrap();

    Pki {
        ca_pem: ca.pem(),
        ca_der: ca.der().clone(),
        server_chain: vec![server.der().clone()],
        server_key: server_key.serialize_der(),
        client_cert_pem: client.pem(),
        client_key_pem: client_key.serialize_pem(),
        stranger_key_pem: KeyPair::generate().unwrap().serialize_pem(),
    }
}

/// Serve the Vault fixture over TLS on the loopback interface, returning its address.
fn serve(pki: &Pki, require_client_certificate: bool) -> String {
    let provider = Arc::new(default_provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap();
    let builder = if require_client_certificate {
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca_der.clone()).unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .unwrap();
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let config = Arc::new(
        builder
            .with_single_cert(
                pki.server_chain.clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key.clone())),
            )
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = format!("https://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { break };
            let Ok(connection) = ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            let mut tls = StreamOwned::new(connection, tcp);
            // A client that fails the handshake surfaces as a read error here, which is the
            // outcome several of these tests are after, so it is dropped without comment.
            let mut seen = Vec::new();
            let mut chunk = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&chunk[..n]),
                }
            }
            if seen.is_empty() {
                continue;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{VAULT_BODY}",
                VAULT_BODY.len()
            );
            let _ = tls.write_all(response.as_bytes());
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    address
}

fn write(dir: &Path, file: &str, contents: &str) -> PathBuf {
    let path = dir.join(file);
    std::fs::write(&path, contents).unwrap();
    path
}

/// A `sealref` invocation that reads one Vault secret from `address`, with no ambient TLS setup.
fn resolve(address: &str) -> Command {
    let mut command = Command::cargo_bin("sealref").expect("the sealref binary is built");
    for name in [
        "SEALREF_KEY",
        "SEALREF_KEY_FILE",
        "SEALREF_KEY_FD",
        "SEALREF_CA_FILE",
        "SEALREF_CLIENT_CERT",
        "SEALREF_CLIENT_KEY",
        "VAULT_NAMESPACE",
        "VAULT_TOKEN_FILE",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env_remove(name);
    }
    command
        .env("VAULT_ADDR", address)
        .env("VAULT_TOKEN", "s.testtoken")
        .args(["resolve", "--ref", "seal:vault:secret/app#password"]);
    command
}

#[test]
fn a_server_signed_by_the_ca_file_is_trusted() {
    let pki = pki();
    let address = serve(&pki, false);
    let dir = tempfile::tempdir().unwrap();
    let ca = write(dir.path(), "ca.pem", &pki.ca_pem);
    resolve(&address)
        .env("SEALREF_CA_FILE", &ca)
        .assert()
        .success()
        .stdout("hunter2");
}

#[test]
fn a_server_the_built_in_roots_do_not_vouch_for_is_refused_cleanly() {
    let pki = pki();
    let address = serve(&pki, false);
    resolve(&address)
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("cannot reach"))
        .stderr(predicate::str::contains("secret/app#password"))
        .stderr(predicate::str::contains("panicked").not())
        .stderr(predicate::str::contains("s.testtoken").not());
}

#[test]
fn a_ca_file_replaces_the_built_in_roots_rather_than_adding_to_them() {
    // A CA file that trusts some other authority must not leave this server trusted just because
    // it is a certificate chain.
    let pki = pki();
    let other = self::pki();
    let address = serve(&pki, false);
    let dir = tempfile::tempdir().unwrap();
    let ca = write(dir.path(), "other-ca.pem", &other.ca_pem);
    resolve(&address)
        .env("SEALREF_CA_FILE", &ca)
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("cannot reach"))
        .stderr(predicate::str::contains("panicked").not());
}

#[test]
fn a_client_certificate_is_presented_when_the_server_asks_for_one() {
    let pki = pki();
    let address = serve(&pki, true);
    let dir = tempfile::tempdir().unwrap();
    let ca = write(dir.path(), "ca.pem", &pki.ca_pem);
    let cert = write(dir.path(), "client.pem", &pki.client_cert_pem);
    let key = write(dir.path(), "client-key.pem", &pki.client_key_pem);
    resolve(&address)
        .env("SEALREF_CA_FILE", &ca)
        .env("SEALREF_CLIENT_CERT", &cert)
        .env("SEALREF_CLIENT_KEY", &key)
        .assert()
        .success()
        .stdout("hunter2");
}

#[test]
fn a_server_that_requires_a_client_certificate_refuses_a_run_without_one() {
    let pki = pki();
    let address = serve(&pki, true);
    let dir = tempfile::tempdir().unwrap();
    let ca = write(dir.path(), "ca.pem", &pki.ca_pem);
    resolve(&address)
        .env("SEALREF_CA_FILE", &ca)
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("cannot reach"))
        .stderr(predicate::str::contains("panicked").not());
}

#[test]
fn a_certificate_and_key_that_do_not_match_fail_before_any_connection() {
    let pki = pki();
    let address = serve(&pki, true);
    let dir = tempfile::tempdir().unwrap();
    let ca = write(dir.path(), "ca.pem", &pki.ca_pem);
    let cert = write(dir.path(), "client.pem", &pki.client_cert_pem);
    let key = write(dir.path(), "stranger-key.pem", &pki.stranger_key_pem);
    resolve(&address)
        .env("SEALREF_CA_FILE", &ca)
        .env("SEALREF_CLIENT_CERT", &cert)
        .env("SEALREF_CLIENT_KEY", &key)
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("SEALREF_CLIENT_CERT"))
        .stderr(predicate::str::contains("panicked").not());
}
