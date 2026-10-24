//! Offline TLS 1.3 interoperability tests: exercise *negotiated* key exchange,
//! not just the CryptoProvider's list of advertised groups.
#![cfg(feature = "pqc")]

use doh_proxy::tls_crypto::build_provider;
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, NamedGroup, RootCertStore, ServerConfig,
};
use std::{sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

async fn negotiate(server_provider: CryptoProvider) -> (NamedGroup, NamedGroup) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate local test certificate");
    let certificate = CertificateDer::from(cert.der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let server = ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("server supports TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)
        .expect("server certificate");

    // Trust *only* the ephemeral local test certificate; never disable TLS
    // verification or inject a global trust root.
    let mut root_store = RootCertStore::empty();
    root_store.add(certificate).expect("trusted test certificate");
    let client = ClientConfig::builder_with_provider(Arc::new(build_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("client supports TLS 1.3")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local test server");
    let addr = listener.local_addr().expect("local test address");
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept client");
        let stream = TlsAcceptor::from(Arc::new(server))
            .accept(socket)
            .await
            .expect("server TLS handshake");
        stream
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .expect("server negotiated group")
            .name()
    });

    let socket = TcpStream::connect(addr).await.expect("connect to local server");
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        TlsConnector::from(Arc::new(client)).connect(
            ServerName::try_from("localhost").expect("valid test DNS name"),
            socket,
        ),
    )
    .await
    .expect("client handshake timeout")
    .expect("client TLS handshake");
    let client_group = stream
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .expect("client negotiated group")
        .name();

    let server_group = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("server task timeout")
        .expect("server task failed");
    (client_group, server_group)
}

#[tokio::test]
async fn cloudflare_hybrid_group_negotiates_on_both_peers() {
    let groups = negotiate(build_provider()).await;
    assert_eq!(groups, (NamedGroup::X25519MLKEM768, NamedGroup::X25519MLKEM768));
}

#[tokio::test]
async fn classical_only_server_negotiates_x25519_fallback() {
    let mut server_provider = build_provider();
    server_provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::X25519);
    assert_eq!(server_provider.kx_groups.len(), 1);
    let groups = negotiate(server_provider).await;
    assert_eq!(groups, (NamedGroup::X25519, NamedGroup::X25519));
}
