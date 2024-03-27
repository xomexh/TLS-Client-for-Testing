#![allow(unused_variables)]

use std::{
    env::args,
    io::{self, Write},
    net::TcpStream,
    sync::Arc,
};

use rustls::{ pki_types::ServerName
};
use tracing::info;

fn main() -> io::Result<()> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .try_init();

    // let server = args().nth(1).expect("No Server given");
    // let port = args().nth(2).expect("No Port given");
    // let sock_addr = format!("{}:{}", server, port);
    let server = "127.0.0.1".to_string();
    let port = "8080";
    let sock_addr = "127.0.0.1:8080";
    dbg!(&sock_addr);


    // let config = rustls::ClientConfig::builder()
    //     .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {}))
    //     .with_no_client_auth();

    let config = rustls::client::danger::DangerousClientConfigBuilder{ cfg: rustls::ClientConfig::builder()};
    let config = config.with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {})).with_no_client_auth();
    // .dangerous()
    // .set_certificate_verifier(Arc::new(danger::NoCertificateVerification{}));

    //TLS handshake here:
    let server_name: ServerName = ServerName::try_from("127.0.0.1").expect("Invalid DNS Name");
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(sock_addr).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    match tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    ) {
        Ok(_) => {println!("\n\n WROTE REQUEST on Server\n");}
        Err(e) => {println!("failed to write request: {}", e);}
    }

    info!("retrieving peer certificates...");
    match conn.peer_certificates() {
        Some(peer_certs) => { println!("\n PEER CERTS:\n {:#?}\n", peer_certs);}
        None => {println!("no peer certs");}
    }
    Ok(())
}


//Set Dangerous Configuration
mod danger {
    use std::time::SystemTime;
    use random_manager::u16;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::UnixTime;
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::SignatureScheme;
    use rustls::{client::danger::ServerCertVerified, Error, pki_types::ServerName};
    use rustls::client::danger::ServerCertVerifier;
    #[derive(Debug)]
    pub struct NoCertificateVerification {}

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct
        ) -> Result<HandshakeSignatureValid, Error>{
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme>{
            vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::Unknown(u16()),
            ]
        }
    }
}