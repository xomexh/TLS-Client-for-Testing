#![allow(unused_imports)]
#![allow(unused_variables)]

use std::{
    env::args,
    io::{self, Write},
    net::TcpStream,
    sync::Arc,
};

use rustls::{
    client::DangerousClientConfig, server::AllowAnyAnonymousOrAuthenticatedClient,
    OwnedTrustAnchor, RootCertStore, ServerName,
};
use tracing::info;

fn main() -> io::Result<()> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .try_init();

    // let server = args().nth(1).expect("No Server given");
    // let port = args().nth(2).expect("No Port given");
    // let sock_addr = format!("{}:{}", server, port);
    let server = "127.0.0.1";
    let port = "3000";
    let sock_addr = "127.0.0.1:3000";
    dbg!(&sock_addr);


    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {}))
        .with_no_client_auth();
    // .dangerous()
    // .set_certificate_verifier(Arc::new(danger::NoCertificateVerification{}));

    //TLS handshake here:
    let server_name: ServerName = ServerName::try_from(server.as_ref()).unwrap();
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
    use rustls::{client::ServerCertVerified, Certificate, Error, ServerName};
    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            end_entity: &Certificate,
            intermediates: &[Certificate],
            server_name: &ServerName,
            scts: &mut dyn Iterator<Item = &[u8]>,
            ocsp_response: &[u8],
            now: SystemTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}