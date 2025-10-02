//! Certificate handling implementations
//!
//! Nym Nodes have identity keys (ed25519) that can be used to sign and verify certificates to use
//! with QUIC TLS.
//!
//! The server:
//! - has the ed25519 private key that all nodes have
//! - uses this key to create a self-signed certificate
//!   - sets the certificates common name to the base58 encoded identity key
//!
//! The client:
//! - implements a custom certificate verifier that:
//!   - only accepts ed25519 signatures
//!   - "hostname" / SNI check is set to "base58 encoded identity key" or any configured domain name
//!      - if the Server Name is not in the acceptable configured alt-names it throws a
//!        NotValidForName error
//!   - at least one common name entry is either the "base58 encoded identity key" or any configured
//!     domain name
//!     - if none of the common names are in the acceptable configured alt-names it throws a
//!       NotValidForName error
//!   - the public key from the certificate PKI is the server's ed25519 identity key
//!   - cert is signed correctly
//!     - done last to avoid ed25519 signature verification in case string based checks fail
//!   - uses the default [`rustls::client::WebPkiServerVerifier`] to verify TLS 1.2 / TLS 1.3

use anyhow::{Context, Result};
use base64::prelude::*;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePrivateKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rcgen::{Certificate, CertificateParams, DnType, KeyPair};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tracing::*;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;

use std::sync::Arc;

pub fn get_cert_signed_by_ed25519<'a>(
    common_name: String,
    signing_key: &SigningKey,
) -> Result<(Certificate, PrivateKeyDer<'a>)> {
    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("failed to create pem from signing key");

    trace!("pem: {pem:?}");

    let ca_private_key = PrivateKeyDer::from_pem_slice(pem.as_bytes())?;

    trace!("private_key: {ca_private_key:?}");

    let key_pair = KeyPair::from_pem_and_sign_algo(&pem, &rcgen::PKCS_ED25519)?;

    trace!("key pair: {key_pair:?}");

    let mut params = CertificateParams::new(vec![common_name.to_string()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_string());
    let cert = params.self_signed(&key_pair)?;

    trace!("cert: {cert:?}");

    Ok((cert, ca_private_key))
}

fn parse_certificate(
    cert_der: &[u8],
) -> Result<X509Certificate<'_>, x509_parser::nom::Err<X509Error>> {
    let res = X509Certificate::from_der(cert_der)?;
    Ok(res.1)
}

#[derive(Debug)]
pub struct IdentityBasedVerifier {
    alt_names: Vec<String>,
    server_identity_pubkey: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    default_verifier: Arc<WebPkiServerVerifier>,
}

impl IdentityBasedVerifier {
    pub fn new(identity_key: &VerifyingKey) -> Result<Self, Box<dyn std::error::Error>> {
        let pubkey_as_name = bs58::encode(identity_key.as_bytes()).into_string();
        trace!("building identity key based verified with key: {pubkey_as_name}");
        let alt_names = vec![pubkey_as_name];

        // create an empty trust store
        let mut roots = RootCertStore::empty();

        // annoyingly rustls wants CA root certificates - might be possible to set a single fake one to keep it happy
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());

        // create a verifier so we can use default implementations
        let default_verifier = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;

        Ok(IdentityBasedVerifier {
            alt_names,
            server_identity_pubkey: identity_key.to_bytes(),
            default_verifier,
        })
    }

    pub fn new_with_alt_names(
        identity_key: &VerifyingKey,
        alt_names: Option<Vec<impl ToString>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut alt_names: Vec<String> = alt_names
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect();
        let pubkey_as_name = bs58::encode(identity_key.as_bytes()).into_string();
        if !alt_names.contains(&pubkey_as_name) {
            alt_names.push(pubkey_as_name);
        }

        let mut verifier = Self::new(identity_key)?;
        verifier.alt_names = alt_names;

        Ok(verifier)
    }
}

impl ServerCertVerifier for IdentityBasedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, quinn::rustls::Error> {
        trace!(
            ">>>> verify_server_cert: end_entity: {end_entity:?}, intermediates: {intermediates:?}, server_name: {server_name:?}, ocsp_response: {ocsp_response:?}, now: {now:?}",
        );

        // check Server Name against the configured acceptable names
        if !self.alt_names.contains(&server_name.to_str().to_string()) {
            trace!(
                "⛔️ unexpected server name: {:?} {:?}",
                server_name, self.alt_names
            );
            return Err(quinn::rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ));
        }

        match parse_certificate(end_entity) {
            Ok(cert) => {
                // check Common Name against the configured acceptable names
                if cert.subject.iter_common_name().any(|cn| {
                    cn.as_str().is_ok_and(|v| {
                        trace!("  - CN = {v}");
                        self.alt_names.contains(&v.to_string())
                    })
                }) {
                    trace!("✅ acceptable common name");
                } else {
                    trace!("⛔️ unexpected common name");
                    return Err(quinn::rustls::Error::InvalidCertificate(
                        CertificateError::NotValidForName,
                    ));
                }

                // extract the public key
                let public_key = cert.public_key();
                let raw_public_key = public_key.raw;

                trace!("public key in certificate: {public_key:?}, bytes: {raw_public_key:?}");

                // check that the public key associated with the cert matches the identity key of the server
                match ed25519_dalek::pkcs8::PublicKeyBytes::from_public_key_der(raw_public_key) {
                    Ok(pk) => {
                        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk.to_bytes()) {
                            if vk.to_bytes() == self.server_identity_pubkey {
                                trace!("✅ parsed public key in certificate matches identity key");
                            } else {
                                trace!(
                                    "😢 parsed public key in certificate does not match identity key"
                                );
                                return Err(quinn::rustls::Error::InvalidCertificate(
                                    CertificateError::NotValidForName,
                                ));
                            }
                        } else {
                            trace!(
                                "😢 Could not decode subject public key into a ed25519 public key"
                            );
                        }
                    }
                    Err(_) => {
                        trace!("😢 Could not parse subject public key info from certificate");
                    }
                }

                // the certificate is self-signed, so let it verify itself
                //
                // done last in case cheaper string matching checks fail
                match cert.verify_signature(None) {
                    Ok(()) => {
                        trace!(
                            "✅ self signed certificate is valid using certificate's own public key info"
                        );
                    }
                    Err(_) => {
                        trace!("⛔️ self signed certificate failed to verify signature");
                        return Err(quinn::rustls::Error::InvalidCertificate(
                            CertificateError::BadEncoding,
                        ));
                    }
                }
            }
            Err(_) => {
                return Err(quinn::rustls::Error::InvalidCertificate(
                    CertificateError::BadEncoding,
                ));
            }
        }

        trace!("🌈 everything looks good");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        trace!(">>>> verify_tls12_signature: message: {message:?}, cert: {cert:?}, dss: {dss:?}");
        self.default_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        trace!(">>>> verify_tls13_signature: message: {message:?}, cert: {cert:?}, dss: {dss:?}");
        self.default_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

pub struct ServerConfigSource([u8; 32]);

impl ServerConfigSource {
    pub fn from_identity(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_identity_base64(id_key_base64: &str) -> Result<Self> {
        let key_in = BASE64_STANDARD.decode(id_key_base64)?;
        if key_in.len() != ed25519_dalek::SECRET_KEY_LENGTH {
            return Err(anyhow::anyhow!(
                "incorrect identity key length: {}, (32 expected)",
                key_in.len()
            ));
        }

        let mut bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        bytes.copy_from_slice(&key_in[..ed25519_dalek::SECRET_KEY_LENGTH]);

        Ok(Self::from_identity(bytes))
    }

    pub fn into_server_config(self) -> Result<rustls::ServerConfig> {
        let key_bytes = self.0;
        info!("initializing from transport identity keypair");
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verif_key = signing_key.verifying_key();
        let pubkey_as_sn = bs58::encode(verif_key.to_bytes()).into_string();
        let (cert, key) = get_cert_signed_by_ed25519(pubkey_as_sn, &signing_key)
            .expect("failed to get cert from ed255519 key");

        let (certs, key) = (vec![cert.der().clone()], key);

        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("failed to build cert")
    }

    pub fn public_identity(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }
}

#[cfg(test)]
mod test {
    use rustls_pki_types::DnsName;

    use super::*;

    /// Make sure that client connection using domain name not signed by the
    /// identity key derived cert gives an InvalidCertificate(NotValidForName) error.
    #[test]
    fn certificate_name_validity() {
        // let level = Some(tracing::level_filters::LevelFilter::DEBUG);
        // crate::test_utils::init_subscriber(level);

        let mut rng = rand::thread_rng();

        let signing_key: SigningKey = SigningKey::generate(&mut rng);
        let verif_key = signing_key.verifying_key();
        let encoded_pubkey = bs58::encode(verif_key.to_bytes()).into_string();

        let (cert, _) = get_cert_signed_by_ed25519(encoded_pubkey.clone(), &signing_key).unwrap();

        let verifier =
            IdentityBasedVerifier::new_with_alt_names(&verif_key, Some(vec!["localhost"])).unwrap();

        // Make sure that domains not included in the alt names return a NotValidForName error
        let sn = DnsName::try_from_str("other-domain.example.com").unwrap();
        let result = verifier.verify_server_cert(
            cert.der(),
            &[],
            &ServerName::DnsName(sn),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        );

        // Make sure that the encoded public key is a valid SN
        let sn = DnsName::try_from_str(&encoded_pubkey).unwrap();
        let result = verifier.verify_server_cert(
            cert.der(),
            &[],
            &ServerName::DnsName(sn),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok());

        // Make sure that items included in the alt-names are valid for SN
        let sn = DnsName::try_from_str("localhost").unwrap();
        let result = verifier.verify_server_cert(
            cert.der(),
            &[],
            &ServerName::DnsName(sn),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn rustls_handshake() {
        // let level = Some(tracing::level_filters::LevelFilter::DEBUG);
        // crate::test_utils::init_subscriber(level);

        let mut rng = rand::thread_rng();

        let signing_key: SigningKey = SigningKey::generate(&mut rng);
        let verif_key = signing_key.verifying_key();
        let encoded_pubkey = bs58::encode(verif_key.to_bytes()).into_string();

        let (cert, ca_private_key) =
            get_cert_signed_by_ed25519(encoded_pubkey.clone(), &signing_key).unwrap();

        let verifier = IdentityBasedVerifier::new(&verif_key).unwrap();

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let sn = encoded_pubkey.try_into().unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(client_config), sn).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.into()], ca_private_key)
            .unwrap();

        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();

        let (mut server_rx, mut client_tx) = std::io::pipe().unwrap();
        let (mut client_rx, mut server_tx) = std::io::pipe().unwrap();

        // Perform handshake
        let mut handshake_complete = false;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 10; // Prevent infinite loops

        while !handshake_complete && iterations < MAX_ITERATIONS {
            iterations += 1;
            let mut progress = false;
            // Client side
            if client.wants_write() {
                client.write_tls(&mut client_tx).unwrap();
                progress = true;
            }

            if server.wants_read() {
                match server.read_tls(&mut server_rx) {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        server.process_new_packets().unwrap();
                        progress = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("Server read error: {e}"),
                }
            }

            if server.wants_write() {
                server.write_tls(&mut server_tx).unwrap();
                progress = true;
            }

            if client.wants_read() {
                match client.read_tls(&mut client_rx) {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        client.process_new_packets().unwrap();
                        progress = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("Client read error: {e}"),
                }
            }

            // Check if handshake is complete
            handshake_complete = !client.is_handshaking() && !server.is_handshaking();

            // If no progress was made, break to avoid infinite loop
            if !progress {
                break;
            }
        }

        assert!(
            handshake_complete,
            "Handshake did not complete within {MAX_ITERATIONS} iterations",
        );
    }
}
