use super::*;
use ed25519_dalek::SigningKey;
use russh::ChannelMsg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Spin up a real server, in the background, listening on an ephemeral loopback port. Each
/// accepted connection is driven by the production [`ConnectionHandler`] via [`accept`], so
/// these tests exercise the actual restrictions a connecting client is subject to rather than
/// a re-implementation of them. Connections that never open a "session" channel simply leave
/// their background task parked forever, which is harmless for a test.
async fn spawn_test_server() -> SocketAddr {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(BASE64_STANDARD.encode(signing_key.to_bytes())),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let config = create_listener(&server_cfg).unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let config = config.clone();
            let expected_username = expected_username.clone();
            tokio::spawn(async move {
                let Ok(mut chan_stream) = accept(config, expected_username, None, stream).await
                else {
                    return;
                };
                // Keep the channel (and thus the session) alive until the client closes it,
                // rather than dropping it the instant it's opened, so tests can still send
                // channel requests (pty/exec/etc.) after the channel is established.
                let mut buf = [0u8; 256];
                while matches!(chan_stream.read(&mut buf).await, Ok(n) if n > 0) {}
            });
        }
    });

    addr
}

/// Client-side handler for tests that only care about server-side restrictions: it accepts
/// whatever host key the server presents rather than exercising the identity-pinning check
/// covered separately by `client_rejects_mismatched_host_key`.
struct AcceptAnyHostKey;

impl russh::client::Handler for AcceptAnyHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn connect_test_client(addr: SocketAddr) -> russh::client::Handle<AcceptAnyHostKey> {
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, addr, AcceptAnyHostKey)
        .await
        .expect("ssh handshake failed");
    let auth = handle
        .authenticate_none(DEFAULT_SSH_USER)
        .await
        .expect("auth request failed");
    assert!(auth.success(), "server should accept `none` auth");
    handle
}

#[tokio::test]
async fn client_server_handshake_and_echo() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();
    let identity_key = BASE64_STANDARD.encode(signing_key.to_bytes());
    let id_pubkey = BASE64_STANDARD.encode(verifying_key.to_bytes());

    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(identity_key),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut chan_stream = accept(config, expected_username, None, stream)
            .await
            .unwrap();

        let mut buf = [0u8; 5];
        chan_stream.read_exact(&mut buf).await.unwrap();
        chan_stream.write_all(&buf).await.unwrap();
    });

    let client_opts = ClientOptions {
        addresses: vec![addr],
        id_pubkey,
        username: None,
        banner: None,
    };
    let mut client_stream = transport_conn(&client_opts).await.unwrap();
    client_stream.write_all(b"hello").await.unwrap();

    let mut buf = [0u8; 5];
    client_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    server_task.await.unwrap();
}

#[tokio::test]
async fn client_rejects_mismatched_host_key() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let identity_key = BASE64_STANDARD.encode(signing_key.to_bytes());

    // Client is configured to pin a *different* identity than the server actually presents.
    let wrong_pubkey = BASE64_STANDARD.encode(
        SigningKey::generate(&mut rand::rng())
            .verifying_key()
            .to_bytes(),
    );

    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(identity_key),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = accept(config, expected_username, None, stream).await;
    });

    let client_opts = ClientOptions {
        addresses: vec![addr],
        id_pubkey: wrong_pubkey,
        username: None,
        banner: None,
    };
    let result = transport_conn(&client_opts).await;
    assert!(result.is_err());

    let _ = server_task.await;
}

#[tokio::test]
async fn client_rejects_mismatched_username() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();
    let identity_key = BASE64_STANDARD.encode(signing_key.to_bytes());
    let id_pubkey = BASE64_STANDARD.encode(verifying_key.to_bytes());

    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(identity_key),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = accept(config, expected_username, None, stream).await;
    });

    let client_opts = ClientOptions {
        addresses: vec![addr],
        id_pubkey,
        username: Some("wrong_user".into()),
        banner: None,
    };
    let result = transport_conn(&client_opts).await;
    assert!(result.is_err());

    let _ = server_task.await;
}

/// Confirms that a configured server banner is actually presented to the client during
/// authentication (not just plumbed into the derived client config, which is covered separately
/// in `nym_bridges::config::test::conversion`).
#[tokio::test]
async fn server_sends_configured_banner() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(BASE64_STANDARD.encode(signing_key.to_bytes())),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        banner: Some("this is a test banner".into()),
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let banner = server_cfg.banner.clone();
    let config = create_listener(&server_cfg).unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = accept(config, expected_username, banner, stream).await;
    });

    struct CaptureBanner {
        banner_tx: Option<oneshot::Sender<String>>,
    }

    impl russh::client::Handler for CaptureBanner {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn auth_banner(
            &mut self,
            banner: &str,
            _session: &mut russh::client::Session,
        ) -> Result<(), Self::Error> {
            if let Some(tx) = self.banner_tx.take() {
                let _ = tx.send(banner.to_string());
            }
            Ok(())
        }
    }

    let (banner_tx, banner_rx) = oneshot::channel();
    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        addr,
        CaptureBanner {
            banner_tx: Some(banner_tx),
        },
    )
    .await
    .expect("ssh handshake failed");

    // Triggers the "ssh-userauth" service request, which is what causes the server to send its
    // configured banner; the actual auth outcome doesn't matter for this test.
    let _ = handle.authenticate_none(DEFAULT_SSH_USER).await;

    let received_banner = banner_rx
        .await
        .expect("server should have sent an auth banner");
    assert_eq!(received_banner, "this is a test banner");
}

/// Confirms the username check is against the server's *configured* `expected_username`, not
/// just the shared default: a client presenting the configured username connects successfully,
/// while a client that omits it (falling back to the default) is rejected.
#[tokio::test]
async fn server_honors_configured_expected_username() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();
    let identity_key = BASE64_STANDARD.encode(signing_key.to_bytes());
    let id_pubkey = BASE64_STANDARD.encode(verifying_key.to_bytes());

    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(identity_key),
        private_ed25519_identity_key_file: None,
        expected_username: Some("custom_user".into()),
        banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    assert_eq!(expected_username, "custom_user");
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let config = config.clone();
            let expected_username = expected_username.clone();
            tokio::spawn(async move {
                let _ = accept(config, expected_username, None, stream).await;
            });
        }
    });

    // A client using the username the server was configured to expect succeeds.
    let matching_client = ClientOptions {
        addresses: vec![addr],
        id_pubkey: id_pubkey.clone(),
        username: Some("custom_user".into()),
        banner: None,
    };
    transport_conn(&matching_client)
        .await
        .expect("client presenting the configured username should be accepted");

    // A client that doesn't know the configured username (falling back to the shared default)
    // is rejected, even though it correctly pinned the server's host key.
    let default_username_client = ClientOptions {
        addresses: vec![addr],
        id_pubkey,
        username: None,
        banner: None,
    };
    let result = transport_conn(&default_username_client).await;
    assert!(
        result.is_err(),
        "client presenting the default username should be rejected by a server configured with a custom one"
    );

    server_task.abort();
}

#[tokio::test]
async fn server_rejects_direct_tcpip_channel() {
    let addr = spawn_test_server().await;
    let handle = connect_test_client(addr).await;

    let result = handle
        .channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 0)
        .await;

    assert!(
        matches!(result, Err(russh::Error::ChannelOpenFailure(_))),
        "direct-tcpip (local TCP/IP forwarding) channel open should be refused, got {result:?}"
    );
}

#[tokio::test]
async fn server_rejects_x11_channel_open() {
    let addr = spawn_test_server().await;
    let handle = connect_test_client(addr).await;

    let result = handle.channel_open_x11("127.0.0.1", 6010).await;

    assert!(
        matches!(result, Err(russh::Error::ChannelOpenFailure(_))),
        "X11 channel open should be refused, got {result:?}"
    );
}

#[tokio::test]
async fn server_rejects_remote_tcpip_forward() {
    let addr = spawn_test_server().await;
    let handle = connect_test_client(addr).await;

    let result = handle.tcpip_forward("127.0.0.1", 0).await;

    assert!(
        matches!(result, Err(russh::Error::RequestDenied)),
        "remote (reverse) TCP/IP forwarding should be refused, got {result:?}"
    );
}

#[tokio::test]
async fn server_rejects_pty_request() {
    let addr = spawn_test_server().await;
    let handle = connect_test_client(addr).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("plain session channel should be accepted");

    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("request should be sendable even though it will be refused");

    match channel.wait().await {
        Some(ChannelMsg::Failure) => {}
        other => panic!("expected pty request to be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn server_rejects_exec_request() {
    let addr = spawn_test_server().await;
    let handle = connect_test_client(addr).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("plain session channel should be accepted");

    channel
        .exec(true, "id")
        .await
        .expect("request should be sendable even though it will be refused");

    match channel.wait().await {
        Some(ChannelMsg::Failure) => {}
        other => panic!("expected exec request to be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn server_rejects_shell_request() {
    let addr = spawn_test_server().await;
    let handle = connect_test_client(addr).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("plain session channel should be accepted");

    channel
        .request_shell(true)
        .await
        .expect("request should be sendable even though it will be refused");

    match channel.wait().await {
        Some(ChannelMsg::Failure) => {}
        other => panic!("expected shell request to be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn server_rejects_subsystem_request() {
    let addr = spawn_test_server().await;
    let handle = connect_test_client(addr).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("plain session channel should be accepted");

    channel
        .request_subsystem(true, "sftp")
        .await
        .expect("request should be sendable even though it will be refused");

    match channel.wait().await {
        Some(ChannelMsg::Failure) => {}
        other => panic!("expected subsystem request to be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn server_rejects_x11_request() {
    let addr = spawn_test_server().await;
    let handle = connect_test_client(addr).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("plain session channel should be accepted");

    channel
        .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "0000000000000000", 0)
        .await
        .expect("request should be sendable even though it will be refused");

    match channel.wait().await {
        Some(ChannelMsg::Failure) => {}
        other => panic!("expected X11 forwarding request to be rejected, got {other:?}"),
    }
}
