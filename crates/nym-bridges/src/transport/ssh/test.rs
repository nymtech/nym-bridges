use super::*;
use ed25519_dalek::SigningKey;
use russh::ChannelMsg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Generate a fresh base64-encoded ed25519 private key for use as a test `client_auth_key`. The
/// same string must be configured on both the server (`ServerConfig::client_auth_key`) and the
/// client (`ClientOptions::client_auth_key`) attempting to authenticate against it.
fn generate_auth_key() -> String {
    BASE64_STANDARD.encode(SigningKey::generate(&mut rand::rng()).to_bytes())
}

/// Spin up a real server, in the background, listening on an ephemeral loopback port. Each
/// accepted connection is driven by the production [`ConnectionHandler`] via [`accept`], so
/// these tests exercise the actual restrictions a connecting client is subject to rather than
/// a re-implementation of them. Connections that never open a "session" channel simply leave
/// their background task parked forever, which is harmless for a test.
///
/// Returns the address to connect to and the `client_auth_key` a client must present to
/// authenticate, for use with [`connect_test_client`].
async fn spawn_test_server() -> (SocketAddr, String) {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let client_auth_key = generate_auth_key();
    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(BASE64_STANDARD.encode(signing_key.to_bytes())),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        client_auth_key: Some(client_auth_key.clone()),
        banner: None,
        client_banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let expected_client_pubkey = server_cfg.client_auth_pubkey().unwrap();
    let config = create_listener(&server_cfg).unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let config = config.clone();
            let expected_username = expected_username.clone();
            tokio::spawn(async move {
                let Ok(mut chan_stream) =
                    accept(config, expected_username, expected_client_pubkey, stream).await
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

    (addr, client_auth_key)
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
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn connect_test_client(
    addr: SocketAddr,
    client_auth_key: &str,
) -> russh::client::Handle<AcceptAnyHostKey> {
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, addr, AcceptAnyHostKey)
        .await
        .expect("ssh handshake failed");
    let private_key = InnerClientOptions::parse_base64_auth_key(client_auth_key)
        .expect("test auth key should decode");
    let auth_key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
    let auth = handle
        .authenticate_publickey(DEFAULT_SSH_USER, auth_key)
        .await
        .expect("auth request failed");
    assert!(
        auth.success(),
        "server should accept the pre-shared publickey auth"
    );
    handle
}

#[tokio::test]
async fn client_server_handshake_and_echo() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();
    let identity_key = BASE64_STANDARD.encode(signing_key.to_bytes());
    let id_pubkey = BASE64_STANDARD.encode(verifying_key.to_bytes());
    let client_auth_key = generate_auth_key();

    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(identity_key),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        client_auth_key: Some(client_auth_key.clone()),
        banner: None,
        client_banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let expected_client_pubkey = server_cfg.client_auth_pubkey().unwrap();
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut chan_stream = accept(config, expected_username, expected_client_pubkey, stream)
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
        client_auth_key,
        banner: None,
        client_banner: None,
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
    let client_auth_key = generate_auth_key();

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
        client_auth_key: Some(client_auth_key.clone()),
        banner: None,
        client_banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let expected_client_pubkey = server_cfg.client_auth_pubkey().unwrap();
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = accept(config, expected_username, expected_client_pubkey, stream).await;
    });

    let client_opts = ClientOptions {
        addresses: vec![addr],
        id_pubkey: wrong_pubkey,
        username: None,
        client_auth_key,
        banner: None,
        client_banner: None,
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
    let client_auth_key = generate_auth_key();

    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(identity_key),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        client_auth_key: Some(client_auth_key.clone()),
        banner: None,
        client_banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let expected_client_pubkey = server_cfg.client_auth_pubkey().unwrap();
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = accept(config, expected_username, expected_client_pubkey, stream).await;
    });

    let client_opts = ClientOptions {
        addresses: vec![addr],
        id_pubkey,
        username: Some("wrong_user".into()),
        client_auth_key,
        banner: None,
        client_banner: None,
    };
    let result = transport_conn(&client_opts).await;
    assert!(result.is_err());

    let _ = server_task.await;
}

/// Confirms a client presenting the wrong `client_auth_key` - i.e. a signature from a keypair
/// other than the one the server was configured to expect - is rejected, even when it otherwise
/// pins the server's host key and presents the correct username. This is the actual security
/// gate now that `none` auth is disallowed.
#[tokio::test]
async fn client_rejects_mismatched_auth_key() {
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
        client_auth_key: Some(generate_auth_key()),
        banner: None,
        client_banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let expected_client_pubkey = server_cfg.client_auth_pubkey().unwrap();
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = accept(config, expected_username, expected_client_pubkey, stream).await;
    });

    // Client has its own, different auth key rather than the one the server expects.
    let client_opts = ClientOptions {
        addresses: vec![addr],
        id_pubkey,
        username: None,
        client_auth_key: generate_auth_key(),
        banner: None,
        client_banner: None,
    };
    let result = transport_conn(&client_opts).await;
    assert!(
        result.is_err(),
        "client presenting a different auth keypair than the server expects should be rejected"
    );

    let _ = server_task.await;
}

/// Confirms the `none` auth method is explicitly disallowed (soft-rejected, per
/// [`ConnectionHandler::auth_none`]) while `publickey` against the pre-shared `client_auth_key`
/// still works on the very same connection afterward - i.e. `none` being turned away doesn't
/// itself end the session, since standard SSH clients commonly probe with it first.
#[tokio::test]
async fn server_disallows_none_auth_but_still_allows_publickey() {
    let (addr, client_auth_key) = spawn_test_server().await;

    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, addr, AcceptAnyHostKey)
        .await
        .expect("ssh handshake failed");

    let none_auth = handle
        .authenticate_none(DEFAULT_SSH_USER)
        .await
        .expect("none auth request failed");
    assert!(
        !none_auth.success(),
        "`none` auth should be disallowed, not accepted"
    );

    let private_key = InnerClientOptions::parse_base64_auth_key(&client_auth_key)
        .expect("test auth key should decode");
    let auth_key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
    let publickey_auth = handle
        .authenticate_publickey(DEFAULT_SSH_USER, auth_key)
        .await
        .expect("publickey auth request failed");
    assert!(
        publickey_auth.success(),
        "publickey auth should still succeed on the same connection after `none` was rejected"
    );
}

/// Confirms `password` auth - not just `none` - is rejected too, and that (like `none`) it's a
/// soft rejection rather than a hard disconnect: `publickey` still works on the same connection
/// afterward. `keyboard-interactive` and OpenSSH certificate auth follow the identical code path
/// in `ConnectionHandler` and aren't separately exercised here.
#[tokio::test]
async fn server_rejects_password_auth_but_still_allows_publickey() {
    let (addr, client_auth_key) = spawn_test_server().await;

    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, addr, AcceptAnyHostKey)
        .await
        .expect("ssh handshake failed");

    let password_auth = handle
        .authenticate_password(DEFAULT_SSH_USER, "not-a-real-password")
        .await
        .expect("password auth request failed");
    assert!(
        !password_auth.success(),
        "`password` auth should be rejected, not accepted"
    );

    let private_key = InnerClientOptions::parse_base64_auth_key(&client_auth_key)
        .expect("test auth key should decode");
    let auth_key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
    let publickey_auth = handle
        .authenticate_publickey(DEFAULT_SSH_USER, auth_key)
        .await
        .expect("publickey auth request failed");
    assert!(
        publickey_auth.success(),
        "publickey auth should still succeed on the same connection after `password` was rejected"
    );
}

/// Confirms a configured `client_banner` is sent as the client's SSH identification string
/// during the handshake, in place of the underlying library's default - the client-side
/// counterpart to `server_presents_configured_banner_as_ssh_id`'s server-side check.
#[tokio::test]
async fn client_presents_configured_banner_as_ssh_id() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();
    let id_pubkey = BASE64_STANDARD.encode(verifying_key.to_bytes());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // A raw TCP peer is enough here: the SSH identification string is the first thing sent, in
    // plaintext, before any key exchange, so there's no need for a real SSH server to observe it.
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });

    let client_opts = ClientOptions {
        addresses: vec![addr],
        id_pubkey,
        username: None,
        client_auth_key: generate_auth_key(),
        banner: None,
        client_banner: Some("SSH-2.0-OpenSSH_9.6".into()),
    };
    // The handshake itself will fail since nothing on the other end speaks SSH past the
    // identification exchange; only the client's outgoing id string matters for this test.
    let _ = tokio::time::timeout(Duration::from_secs(5), transport_conn(&client_opts)).await;

    let received = server_task.await.unwrap();
    assert!(
        received.starts_with("SSH-2.0-OpenSSH_9.6"),
        "expected the configured client banner as the SSH id string, got {received:?}"
    );
}

/// Confirms a configured server `banner` is sent as the server's SSH identification string at
/// the very start of the protocol, in place of the underlying library's default - the
/// server-side counterpart to `client_presents_configured_banner_as_ssh_id`. Exercises the
/// production `accept` function directly (not just the derived client config, which is covered
/// separately in `nym_bridges::config::test::conversion`).
#[tokio::test]
async fn server_presents_configured_banner_as_ssh_id() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(BASE64_STANDARD.encode(signing_key.to_bytes())),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        client_auth_key: Some(generate_auth_key()),
        banner: Some("SSH-2.0-OpenSSH_9.6".into()),
        client_banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    let expected_client_pubkey = server_cfg.client_auth_pubkey().unwrap();
    let config = create_listener(&server_cfg).unwrap();

    // The server writes its identification line as soon as a connection is accepted, without
    // waiting on anything from the peer, so a raw TCP client that never speaks SSH is enough to
    // observe it; the handshake itself will then stall and get dropped once the test ends.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = accept(config, expected_username, expected_client_pubkey, stream).await;
    });

    let mut client_stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), client_stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read failed");
    let received = String::from_utf8_lossy(&buf[..n]);

    assert!(
        received.starts_with("SSH-2.0-OpenSSH_9.6"),
        "expected the configured server banner as the SSH id string, got {received:?}"
    );
}

/// Confirms the server config carries the session-tuning defaults this transport relies on: a
/// single auth attempt (enforced separately in `ConnectionHandler::auth_publickey`, since the
/// installed russh version doesn't itself act on `max_auth_attempts`), and keepalive/inactivity
/// settings generous enough that a lull in forwarded traffic isn't mistaken for a dead peer.
#[test]
fn server_config_uses_hardened_session_defaults() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(BASE64_STANDARD.encode(signing_key.to_bytes())),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        client_auth_key: None,
        banner: None,
        client_banner: None,
    };

    let config = server_cfg.build_server_config().unwrap();
    assert_eq!(config.max_auth_attempts, 1);
    assert_eq!(
        config.methods,
        MethodSet::from(&[MethodKind::PublicKey][..])
    );
    assert_eq!(config.keepalive_interval, Some(KEEPALIVE_INTERVAL));
    assert_eq!(config.inactivity_timeout, Some(INACTIVITY_TIMEOUT));
}

/// The client-side counterpart to `server_config_uses_hardened_session_defaults`: the client
/// also needs a keepalive interval configured, since it's the client's periodic traffic that
/// keeps the *server's* inactivity timer from firing during a lull (see
/// `connection_survives_idle_lull_via_client_keepalives`).
#[test]
fn client_config_uses_hardened_session_defaults() {
    let config = build_client_config(None);
    assert_eq!(config.keepalive_interval, Some(KEEPALIVE_INTERVAL));
    assert_eq!(config.inactivity_timeout, Some(INACTIVITY_TIMEOUT));
}

/// Confirms an idle lull in application traffic - the tunneled connection just being quiet for a
/// while, not actually dead - doesn't get mistaken for a dead peer and torn down. Uses the
/// production `accept`/`build_client_config` session config with `inactivity_timeout` and
/// `keepalive_interval` overridden to millisecond-scale values so the test doesn't have to wait
/// on the production-scale (30s/5min) durations; the mechanism being exercised - the client's
/// keepalive traffic resetting the server's inactivity timer - is the same either way.
#[tokio::test]
async fn connection_survives_idle_lull_via_client_keepalives() {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(BASE64_STANDARD.encode(signing_key.to_bytes())),
        private_ed25519_identity_key_file: None,
        expected_username: None,
        client_auth_key: Some(generate_auth_key()),
        banner: None,
        client_banner: None,
    };

    let expected_client_pubkey = server_cfg.client_auth_pubkey().unwrap();
    let mut raw_server_config = server_cfg.build_server_config().unwrap();
    // No keepalive of its own: surviving the lull below must come entirely from the client.
    raw_server_config.keepalive_interval = None;
    raw_server_config.inactivity_timeout = Some(Duration::from_millis(300));
    let config = Arc::new(raw_server_config);

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accept(config, expected_username, expected_client_pubkey, stream).await
    });

    let mut client_config = build_client_config(None);
    client_config.keepalive_interval = Some(Duration::from_millis(50));
    let handler = ClientHandler {
        id_pubkey: signing_key.verifying_key(),
    };
    let mut handle = russh::client::connect(Arc::new(client_config), addr, handler)
        .await
        .expect("ssh handshake failed");

    let private_key =
        InnerClientOptions::parse_base64_auth_key(server_cfg.client_auth_key.as_ref().unwrap())
            .unwrap();
    let auth_key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
    let auth = handle
        .authenticate_publickey(DEFAULT_SSH_USER, auth_key)
        .await
        .expect("auth request failed");
    assert!(auth.success());

    let mut client_stream = handle
        .channel_open_session()
        .await
        .expect("plain session channel should be accepted")
        .into_stream();

    let mut server_stream = server_task
        .await
        .unwrap()
        .expect("server should accept the channel before the lull even starts");

    // Sit idle, well past several multiples of the server's (shortened) inactivity_timeout. If
    // the client's keepalives weren't resetting it, the server would have long since torn the
    // connection down.
    tokio::time::sleep(Duration::from_millis(900)).await;

    client_stream
        .write_all(b"still alive")
        .await
        .expect("channel should still be writable after the idle lull");

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(2), server_stream.read(&mut buf))
        .await
        .expect("read timed out - server likely dropped the connection during the lull")
        .expect("read failed");
    assert_eq!(&buf[..n], b"still alive");
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
    let client_auth_key = generate_auth_key();

    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connection_limit: None,
        identity_key: Some(identity_key),
        private_ed25519_identity_key_file: None,
        expected_username: Some("custom_user".into()),
        client_auth_key: Some(client_auth_key.clone()),
        banner: None,
        client_banner: None,
    };

    let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_username = server_cfg.expected_username();
    assert_eq!(expected_username, "custom_user");
    let expected_client_pubkey = server_cfg.client_auth_pubkey().unwrap();
    let config = create_listener(&server_cfg).unwrap();

    let server_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let config = config.clone();
            let expected_username = expected_username.clone();
            tokio::spawn(async move {
                let _ = accept(config, expected_username, expected_client_pubkey, stream).await;
            });
        }
    });

    // A client using the username the server was configured to expect succeeds.
    let matching_client = ClientOptions {
        addresses: vec![addr],
        id_pubkey: id_pubkey.clone(),
        username: Some("custom_user".into()),
        client_auth_key: client_auth_key.clone(),
        banner: None,
        client_banner: None,
    };
    transport_conn(&matching_client)
        .await
        .expect("client presenting the configured username should be accepted");

    // A client that doesn't know the configured username (falling back to the shared default)
    // is rejected, even though it correctly pinned the server's host key and auth key.
    let default_username_client = ClientOptions {
        addresses: vec![addr],
        id_pubkey,
        username: None,
        client_auth_key,
        banner: None,
        client_banner: None,
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
    let (addr, client_auth_key) = spawn_test_server().await;
    let handle = connect_test_client(addr, &client_auth_key).await;

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
    let (addr, client_auth_key) = spawn_test_server().await;
    let handle = connect_test_client(addr, &client_auth_key).await;

    let result = handle.channel_open_x11("127.0.0.1", 6010).await;

    assert!(
        matches!(result, Err(russh::Error::ChannelOpenFailure(_))),
        "X11 channel open should be refused, got {result:?}"
    );
}

#[tokio::test]
async fn server_rejects_remote_tcpip_forward() {
    let (addr, client_auth_key) = spawn_test_server().await;
    let handle = connect_test_client(addr, &client_auth_key).await;

    let result = handle.tcpip_forward("127.0.0.1", 0).await;

    assert!(
        matches!(result, Err(russh::Error::RequestDenied)),
        "remote (reverse) TCP/IP forwarding should be refused, got {result:?}"
    );
}

#[tokio::test]
async fn server_rejects_pty_request() {
    let (addr, client_auth_key) = spawn_test_server().await;
    let handle = connect_test_client(addr, &client_auth_key).await;
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
    let (addr, client_auth_key) = spawn_test_server().await;
    let handle = connect_test_client(addr, &client_auth_key).await;
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
    let (addr, client_auth_key) = spawn_test_server().await;
    let handle = connect_test_client(addr, &client_auth_key).await;
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
    let (addr, client_auth_key) = spawn_test_server().await;
    let handle = connect_test_client(addr, &client_auth_key).await;
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
    let (addr, client_auth_key) = spawn_test_server().await;
    let handle = connect_test_client(addr, &client_auth_key).await;
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
