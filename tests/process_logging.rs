#![cfg(unix)]

use serde_json::Value;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nddev-device-sync-server"));
    for (key, _) in std::env::vars_os() {
        let key_text = key.to_string_lossy();
        if key_text.starts_with("NDS_")
            || key_text.starts_with("DATABASE_URL")
            || key_text == "RUST_LOG"
        {
            command.env_remove(key);
        }
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
}

struct Process(Option<Child>);
impl Process {
    fn finish(mut self, terminate: bool) -> (bool, Vec<Value>, String) {
        let child = self.0.as_mut().unwrap();
        if terminate {
            assert!(
                Command::new("kill")
                    .args(["-TERM", &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "child did not exit by its deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = self.0.take().unwrap().wait_with_output().unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.stderr.is_empty(),
            "unexpected unstructured process output"
        );
        let events: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for event in &events {
            for field in [
                "timestamp",
                "severity",
                "service.name",
                "service.version",
                "deployment.environment",
                "release.channel",
                "release.version",
                "source.repository",
                "source.commit",
                "module",
                "event.name",
            ] {
                assert!(event[field].is_string(), "missing {field}: {event}");
            }
        }
        (output.status.success(), events, text)
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn request(port: u16, trace: &str) -> std::io::Result<String> {
    request_uri(port, trace, "GET", "/v1/health?code=synthetic-query-secret")
}

fn request_uri(port: u16, trace: &str, method: &str, uri: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(200),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "{method} {uri} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-header-secret\r\nCookie: synthetic-cookie-secret\r\ntraceparent: 00-{trace}-0123456789abcdef-01\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn real_http_completion_uses_the_common_formatter_and_excludes_request_secrets() {
    let (process, port) = server(&[]);
    let trace = "0123456789abcdef0123456789abcdef";
    let response = request_uri(
        port,
        trace,
        "synthetic-method-secret",
        "/synthetic-path-secret?code=synthetic-query-secret",
    )
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 404"));
    assert!(response.contains(&format!("x-request-id: {trace}")));
    let (success, events, text) = process.finish(true);
    assert!(success);
    let completion = events
        .iter()
        .find(|event| event["event.name"] == "http.request.completed" && event["trace_id"] == trace)
        .unwrap();
    assert_eq!(completion["route"], "unmatched");
    assert_eq!(completion["method"], "OTHER");
    assert_eq!(completion["outcome"], "rejected");
    assert_eq!(completion["service.name"], "nddev-device-sync-server");
    assert_eq!(completion["release.channel"], "alpha");
    assert!(completion.get("span").is_none());
    assert!(completion.get("fields").is_none());
    for secret in [
        "synthetic-method-secret",
        "synthetic-path-secret",
        "synthetic-query-secret",
        "synthetic-header-secret",
        "synthetic-cookie-secret",
    ] {
        assert!(!text.contains(secret));
    }
}

fn server(settings: &[(&str, &str)]) -> (Process, u16) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let process = Process(Some(
        command()
            .env("NDS_SERVER_ADDR", format!("127.0.0.1:{port}"))
            .envs(settings.iter().copied())
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(response) = request(port, "11111111111111111111111111111111") {
            assert!(response.starts_with("HTTP/1.1 200"));
            break;
        }
        assert!(Instant::now() < deadline, "server did not listen");
        std::thread::sleep(Duration::from_millis(10));
    }
    (process, port)
}

#[test]
fn startup_failure_has_safe_process_metadata_even_when_logging_configuration_is_invalid() {
    for setting in [
        ("NDS_SERVER_ADDR", "synthetic-secret-invalid-address"),
        ("NDS_DEBUG_SCOPE", "synthetic-secret-invalid-scope"),
    ] {
        let (success, events, text) =
            Process(Some(command().env(setting.0, setting.1).spawn().unwrap())).finish(false);
        assert!(!success);
        assert!(
            events
                .iter()
                .any(|event| event["event.name"] == "process.failed")
        );
        assert!(!text.contains("synthetic-secret"));
    }
}

#[test]
fn scoped_debug_expires_and_never_logs_request_credentials() {
    let (process, port) = server(&[
        ("NDS_LOG_MODE", "debug"),
        ("NDS_DEBUG_SCOPE", "http"),
        ("NDS_DEBUG_SECONDS", "1"),
        ("NDS_DEBUG_EVENT_LIMIT", "100"),
        ("RUST_LOG", "trace"),
    ]);
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        request(port, "22222222222222222222222222222222")
            .unwrap()
            .contains("cache-control: no-store")
    );
    let (success, events, text) = process.finish(true);
    assert!(success);
    assert!(events.iter().any(|event| event["severity"] == "debug"
        && event["trace_id"] == "11111111111111111111111111111111"));
    assert!(!events.iter().any(|event| event["severity"] == "debug"
        && event["trace_id"] == "22222222222222222222222222222222"));
    assert!(events.iter().any(
        |event| event["event.name"] == "logging.debug.disabled" && event["reason"] == "expired"
    ));
    for secret in [
        "synthetic-query-secret",
        "synthetic-header-secret",
        "synthetic-cookie-secret",
    ] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn debug_budget_is_finite_and_normal_mode_ignores_dependency_verbosity() {
    let (process, port) = server(&[
        ("NDS_LOG_MODE", "debug"),
        ("NDS_DEBUG_SCOPE", "http"),
        ("NDS_DEBUG_SECONDS", "30"),
        ("NDS_DEBUG_EVENT_LIMIT", "2"),
    ]);
    for _ in 0..3 {
        request(port, "11111111111111111111111111111111").unwrap();
    }
    let (success, events, _) = process.finish(true);
    assert!(success);
    let count = events
        .iter()
        .filter(|event| event["severity"] == "debug")
        .count();
    assert!((1..=2).contains(&count));
    assert!(
        events
            .iter()
            .any(|event| event["event.name"] == "logging.debug.disabled"
                && event["reason"] == "event_budget")
    );
    let (process, _) = server(&[("RUST_LOG", "trace")]);
    let (success, events, _) = process.finish(true);
    assert!(success);
    assert!(
        !events
            .iter()
            .any(|event| event["severity"] == "debug" || event["severity"] == "trace")
    );
    assert!(
        events
            .iter()
            .any(|event| event["event.name"] == "server.shutdown.completed")
    );
}

#[test]
fn actual_tls_signal_reload_and_shutdown_keep_the_process_envelope() {
    use rcgen::generate_simple_self_signed;
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use std::{path::PathBuf, sync::Arc};
    struct Files(PathBuf);
    impl Drop for Files {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let files =
        Files(std::env::temp_dir().join(format!("nds-process-tls-{}", uuid::Uuid::new_v4())));
    std::fs::create_dir(&files.0).unwrap();
    let first = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let second = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = files.0.join("cert.pem");
    let key = files.0.join("key.pem");
    std::fs::write(&cert, first.cert.pem()).unwrap();
    std::fs::write(&key, first.signing_key.serialize_pem()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(first.cert.der().clone()).unwrap();
    roots.add(second.cert.der().clone()).unwrap();
    let client = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let process = Process(Some(
        command()
            .env("NDS_SERVER_ADDR", format!("127.0.0.1:{port}"))
            .env("NDS_TLS_CERT_FILE", &cert)
            .env("NDS_TLS_KEY_FILE", &key)
            .spawn()
            .unwrap(),
    ));
    let exchange = || -> std::io::Result<Vec<u8>> {
        let socket = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        )?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        socket.set_write_timeout(Some(Duration::from_secs(1)))?;
        let connection =
            ClientConnection::new(client.clone(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut tls = StreamOwned::new(connection, socket);
        tls.write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut response = String::new();
        tls.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 200"));
        Ok(tls.conn.peer_certificates().unwrap()[0].to_vec())
    };
    let wait_certificate = |expected: &[u8]| {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if exchange().is_ok_and(|presented| presented == expected) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "TLS did not present the expected certificate"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    wait_certificate(first.cert.der().as_ref());
    std::fs::write(&cert, second.cert.pem()).unwrap();
    std::fs::write(&key, second.signing_key.serialize_pem()).unwrap();
    assert!(
        Command::new("kill")
            .args(["-HUP", &process.0.as_ref().unwrap().id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    wait_certificate(second.cert.der().as_ref());
    let (success, events, text) = process.finish(true);
    assert!(success);
    for name in [
        "server.started",
        "tls.reload.completed",
        "server.shutdown.completed",
    ] {
        assert!(events.iter().any(|event| event["event.name"] == name));
    }
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains(files.0.to_str().unwrap()));
}
