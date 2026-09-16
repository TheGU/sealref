//! End to end tests for the remote providers, driven against a local HTTP server.
//!
//! The point of these is that the request SealRef actually puts on the wire is checked: the path,
//! the query, and the vendor authentication header. A unit test over a response body cannot catch
//! a wrong URL or a missing header, and those are exactly the mistakes that only show up against a
//! real Vault or a real CyberArk appliance.
//!
//! The server speaks plain HTTP on the loopback interface, so no certificate is needed and the
//! suite still runs with no network.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use predicates::prelude::*;

/// One request the server received.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: String,
}

/// A canned answer for one request target.
struct Route {
    method: &'static str,
    target: &'static str,
    status: u16,
    body: &'static str,
    content_type: &'static str,
}

impl Route {
    fn json(method: &'static str, target: &'static str, body: &'static str) -> Self {
        Route {
            method,
            target,
            status: 200,
            body,
            content_type: "application/json",
        }
    }

    fn text(method: &'static str, target: &'static str, body: &'static str) -> Self {
        Route {
            method,
            target,
            status: 200,
            body,
            content_type: "text/plain",
        }
    }

    fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}

struct TestServer {
    address: String,
    recorded: Arc<Mutex<Vec<Recorded>>>,
}

impl TestServer {
    fn start(routes: Vec<Route>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = format!("http://{}", listener.local_addr().unwrap());
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&recorded);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                // One request per connection keeps the server a few lines long; every response
                // closes the socket so there is no keep-alive state to manage.
                if let Some(request) = read_request(&stream) {
                    sink.lock().unwrap().push(request.clone());
                    respond(stream, &routes, &request);
                }
            }
        });
        TestServer { address, recorded }
    }

    fn requests(&self) -> Vec<Recorded> {
        self.recorded.lock().unwrap().clone()
    }
}

fn read_request(stream: &TcpStream) -> Option<Recorded> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut start = String::new();
    reader.read_line(&mut start).ok()?;
    let mut parts = start.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body).ok()?;
    }

    Some(Recorded {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn respond(mut stream: TcpStream, routes: &[Route], request: &Recorded) {
    let matched = routes
        .iter()
        .find(|r| r.method == request.method && r.target == request.target);
    let (status, content_type, body) = match matched {
        Some(route) => (route.status, route.content_type, route.body),
        None => (404, "application/json", r#"{"errors":["not found"]}"#),
    };
    let response = format!(
        "HTTP/1.1 {status} X\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Location: http://127.0.0.1:1/moved\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// A `sealref` invocation with no ambient key or provider configuration.
fn sealref() -> Command {
    let mut command = Command::cargo_bin("sealref").expect("the sealref binary is built");
    for name in [
        "SEALREF_KEY",
        "SEALREF_KEY_FILE",
        "SEALREF_KEY_FD",
        "SEALREF_CA_FILE",
        "SEALREF_CLIENT_CERT",
        "SEALREF_CLIENT_KEY",
        "SEALREF_CCP_URL",
        "SEALREF_CCP_APP_ID",
        "VAULT_ADDR",
        "VAULT_TOKEN",
        "VAULT_TOKEN_FILE",
        "VAULT_NAMESPACE",
        "CONJUR_APPLIANCE_URL",
        "CONJUR_ACCOUNT",
        "CONJUR_AUTHN_TOKEN",
        "CONJUR_AUTHN_TOKEN_FILE",
        "CONJUR_AUTHN_LOGIN",
        "CONJUR_AUTHN_API_KEY",
        "CONJUR_AUTHN_API_KEY_FILE",
        "VAULT_CACERT",
        "VAULT_CAPATH",
        "VAULT_SKIP_VERIFY",
        "CONJUR_CERT_FILE",
    ] {
        command.env_remove(name);
    }
    command
}

const VAULT_BODY: &str = r#"{"data":{"data":{"password":"hunter2"},"metadata":{"version":1}}}"#;

const CONJUR_TOKEN_JSON: &str =
    r#"{"protected":"cHJvdGVjdGVk","payload":"cGF5bG9hZA==","signature":"c2ln"}"#;

#[test]
fn vault_reads_a_kv_v2_secret() {
    let server = TestServer::start(vec![Route::json(
        "GET",
        "/v1/secret/data/myapp/prod/database",
        VAULT_BODY,
    )]);
    sealref()
        .env("VAULT_ADDR", &server.address)
        .env("VAULT_TOKEN", "s.testtoken")
        .args([
            "resolve",
            "--ref",
            "seal:vault:secret/myapp/prod/database#password",
        ])
        .assert()
        .success()
        .stdout("hunter2");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers["x-vault-token"], "s.testtoken");
    assert!(!requests[0].headers.contains_key("x-vault-namespace"));
}

#[test]
fn vault_sends_the_namespace_header_when_one_is_set() {
    let server = TestServer::start(vec![Route::json("GET", "/v1/secret/data/app", VAULT_BODY)]);
    sealref()
        .env("VAULT_ADDR", &server.address)
        .env("VAULT_TOKEN", "s.testtoken")
        .env("VAULT_NAMESPACE", "team-a")
        .args(["resolve", "--ref", "seal:vault:secret/app#password"])
        .assert()
        .success();
    assert_eq!(server.requests()[0].headers["x-vault-namespace"], "team-a");
}

#[test]
fn vault_reports_a_status_without_the_response_body() {
    let server = TestServer::start(vec![Route::json(
        "GET",
        "/v1/secret/data/app",
        r#"{"errors":["1 error occurred: permission denied for policy team-a"]}"#,
    )
    .status(403)]);
    sealref()
        .env("VAULT_ADDR", &server.address)
        .env("VAULT_TOKEN", "s.testtoken")
        .args(["resolve", "--ref", "seal:vault:secret/app#password"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HTTP 403"))
        .stderr(predicate::str::contains("secret/app#password"))
        .stderr(predicate::str::contains("s.testtoken").not())
        .stderr(predicate::str::contains("permission denied").not());
}

#[test]
fn a_redirect_is_refused_rather_than_followed() {
    // Following one would resend the vendor token to whatever host the redirect named.
    let server = TestServer::start(vec![
        Route::json("GET", "/v1/secret/data/app", "{}").status(302)
    ]);
    sealref()
        .env("VAULT_ADDR", &server.address)
        .env("VAULT_TOKEN", "s.testtoken")
        .args(["resolve", "--ref", "seal:vault:secret/app#password"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HTTP 302"));
    assert_eq!(server.requests().len(), 1, "the redirect was not followed");
}

#[test]
fn conjur_reads_a_variable_with_a_supplied_token() {
    let server = TestServer::start(vec![Route::text(
        "GET",
        "/secrets/myorg/variable/prod/db/password",
        "hunter2",
    )]);
    sealref()
        .env("CONJUR_APPLIANCE_URL", format!("{}/", server.address))
        .env("CONJUR_ACCOUNT", "myorg")
        .env("CONJUR_AUTHN_TOKEN", CONJUR_TOKEN_JSON)
        .args(["resolve", "--ref", "seal:conjur:prod/db/password"])
        .assert()
        .success()
        .stdout("hunter2");

    let requests = server.requests();
    assert_eq!(requests.len(), 1, "a supplied token needs no authenticate");
    let expected = format!(
        "Token token=\"{}\"",
        base64_standard(CONJUR_TOKEN_JSON.as_bytes())
    );
    assert_eq!(requests[0].headers["authorization"], expected);
}

#[test]
fn conjur_exchanges_an_api_key_once_for_two_variables() {
    let token = base64_standard(CONJUR_TOKEN_JSON.as_bytes());
    let token: &'static str = Box::leak(token.into_boxed_str());
    let server = TestServer::start(vec![
        Route::text("POST", "/authn/myorg/host%2Fmyapp/authenticate", token),
        Route::text("GET", "/secrets/myorg/variable/prod/db/password", "first"),
        Route::text("GET", "/secrets/myorg/variable/prod/api/token", "second"),
    ]);
    let key_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(key_file.path(), "1vbkm9x2q8j7y3nw5tzp\n").unwrap();

    sealref()
        .env("CONJUR_APPLIANCE_URL", &server.address)
        .env("CONJUR_ACCOUNT", "myorg")
        .env("CONJUR_AUTHN_LOGIN", "host/myapp")
        .env("CONJUR_AUTHN_API_KEY_FILE", key_file.path())
        .env("DB_PASSWORD", "seal:conjur:prod/db/password")
        .env("API_TOKEN", "seal:conjur:prod/api/token")
        .arg("exec")
        .arg("--")
        .args(echo_two("DB_PASSWORD", "API_TOKEN"))
        .assert()
        .success()
        .stdout(predicate::str::contains("first"))
        .stdout(predicate::str::contains("second"));

    let requests = server.requests();
    assert_eq!(requests.len(), 3, "one authenticate, then two reads");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].body, "1vbkm9x2q8j7y3nw5tzp");
    assert_eq!(requests[0].headers["accept-encoding"], "base64");
}

#[test]
fn conjur_refuses_an_api_key_placed_in_the_token_variable() {
    let server = TestServer::start(vec![]);
    sealref()
        .env("CONJUR_APPLIANCE_URL", &server.address)
        .env("CONJUR_ACCOUNT", "myorg")
        .env("CONJUR_AUTHN_TOKEN", "1vbkm9x2q8j7y3nw5tzp")
        .args(["resolve", "--ref", "seal:conjur:prod/db/password"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("1vbkm9x2q8j7y3nw5tzp").not());
    assert!(
        server.requests().is_empty(),
        "a credential that is not an access token must never be sent"
    );
}

#[test]
fn ccp_reads_an_account_property() {
    let server = TestServer::start(vec![Route::json(
        "GET",
        "/AIMWebService/api/Accounts?AppID=myapp&Safe=Prod%20Databases&Object=pg-main",
        r#"{"Content":"hunter2","UserName":"svc_app"}"#,
    )]);
    sealref()
        .env("SEALREF_CCP_URL", &server.address)
        .env("SEALREF_CCP_APP_ID", "myapp")
        .args([
            "resolve",
            "--ref",
            "seal:ccp:Prod Databases/pg-main#Content",
        ])
        .assert()
        .success()
        .stdout("hunter2");
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn ccp_reports_the_error_code_but_not_the_error_message() {
    // CyberArk's ErrorMsg echoes the application id and the requesting machine into what would
    // become a CI log line.
    let server = TestServer::start(vec![Route::json(
        "GET",
        "/AIMWebService/api/Accounts?AppID=myapp&Safe=MySafe&Object=pg-main",
        r#"{"ErrorCode":"APPAP004E","ErrorMsg":"query [Safe=MySafe] from machine 10.0.0.9 for app myapp"}"#,
    )
    .status(404)]);
    sealref()
        .env("SEALREF_CCP_URL", &server.address)
        .env("SEALREF_CCP_APP_ID", "myapp")
        .args(["resolve", "--ref", "seal:ccp:MySafe/pg-main#Content"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("APPAP004E"))
        .stderr(predicate::str::contains("MySafe/pg-main#Content"))
        .stderr(predicate::str::contains("10.0.0.9").not())
        .stderr(predicate::str::contains("machine").not());
}

#[test]
fn conjur_never_echoes_the_response_body() {
    // A Conjur read returns the secret AS the response body, so an error handler that quotes a
    // body is a direct disclosure. This route fails, but with a body shaped like a secret.
    let server = TestServer::start(vec![Route::text(
        "GET",
        "/secrets/myorg/variable/prod/db/password",
        "SECRET-BODY-THAT-MUST-NOT-BE-PRINTED",
    )
    .status(500)]);
    sealref()
        .env("CONJUR_APPLIANCE_URL", &server.address)
        .env("CONJUR_ACCOUNT", "myorg")
        .env("CONJUR_AUTHN_TOKEN", CONJUR_TOKEN_JSON)
        .args(["resolve", "--ref", "seal:conjur:prod/db/password"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HTTP 500"))
        .stderr(predicate::str::contains("SECRET-BODY-THAT-MUST-NOT-BE-PRINTED").not());
}

#[test]
fn conjur_refuses_an_empty_value_rather_than_starting_with_one() {
    let server = TestServer::start(vec![Route::text(
        "GET",
        "/secrets/myorg/variable/prod/db/password",
        "",
    )]);
    sealref()
        .env("CONJUR_APPLIANCE_URL", &server.address)
        .env("CONJUR_ACCOUNT", "myorg")
        .env("CONJUR_AUTHN_TOKEN", CONJUR_TOKEN_JSON)
        .args(["resolve", "--ref", "seal:conjur:prod/db/password"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty value"));
}

#[test]
fn a_transport_failure_does_not_print_the_request_url() {
    // The CCP request URL carries the application id in its query string, and a refused connection
    // is an ordinary first-deployment event that lands straight in a CI log.
    sealref()
        .env("SEALREF_CCP_URL", "http://127.0.0.1:1")
        .env("SEALREF_CCP_APP_ID", "SUPER-SECRET-APPID")
        .args(["resolve", "--ref", "seal:ccp:MySafe/pg-main#Content"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("MySafe/pg-main#Content"))
        .stderr(predicate::str::contains("cannot reach"))
        .stderr(predicate::str::contains("SUPER-SECRET-APPID").not())
        .stderr(predicate::str::contains("AIMWebService").not());
}

#[test]
fn a_traversing_reference_is_refused_before_any_request() {
    let server = TestServer::start(vec![]);
    for reference in [
        "seal:conjur:../../otheracct/variable/prod/db",
        "seal:vault:secret/../../sys/seal-status#x",
    ] {
        sealref()
            .env("CONJUR_APPLIANCE_URL", &server.address)
            .env("CONJUR_ACCOUNT", "myorg")
            .env("CONJUR_AUTHN_TOKEN", CONJUR_TOKEN_JSON)
            .env("VAULT_ADDR", &server.address)
            .env("VAULT_TOKEN", "s.testtoken")
            .args(["resolve", "--ref", reference])
            .assert()
            .failure()
            .stderr(predicate::str::contains("segment"));
    }
    assert!(
        server.requests().is_empty(),
        "a traversing reference must never reach the server"
    );
}

#[test]
fn a_vendor_tls_variable_is_reported_rather_than_silently_ignored() {
    let server = TestServer::start(vec![Route::json("GET", "/v1/secret/data/app", VAULT_BODY)]);
    sealref()
        .env("VAULT_ADDR", &server.address)
        .env("VAULT_TOKEN", "s.testtoken")
        .env("VAULT_CACERT", "/etc/ssl/internal.pem")
        .args(["resolve", "--ref", "seal:vault:secret/app#password"])
        .assert()
        .success()
        .stderr(predicate::str::contains("VAULT_CACERT"))
        .stderr(predicate::str::contains("SEALREF_CA_FILE"));
}

#[test]
fn a_local_reference_never_builds_an_http_client() {
    // A deployment with only seal:v1 references must not be broken by an unusable certificate.
    let keyring = "k1 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let sealed = String::from_utf8(
        sealref()
            .env("SEALREF_KEY", keyring)
            .arg("seal")
            .write_stdin("local-only")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    sealref()
        .env("SEALREF_KEY", keyring)
        .env("SEALREF_CLIENT_CERT", "/nonexistent/client.pem")
        .env("SEALREF_CLIENT_KEY", "/nonexistent/client.key")
        .args(["resolve", "--ref", sealed.trim()])
        .assert()
        .success()
        .stdout("local-only");
}

#[test]
fn an_unusable_client_certificate_fails_a_remote_reference() {
    let server = TestServer::start(vec![Route::json("GET", "/v1/secret/data/app", VAULT_BODY)]);
    sealref()
        .env("VAULT_ADDR", &server.address)
        .env("VAULT_TOKEN", "s.testtoken")
        .env("SEALREF_CLIENT_CERT", "/nonexistent/client.pem")
        .env("SEALREF_CLIENT_KEY", "/nonexistent/client.key")
        .args(["resolve", "--ref", "seal:vault:secret/app#password"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("SEALREF_CLIENT_CERT"));
}

#[test]
fn a_client_certificate_without_its_key_is_refused() {
    let server = TestServer::start(vec![Route::json("GET", "/v1/secret/data/app", VAULT_BODY)]);
    sealref()
        .env("VAULT_ADDR", &server.address)
        .env("VAULT_TOKEN", "s.testtoken")
        .env("SEALREF_CLIENT_CERT", "/nonexistent/client.pem")
        .args(["resolve", "--ref", "seal:vault:secret/app#password"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("SEALREF_CLIENT_KEY is not"));
}

/// Standard base64, spelled out so the test does not depend on the crate under test.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A command that prints two environment variables, spelled for the host shell.
fn echo_two(first: &str, second: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec![
            "cmd".to_string(),
            "/c".to_string(),
            format!("echo %{first}% %{second}%"),
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("printf '%s %s\\n' \"${first}\" \"${second}\""),
        ]
    }
}
