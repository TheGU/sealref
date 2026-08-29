//! End to end tests that drive the built binary.
//!
//! Every invocation passes its keyring explicitly and clears the other key sources, so the suite
//! is independent of whatever the developer or the CI runner happens to have in the environment.

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const KEY_B: &str = "PDs6OTg3NjU0MzIxMC8uLSwrKikoJyYlJCMiIR8eHRw";
const KEYRING: &str = "k1 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8;k2 PDs6OTg3NjU0MzIxMC8uLSwrKikoJyYlJCMiIR8eHRw;dev argon2id:development-only-passphrase";

/// A `sealref` invocation with a known keyring and no ambient key sources.
fn sealref() -> Command {
    let mut command = Command::cargo_bin("sealref").expect("the sealref binary is built");
    command
        .env_remove("SEALREF_KEY_FD")
        .env_remove("SEALREF_KEY_FILE")
        .env("SEALREF_KEY", KEYRING);
    command
}

/// A `sealref` invocation with no keyring at all.
fn sealref_without_keys() -> Command {
    let mut command = Command::cargo_bin("sealref").expect("the sealref binary is built");
    command
        .env_remove("SEALREF_KEY_FD")
        .env_remove("SEALREF_KEY_FILE")
        .env_remove("SEALREF_KEY");
    command
}

fn seal_value(kid: &str, plaintext: &str) -> String {
    let output = sealref()
        .args(["seal", "--kid", kid])
        .write_stdin(plaintext.to_string())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).unwrap().trim().to_string()
}

fn write(dir: &TempDir, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, contents).unwrap();
    path
}

fn path_arg(path: &Path) -> String {
    path.display().to_string()
}

#[test]
fn keygen_prints_one_usable_keyring_line() {
    let output = sealref_without_keys()
        .args(["keygen", "--kid", "k-test"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let line = String::from_utf8(output).unwrap();
    assert!(line.ends_with('\n'));
    let line = line.trim();
    let (kid, key) = line.split_once(' ').expect("kid and key on one line");
    assert_eq!(kid, "k-test");
    assert_eq!(key.len(), 43, "43 base64url characters encode 32 bytes");

    // The generated line is a working keyring on its own.
    let mut command = Command::cargo_bin("sealref").unwrap();
    let sealed = command
        .env_remove("SEALREF_KEY_FD")
        .env_remove("SEALREF_KEY_FILE")
        .env("SEALREF_KEY", line)
        .arg("seal")
        .write_stdin("round trip")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let sealed = String::from_utf8(sealed).unwrap().trim().to_string();
    assert!(sealed.starts_with("seal:v1:k-test:"));
}

#[test]
fn keygen_defaults_the_key_id_to_a_dated_one() {
    let output = sealref_without_keys()
        .arg("keygen")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let line = String::from_utf8(output).unwrap();
    let kid = line.split_once(' ').unwrap().0;
    assert!(kid.starts_with('k'));
    assert_eq!(kid.len(), 9, "k plus YYYYMMDD");
    assert!(kid[1..].chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn seal_and_unseal_round_trip() {
    let sealed = seal_value("k1", "hunter2");
    assert!(sealed.starts_with("seal:v1:k1:"));
    sealref()
        .args(["unseal", "--ref", &sealed])
        .assert()
        .success()
        .stdout("hunter2");
}

#[test]
fn seal_keeps_stdin_byte_for_byte_unless_trim_is_given() {
    let sealed = seal_value("k1", "hunter2\n");
    sealref()
        .args(["unseal", "--ref", &sealed])
        .assert()
        .success()
        .stdout("hunter2\n");

    let trimmed = sealref()
        .args(["seal", "--kid", "k1", "--trim"])
        .write_stdin("hunter2\n")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let trimmed = String::from_utf8(trimmed).unwrap().trim().to_string();
    sealref()
        .args(["unseal", "--ref", &trimmed])
        .assert()
        .success()
        .stdout("hunter2");
}

#[test]
fn seal_uses_the_first_keyring_line_by_default() {
    let sealed = sealref()
        .arg("seal")
        .write_stdin("default key")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(String::from_utf8(sealed)
        .unwrap()
        .starts_with("seal:v1:k1:"));
}

#[test]
fn seal_refuses_a_plaintext_argument() {
    sealref()
        .args(["seal", "my-super-secret"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("shell history"))
        .stderr(predicate::str::contains("my-super-secret").not());
}

#[test]
fn unseal_reads_a_reference_from_stdin() {
    let sealed = seal_value("dev", "from a passphrase key");
    sealref()
        .arg("unseal")
        .write_stdin(format!("{sealed}\n"))
        .assert()
        .success()
        .stdout("from a passphrase key");
}

#[test]
fn unseal_adds_a_newline_on_request() {
    let sealed = seal_value("k1", "value");
    sealref()
        .args(["unseal", "--ref", &sealed, "--newline"])
        .assert()
        .success()
        .stdout("value\n");
}

#[test]
fn a_tampered_reference_fails() {
    let sealed = seal_value("k1", "hunter2");
    let mut bytes = sealed.into_bytes();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    sealref()
        .args(["unseal", "--ref", &tampered])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("wrong key or altered ciphertext"));
}

#[test]
fn an_unknown_key_id_fails() {
    let sealed = seal_value("k1", "hunter2").replace("seal:v1:k1:", "seal:v1:k9:");
    sealref()
        .args(["unseal", "--ref", &sealed])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("no key with id \"k9\""));
}

#[test]
fn the_wrong_key_id_from_the_same_keyring_fails() {
    let sealed = seal_value("k1", "hunter2").replace("seal:v1:k1:", "seal:v1:k2:");
    sealref()
        .args(["unseal", "--ref", &sealed])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn an_unknown_provider_fails() {
    sealref()
        .args(["resolve", "--ref", "seal:aws-sm:something"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unknown reference provider"));
}

#[test]
fn malformed_base64_fails() {
    sealref()
        .args(["unseal", "--ref", "seal:v1:k1:not+valid+base64url"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("base64url"));
}

#[test]
fn unseal_refuses_a_vault_reference() {
    sealref()
        .args(["unseal", "--ref", "seal:vault:secret/app#password"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("seal:v1 references only"));
}

#[test]
fn a_missing_keyring_is_reported_clearly() {
    sealref_without_keys()
        .args([
            "unseal",
            "--ref",
            "seal:v1:k1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("no key source"));
}

#[test]
fn the_keyring_can_come_from_a_file() {
    let dir = TempDir::new().unwrap();
    let keyfile = write(&dir, "sealref.key", &format!("k1 {KEY_A}\n"));
    let sealed = seal_value("k1", "from a key file");
    Command::cargo_bin("sealref")
        .unwrap()
        .env_remove("SEALREF_KEY_FD")
        .env_remove("SEALREF_KEY")
        .env("SEALREF_KEY_FILE", path_arg(&keyfile))
        .args(["unseal", "--ref", &sealed])
        .assert()
        .success()
        .stdout("from a key file");
}

#[test]
fn the_argon2id_form_is_deterministic_across_runs() {
    let dir = TempDir::new().unwrap();
    let keyfile = write(
        &dir,
        "dev.key",
        "dev argon2id:development-only-passphrase\n",
    );
    let sealed = seal_value("dev", "same key both times");
    Command::cargo_bin("sealref")
        .unwrap()
        .env_remove("SEALREF_KEY_FD")
        .env_remove("SEALREF_KEY")
        .env("SEALREF_KEY_FILE", path_arg(&keyfile))
        .args(["unseal", "--ref", &sealed])
        .assert()
        .success()
        .stdout("same key both times");
}

#[test]
fn render_replaces_every_reference_and_leaves_other_text_alone() {
    let dir = TempDir::new().unwrap();
    let first = seal_value("k1", "first-secret");
    let second = seal_value("k2", "second-secret");
    let template = write(
        &dir,
        "app.ini.tmpl",
        &format!(
            "[db]\nuser = app\npassword = {{{{{first}}}}}\n\n[api]\ntoken = {{{{ {second} }}}}\nnote = {{{{ not-a-reference }}}}\n"
        ),
    );
    sealref()
        .args(["render", &path_arg(&template)])
        .assert()
        .success()
        .stdout(
            "[db]\nuser = app\npassword = first-secret\n\n[api]\ntoken = second-secret\nnote = {{ not-a-reference }}\n",
        );
}

#[test]
fn render_writes_to_a_destination_file() {
    let dir = TempDir::new().unwrap();
    let sealed = seal_value("k1", "written-secret");
    let template = write(
        &dir,
        "app.conf.tmpl",
        &format!("password={{{{{sealed}}}}}\n"),
    );
    let out = dir.path().join("app.conf");
    sealref()
        .args(["render", &path_arg(&template), "--out", &path_arg(&out)])
        .assert()
        .success()
        .stdout("");
    assert_eq!(
        fs::read_to_string(&out).unwrap(),
        "password=written-secret\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn render_writes_nothing_when_a_reference_cannot_be_resolved() {
    let dir = TempDir::new().unwrap();
    let template = write(&dir, "bad.tmpl", "password={{seal:v1:k9:AAAA}}\n");
    let out = dir.path().join("bad.conf");
    sealref()
        .args(["render", &path_arg(&template), "--out", &path_arg(&out)])
        .assert()
        .failure()
        .code(1);
    assert!(!out.exists(), "no file is written when rendering fails");
}

#[test]
fn check_reports_provenance_without_a_keyring() {
    let dir = TempDir::new().unwrap();
    let sealed = seal_value("k1", "hunter2");
    let env_file = write(
        &dir,
        "app.env",
        &format!(
            "DB_HOST=db01\nDB_PASSWORD={sealed}\nSMTP_PASSWORD=seal:vault:secret/myapp/smtp#password\nLOG_LEVEL=info\n"
        ),
    );
    sealref_without_keys()
        .args(["check", "--env-file", &path_arg(&env_file)])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK DB_HOST plaintext"))
        .stdout(predicate::str::contains("OK DB_PASSWORD sealed kid=k1"))
        .stdout(predicate::str::contains(
            "OK SMTP_PASSWORD vault secret/myapp/smtp#password",
        ))
        .stdout(predicate::str::contains("OK LOG_LEVEL plaintext"));
}

#[test]
fn check_accepts_a_positional_env_file() {
    let dir = TempDir::new().unwrap();
    let env_file = write(&dir, "x.env", "LOG_LEVEL=info\n");
    sealref_without_keys()
        .args(["check", &path_arg(&env_file)])
        .assert()
        .success()
        .stdout("OK LOG_LEVEL plaintext\n");
}

#[test]
fn check_require_sealed_fails_on_a_plaintext_secret() {
    let dir = TempDir::new().unwrap();
    let env_file = write(&dir, "app.env", "DB_PASSWORD=hunter2\nLOG_LEVEL=info\n");
    sealref_without_keys()
        .args([
            "check",
            "--require-sealed",
            "--env-file",
            &path_arg(&env_file),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("FAIL DB_PASSWORD plaintext"))
        .stdout(predicate::str::contains("hunter2").not());
}

#[test]
fn check_require_sealed_passes_when_every_secret_is_sealed() {
    let dir = TempDir::new().unwrap();
    let sealed = seal_value("k1", "hunter2");
    let env_file = write(
        &dir,
        "app.env",
        &format!("DB_PASSWORD={sealed}\nAPI_TOKEN=seal:vault:secret/app#token\nLOG_LEVEL=info\n"),
    );
    sealref_without_keys()
        .args([
            "check",
            "--require-sealed",
            "--env-file",
            &path_arg(&env_file),
        ])
        .assert()
        .success();
}

#[test]
fn check_require_sealed_honours_an_extra_pattern() {
    let dir = TempDir::new().unwrap();
    let env_file = write(&dir, "app.env", "LICENSE_BLOB=abc\n");
    sealref_without_keys()
        .args(["check", "--require-sealed", &path_arg(&env_file)])
        .assert()
        .success();
    sealref_without_keys()
        .args([
            "check",
            "--require-sealed",
            "--pattern",
            "^LICENSE_",
            &path_arg(&env_file),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("FAIL LICENSE_BLOB plaintext"));
}

#[test]
fn check_fails_on_a_malformed_reference() {
    let dir = TempDir::new().unwrap();
    let env_file = write(&dir, "app.env", "DB_PASSWORD=seal:v1:k1:!!!\n");
    sealref_without_keys()
        .args(["check", &path_arg(&env_file)])
        .assert()
        .code(2)
        .stdout(predicate::str::contains(
            "FAIL DB_PASSWORD invalid reference",
        ));
}

#[test]
fn check_finds_a_private_key_block_in_a_template() {
    let dir = TempDir::new().unwrap();
    let file = write(
        &dir,
        "app.conf",
        "user = app\ntoken = {{seal:vault:secret/app#token}}\nkey = |\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n",
    );
    sealref_without_keys()
        .args(["check", "--require-sealed", &path_arg(&file)])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("private key block"));
    sealref_without_keys()
        .args(["check", &path_arg(&file)])
        .assert()
        .success();
}

#[test]
fn check_quiet_prints_failures_only() {
    let dir = TempDir::new().unwrap();
    let env_file = write(&dir, "app.env", "LOG_LEVEL=info\nDB_PASSWORD=hunter2\n");
    sealref_without_keys()
        .args(["check", "-q", "--require-sealed", &path_arg(&env_file)])
        .assert()
        .code(2)
        .stdout("FAIL DB_PASSWORD plaintext\n");
}

#[test]
fn rewrap_rewrites_only_the_named_key_and_keeps_every_other_byte() {
    let dir = TempDir::new().unwrap();
    let first = seal_value("k1", "first-secret");
    let second = seal_value("k2", "already-rotated");
    let original = format!(
        "# an app env file\nDB_HOST=db01\nexport DB_PASSWORD={first}\nOTHER={second}\nAPI_TOKEN=seal:vault:secret/app#token\n\n# trailing comment\n"
    );
    let env_file = write(&dir, "app.env", &original);

    sealref()
        .args(["rewrap", "--from", "k1", "--to", "k2", &path_arg(&env_file)])
        .assert()
        .success()
        .stdout(predicate::str::contains(" 1"));

    let rewritten = fs::read_to_string(&env_file).unwrap();
    for line in [
        "# an app env file",
        "DB_HOST=db01",
        &format!("OTHER={second}"),
        "API_TOKEN=seal:vault:secret/app#token",
        "# trailing comment",
    ] {
        assert!(
            rewritten.contains(line),
            "expected {line} to survive rewrap"
        );
    }
    assert!(!rewritten.contains(&first), "the old reference is gone");
    assert_eq!(
        rewritten.lines().count(),
        original.lines().count(),
        "line structure is preserved"
    );

    let new_reference = rewritten
        .lines()
        .find_map(|line| line.strip_prefix("export DB_PASSWORD="))
        .expect("the sealed line is still there");
    assert!(new_reference.starts_with("seal:v1:k2:"));
    sealref()
        .args(["unseal", "--ref", new_reference])
        .assert()
        .success()
        .stdout("first-secret");
}

#[test]
fn rewrap_also_rewrites_templates() {
    let dir = TempDir::new().unwrap();
    let sealed = seal_value("k1", "template-secret");
    let template = write(
        &dir,
        "app.ini.tmpl",
        &format!("[db]\npassword = {{{{{sealed}}}}}\n"),
    );
    sealref()
        .args(["rewrap", "--from", "k1", "--to", "k2", &path_arg(&template)])
        .assert()
        .success();
    let rewritten = fs::read_to_string(&template).unwrap();
    assert!(rewritten.starts_with("[db]\npassword = {{seal:v1:k2:"));
    assert!(rewritten.ends_with("}}\n"));
    sealref()
        .args(["render", &path_arg(&template)])
        .assert()
        .success()
        .stdout("[db]\npassword = template-secret\n");
}

#[test]
fn rewrap_reports_zero_for_a_file_with_nothing_to_do() {
    let dir = TempDir::new().unwrap();
    let env_file = write(&dir, "plain.env", "LOG_LEVEL=info\n");
    sealref()
        .args(["rewrap", "--from", "k1", "--to", "k2", &path_arg(&env_file)])
        .assert()
        .success()
        .stdout(predicate::str::contains(" 0"));
    assert_eq!(fs::read_to_string(&env_file).unwrap(), "LOG_LEVEL=info\n");
}

#[test]
fn rewrap_fails_before_touching_a_file_when_a_key_is_missing() {
    let dir = TempDir::new().unwrap();
    let sealed = seal_value("k1", "untouched");
    let contents = format!("DB_PASSWORD={sealed}\n");
    let env_file = write(&dir, "app.env", &contents);
    sealref()
        .args([
            "rewrap",
            "--from",
            "k1",
            "--to",
            "k404",
            &path_arg(&env_file),
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("no key with id \"k404\""));
    assert_eq!(fs::read_to_string(&env_file).unwrap(), contents);
}

/// A command that prints one environment variable, spelled for the host shell.
fn echo_command(variable: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec![
            "cmd".to_string(),
            "/c".to_string(),
            format!("echo %{variable}%"),
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("printf '%s\\n' \"${variable}\""),
        ]
    }
}

#[test]
fn exec_resolves_the_inherited_environment() {
    let sealed = seal_value("k1", "exec-secret");
    let mut command = sealref();
    command
        .env("DB_PASSWORD", &sealed)
        .arg("exec")
        .arg("--")
        .args(echo_command("DB_PASSWORD"));
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("exec-secret"))
        .stdout(predicate::str::contains("seal:v1").not());
}

#[test]
fn exec_leaves_values_that_are_not_references_untouched() {
    let mut command = sealref();
    command
        .env("LOG_LEVEL", "info")
        .arg("exec")
        .arg("--")
        .args(echo_command("LOG_LEVEL"));
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("info"));
}

#[test]
fn exec_layers_an_env_file_over_the_inherited_environment() {
    let dir = TempDir::new().unwrap();
    let sealed = seal_value("k2", "from-the-env-file");
    let env_file = write(
        &dir,
        "app.env",
        &format!("DB_PASSWORD={sealed}\n# comment\nLOG_LEVEL=debug\n"),
    );
    let mut command = sealref();
    command
        .env("DB_PASSWORD", "overridden")
        .arg("exec")
        .arg("--env-file")
        .arg(path_arg(&env_file))
        .arg("--")
        .args(echo_command("DB_PASSWORD"));
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("from-the-env-file"));
}

#[test]
fn exec_renders_a_template_before_starting_the_command() {
    let dir = TempDir::new().unwrap();
    let sealed = seal_value("k1", "template-value");
    let template = write(
        &dir,
        "app.conf.tmpl",
        &format!("password={{{{{sealed}}}}}\n"),
    );
    let out = dir.path().join("app.conf");
    let mut command = sealref();
    command
        .arg("exec")
        .arg("--template")
        .arg(format!("{}:{}", path_arg(&template), path_arg(&out)))
        .arg("--")
        .args(echo_command("PATH"));
    command.assert().success();
    assert_eq!(
        fs::read_to_string(&out).unwrap(),
        "password=template-value\n"
    );
}

#[test]
fn exec_fails_closed_before_running_anything() {
    let dir = TempDir::new().unwrap();
    let marker = dir.path().join("must-not-exist");
    let mut command = sealref();
    #[cfg(windows)]
    let child = vec![
        "cmd".to_string(),
        "/c".to_string(),
        format!("type nul > {}", marker.display()),
    ];
    #[cfg(not(windows))]
    let child = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("touch '{}'", marker.display()),
    ];
    command
        .env(
            "DB_PASSWORD",
            "seal:v1:k404:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .arg("exec")
        .arg("--")
        .args(child);
    command
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("DB_PASSWORD"))
        .stderr(predicate::str::contains("no key with id \"k404\""));
    assert!(!marker.exists(), "the command must not have run");
}

#[test]
fn exec_passes_the_child_exit_code_through() {
    let mut command = sealref();
    #[cfg(windows)]
    let child = vec!["cmd".to_string(), "/c".to_string(), "exit 3".to_string()];
    #[cfg(not(windows))]
    let child = vec!["sh".to_string(), "-c".to_string(), "exit 3".to_string()];
    command.arg("exec").arg("--").args(child);
    command.assert().code(3);
}

#[test]
fn exec_reports_an_unknown_provider_by_variable_name() {
    let mut command = sealref();
    command
        .env("SMTP_PASSWORD", "seal:nope:whatever")
        .arg("exec")
        .arg("--")
        .args(echo_command("PATH"));
    command
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("SMTP_PASSWORD"))
        .stderr(predicate::str::contains("unknown reference provider"));
}

#[test]
fn the_version_flag_names_the_binary_version() {
    sealref_without_keys()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn key_material_never_appears_in_output() {
    let sealed = seal_value("k1", "hunter2");
    let output = sealref()
        .args(["unseal", "--ref", &sealed])
        .assert()
        .success()
        .get_output()
        .clone();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(KEY_A));
    assert!(!combined.contains(KEY_B));
}
