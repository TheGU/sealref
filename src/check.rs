//! `sealref check`: report where each value comes from, without ever reading a secret.
//!
//! Two properties matter here. The first is that no value is ever printed, so the output is safe
//! in a CI log. The second is that a `seal:` value is parsed but never decrypted, so `check` runs
//! on a build agent that holds no keyring and cannot reach Vault.

use std::path::Path;

use regex_lite::Regex;

use crate::reference::Reference;
use crate::{dotenv, reference, template, Error, Result};

/// Variable-name patterns that must not hold plaintext under `--require-sealed`.
pub const DEFAULT_PATTERNS: &[&str] = &[
    "PASS",
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "PRIVATE",
    "CREDENTIAL",
];

/// One reported line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// True when this finding fails the check.
    pub failed: bool,
    /// The rendered report line.
    pub line: String,
}

impl Finding {
    fn ok(name: &str, detail: &str) -> Self {
        Finding {
            failed: false,
            line: format!("OK {name} {detail}"),
        }
    }

    fn fail(name: &str, detail: &str) -> Self {
        Finding {
            failed: true,
            line: format!("FAIL {name} {detail}"),
        }
    }
}

/// The result of checking every requested input.
#[derive(Debug, Default)]
pub struct Report {
    /// Findings in input order.
    pub findings: Vec<Finding>,
}

impl Report {
    /// True when at least one finding failed.
    pub fn failed(&self) -> bool {
        self.findings.iter().any(|f| f.failed)
    }

    /// The process exit code: 0 when everything passed, 2 when anything failed.
    pub fn exit_code(&self) -> i32 {
        if self.failed() {
            2
        } else {
            0
        }
    }
}

/// A configured checker.
pub struct Checker {
    require_sealed: bool,
    patterns: Vec<Regex>,
}

impl Checker {
    /// Build a checker. Extra patterns are added to [`DEFAULT_PATTERNS`]; all of them are matched
    /// case-insensitively against the variable name, anywhere in it.
    pub fn new(require_sealed: bool, extra_patterns: &[String]) -> Result<Self> {
        let mut patterns = Vec::with_capacity(DEFAULT_PATTERNS.len() + extra_patterns.len());
        for source in DEFAULT_PATTERNS
            .iter()
            .map(|p| (*p).to_string())
            .chain(extra_patterns.iter().cloned())
        {
            let regex = Regex::new(&format!("(?i){source}"))
                .map_err(|e| Error::Msg(format!("invalid --pattern \"{source}\": {e}")))?;
            patterns.push(regex);
        }
        Ok(Checker {
            require_sealed,
            patterns,
        })
    }

    fn is_sensitive(&self, name: &str) -> bool {
        self.patterns.iter().any(|p| p.is_match(name))
    }

    /// Check one `NAME=value` pair.
    pub fn check_value(&self, name: &str, value: &str) -> Finding {
        if reference::is_reference(value) {
            return match Reference::parse(value) {
                Ok(Reference::V1(r)) => Finding::ok(name, &format!("sealed kid={}", r.kid)),
                Ok(Reference::Vault(r)) => Finding::ok(name, &format!("vault {}", r.locator())),
                Err(e) => Finding::fail(name, &format!("invalid reference: {e}")),
            };
        }
        if self.require_sealed && !value.is_empty() && self.is_sensitive(name) {
            return Finding::fail(name, "plaintext");
        }
        Finding::ok(name, "plaintext")
    }

    /// Check a dotenv file.
    pub fn check_env_file(&self, path: &Path, report: &mut Report) -> Result<()> {
        for entry in dotenv::parse_file(path)? {
            report
                .findings
                .push(self.check_value(&entry.key, &entry.value));
        }
        Ok(())
    }

    /// Check a template file: report every `{{seal:...}}` placeholder by file and line.
    pub fn check_template_text(&self, path: &Path, text: &str, report: &mut Report) {
        for placeholder in template::placeholders(text) {
            let name = format!("{}:{}", path.display(), placeholder.line);
            report
                .findings
                .push(self.check_value(&name, &placeholder.inner));
        }
    }

    /// Check a positional file.
    ///
    /// A file that holds `{{seal:...}}` placeholders is treated as a template; anything else is
    /// parsed as dotenv. Under `--require-sealed` both kinds are also scanned for raw private key
    /// blocks, which no `KEY=value` parser would ever notice.
    pub fn check_file(&self, path: &Path, report: &mut Report) -> Result<()> {
        let text = template::read_text(path)?;
        if template::placeholders(&text).is_empty() {
            for entry in dotenv::parse(&text, &path.display().to_string())? {
                report
                    .findings
                    .push(self.check_value(&entry.key, &entry.value));
            }
        } else {
            self.check_template_text(path, &text, report);
        }
        if self.require_sealed {
            for line in template::private_key_blocks(&text) {
                report.findings.push(Finding::fail(
                    &format!("{}:{}", path.display(), line),
                    "private key block",
                ));
            }
        }
        Ok(())
    }

    /// Run the whole check over the given env files and positional files.
    pub fn run(
        &self,
        env_files: &[std::path::PathBuf],
        files: &[std::path::PathBuf],
    ) -> Result<Report> {
        let mut report = Report::default();
        for path in env_files {
            self.check_env_file(path, &mut report)?;
        }
        for path in files {
            self.check_file(path, &mut report)?;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{format_v1, MIN_BLOB_LEN};

    fn checker(require_sealed: bool) -> Checker {
        Checker::new(require_sealed, &[]).unwrap()
    }

    #[test]
    fn reports_a_sealed_value_without_decrypting_it() {
        let value = format_v1("k2", &[0u8; MIN_BLOB_LEN]);
        let finding = checker(false).check_value("DB_PASSWORD", &value);
        assert!(!finding.failed);
        assert_eq!(finding.line, "OK DB_PASSWORD sealed kid=k2");
    }

    #[test]
    fn reports_a_vault_value_by_locator() {
        let finding =
            checker(false).check_value("SMTP_PASSWORD", "seal:vault:secret/smtp#password");
        assert_eq!(finding.line, "OK SMTP_PASSWORD vault secret/smtp#password");
    }

    #[test]
    fn reports_plaintext() {
        let finding = checker(false).check_value("LOG_LEVEL", "info");
        assert_eq!(finding.line, "OK LOG_LEVEL plaintext");
    }

    #[test]
    fn never_prints_the_value() {
        let finding = checker(true).check_value("DB_PASSWORD", "hunter2");
        assert!(finding.failed);
        assert!(!finding.line.contains("hunter2"));
        assert_eq!(finding.line, "FAIL DB_PASSWORD plaintext");
    }

    #[test]
    fn a_bad_reference_fails_even_without_require_sealed() {
        let finding = checker(false).check_value("DB_PASSWORD", "seal:v1:k1:!!!");
        assert!(finding.failed);
        assert!(finding
            .line
            .starts_with("FAIL DB_PASSWORD invalid reference"));
    }

    #[test]
    fn an_unknown_provider_fails() {
        assert!(checker(false).check_value("A", "seal:aws-sm:x").failed);
    }

    #[test]
    fn plaintext_passes_when_the_name_is_not_sensitive() {
        assert!(!checker(true).check_value("LOG_LEVEL", "debug").failed);
    }

    #[test]
    fn an_empty_sensitive_value_is_not_a_failure() {
        assert!(!checker(true).check_value("DB_PASSWORD", "").failed);
    }

    #[test]
    fn matches_sensitive_names_case_insensitively_and_anywhere() {
        let c = checker(true);
        for name in [
            "PASSWORD",
            "db_password",
            "MyApiKey",
            "APIKEY",
            "SERVICE_TOKEN",
            "CLIENT_SECRET",
            "PRIVATE_KEY_PEM",
            "DB_CREDENTIALS",
            "PASSWD",
        ] {
            assert!(
                c.check_value(name, "x").failed,
                "expected {name} to be treated as sensitive"
            );
        }
    }

    #[test]
    fn extra_patterns_widen_the_set() {
        let c = Checker::new(true, &["^LICENSE_".to_string()]).unwrap();
        assert!(c.check_value("LICENSE_BLOB", "x").failed);
        assert!(!c.check_value("APP_LICENSE_BLOB", "x").failed);
    }

    #[test]
    fn rejects_an_invalid_pattern() {
        assert!(Checker::new(true, &["(unclosed".to_string()]).is_err());
    }

    #[test]
    fn exit_code_is_two_only_on_failure() {
        let mut report = Report::default();
        report.findings.push(Finding::ok("A", "plaintext"));
        assert_eq!(report.exit_code(), 0);
        report.findings.push(Finding::fail("B", "plaintext"));
        assert_eq!(report.exit_code(), 2);
    }
}
