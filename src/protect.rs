//! `sealref protect`: seal every plaintext secret in a dotenv file, in place.
//!
//! The decision about which values are secrets is `check`'s, reused rather than repeated, so a file
//! that `protect` has been run over passes `check --require-sealed` by construction. The rewrite
//! works on the raw text like `rewrap` does: only the value tokens that get sealed change, and
//! every other byte of the file, comments, quoting and line endings included, stays as it was.
//!
//! This module is a pure text transformation. Sealing itself is a closure supplied by the caller,
//! which is what lets the command load the keyring only when something actually needs sealing,
//! and what lets the tests here run without one.

use zeroize::Zeroizing;

use crate::check::Checker;
use crate::reference::{self, Reference};
use crate::{dotenv, template, Error, Result};

/// One rewritten dotenv file.
pub struct Protected {
    /// The new file text. It still holds any plaintext that was not sealed, so it is zeroized.
    pub text: Zeroizing<String>,
    /// One report line per entry, in file order. None of them holds a value.
    pub lines: Vec<String>,
    /// How many values were sealed. Zero means `text` is the input unchanged.
    pub sealed: usize,
}

/// A configured `protect` run.
pub struct Protector {
    checker: Checker,
    all: bool,
}

impl Protector {
    /// `all` seals every non-empty plaintext value rather than only secret-looking names. Extra
    /// patterns widen the secret-looking set exactly as `check --pattern` does.
    pub fn new(all: bool, extra_patterns: &[String]) -> Result<Self> {
        Ok(Protector {
            checker: Checker::new(true, extra_patterns)?,
            all,
        })
    }

    /// Seal the plaintext secrets in one dotenv text.
    ///
    /// `seal` turns the plaintext bytes of one value into a `seal:v1` reference. It is called only
    /// when a value needs sealing, so a file that is already protected never asks for a key. What
    /// is sealed is the parsed value, quotes removed and escapes applied, which is exactly what
    /// `exec` would have handed to the application. A quoted value keeps its quotes: a reference
    /// only holds `[A-Za-z0-9._:-]`, so it reads back the same inside either kind, and dropping
    /// the quotes would turn `KEY="v"#note` into an unquoted value that no longer parses.
    ///
    /// Any failure returns an error and no text, so a caller never writes a half-protected file.
    pub fn protect_text<F>(&self, text: &str, mut seal: F) -> Result<Protected>
    where
        F: FnMut(&[u8]) -> Result<String>,
    {
        // The dotenv parser would accept `password = hunter2` from an INI file, and a bare
        // `seal:v1:` token written there is one that nothing resolves.
        if !template::placeholders(text).is_empty() {
            return Err(Error::Msg(
                "protect handles dotenv files only; this file holds {{seal:...}} placeholders"
                    .to_string(),
            ));
        }
        // `Entry::value` is a plain `String`, so the parsed plaintext in these entries is not
        // zeroized on drop. Changing that would touch every caller of the parser for one command.
        let entries = dotenv::parse(text, "").map_err(|e| match e {
            Error::Dotenv { line, reason, .. } => Error::Msg(reason).at(format!("line {line}")),
            other => other,
        })?;

        let mut out = Zeroizing::new(String::with_capacity(text.len()));
        let mut cursor = 0usize;
        let mut lines = Vec::with_capacity(entries.len());
        let mut sealed = 0usize;
        for entry in &entries {
            let at_entry = |e: Error| e.at(&entry.key).at(format!("line {}", entry.line));
            let finding = self.checker.check_value(&entry.key, &entry.value);
            let is_reference = reference::is_reference(&entry.value);
            if finding.failed && is_reference {
                // `check` failed a value that starts with `seal:`, so it does not parse.
                let error = match Reference::parse(&entry.value) {
                    Err(e) => e,
                    Ok(_) => Error::Msg("invalid reference".to_string()),
                };
                return Err(at_entry(error));
            }
            // A failed finding that is not a reference is a non-empty secret-looking plaintext.
            let wanted = finding.failed || (self.all && !is_reference && !entry.value.is_empty());
            if !wanted {
                lines.push(finding.line);
                continue;
            }

            let sealed_reference = seal(entry.value.as_bytes()).map_err(at_entry)?;
            // Never write something that would not read back as a local reference.
            let kid = match Reference::parse(&sealed_reference) {
                Ok(Reference::V1(v1)) => v1.kid,
                _ => {
                    return Err(at_entry(Error::Msg(
                        "sealing did not produce a seal:v1 reference".to_string(),
                    )))
                }
            };
            out.push_str(&text[cursor..entry.value_span.start]);
            out.push_str(&sealed_reference);
            cursor = entry.value_span.end;
            lines.push(format!("SEALED {} kid={kid}", entry.key));
            sealed += 1;
        }
        out.push_str(&text[cursor..]);
        Ok(Protected {
            text: out,
            lines,
            sealed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::keyring::Keyring;

    const RAW: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    fn keyring() -> Keyring {
        Keyring::parse(&format!("k1 {RAW}")).unwrap()
    }

    fn protect(text: &str, all: bool, patterns: &[&str]) -> Result<Protected> {
        let ring = keyring();
        let key = ring.default_key().unwrap();
        let patterns: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
        Protector::new(all, &patterns)?.protect_text(text, |plaintext| {
            crypto::seal(key.bytes(), key.kid(), plaintext)
        })
    }

    /// Open a sealed value from the protected text, by variable name.
    fn opened(text: &str, name: &str) -> String {
        let entry = dotenv::parse(text, "out.env")
            .unwrap()
            .into_iter()
            .find(|e| e.key == name)
            .unwrap_or_else(|| panic!("{name} is still in the file"));
        let Reference::V1(v1) = Reference::parse(&entry.value).unwrap() else {
            panic!("{name} is not a seal:v1 reference");
        };
        let ring = keyring();
        let plaintext =
            crypto::open_string(ring.get(&v1.kid).unwrap().bytes(), &v1.kid, &v1.blob).unwrap();
        plaintext.to_string()
    }

    /// Every `seal:v1` token in the output, in order.
    fn tokens(text: &str) -> Vec<String> {
        template::v1_tokens(text)
            .into_iter()
            .map(|t| t.text)
            .collect()
    }

    /// The output with each sealed token replaced by `<SEALED>`, for whole-text comparison.
    fn masked(text: &str) -> String {
        let mut out = text.to_string();
        for token in tokens(text) {
            out = out.replacen(&token, "<SEALED>", 1);
        }
        out
    }

    #[test]
    fn seals_a_secret_and_leaves_every_other_byte_alone() {
        let text = "# app\nDB_HOST=db01\nDB_PASSWORD=hunter2\n\nLOG_LEVEL=info\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(protected.sealed, 1);
        assert_eq!(
            masked(&protected.text),
            "# app\nDB_HOST=db01\nDB_PASSWORD=<SEALED>\n\nLOG_LEVEL=info\n"
        );
        assert_eq!(opened(&protected.text, "DB_PASSWORD"), "hunter2");
        assert_eq!(
            protected.lines,
            vec![
                "OK DB_HOST plaintext",
                "SEALED DB_PASSWORD kid=k1",
                "OK LOG_LEVEL plaintext"
            ]
        );
    }

    #[test]
    fn all_seals_every_non_empty_plaintext() {
        let text = "DB_HOST=db01\nEMPTY=\nAPI_TOKEN=seal:vault:secret/app#token\n";
        let protected = protect(text, true, &[]).unwrap();
        assert_eq!(protected.sealed, 1);
        assert_eq!(
            masked(&protected.text),
            "DB_HOST=<SEALED>\nEMPTY=\nAPI_TOKEN=seal:vault:secret/app#token\n"
        );
        assert_eq!(opened(&protected.text, "DB_HOST"), "db01");
        assert_eq!(protected.lines[1], "OK EMPTY plaintext");
        assert_eq!(protected.lines[2], "OK API_TOKEN vault secret/app#token");
    }

    #[test]
    fn an_extra_pattern_widens_the_set() {
        let text = "LICENSE_BLOB=abc\n";
        assert_eq!(protect(text, false, &[]).unwrap().sealed, 0);
        let protected = protect(text, false, &["^LICENSE_"]).unwrap();
        assert_eq!(protected.sealed, 1);
        assert_eq!(opened(&protected.text, "LICENSE_BLOB"), "abc");
    }

    #[test]
    fn seals_the_unescaped_content_of_a_double_quoted_value_and_keeps_the_quotes() {
        let text = "DB_PASSWORD=\"a \\\"b\\\"\\tc\" # note\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(masked(&protected.text), "DB_PASSWORD=\"<SEALED>\" # note\n");
        assert_eq!(opened(&protected.text, "DB_PASSWORD"), "a \"b\"\tc");
    }

    #[test]
    fn seals_the_literal_content_of_a_single_quoted_value_and_keeps_the_quotes() {
        let text = "DB_PASSWORD='x \\n # y'\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(masked(&protected.text), "DB_PASSWORD='<SEALED>'\n");
        assert_eq!(opened(&protected.text, "DB_PASSWORD"), "x \\n # y");
    }

    #[test]
    fn a_quoted_value_with_a_comment_right_after_it_still_parses() {
        let text = "A_PASSWORD=\"v1\"#note\nB_PASSWORD='v2'#note\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(protected.sealed, 2);
        assert_eq!(
            masked(&protected.text),
            "A_PASSWORD=\"<SEALED>\"#note\nB_PASSWORD='<SEALED>'#note\n"
        );
        let entries = dotenv::parse(&protected.text, "out.env").unwrap();
        let found = tokens(&protected.text);
        assert_eq!(entries[0].value, found[0]);
        assert_eq!(entries[1].value, found[1]);
        assert_eq!(opened(&protected.text, "A_PASSWORD"), "v1");
        assert_eq!(opened(&protected.text, "B_PASSWORD"), "v2");
    }

    #[test]
    fn an_inline_comment_after_an_unquoted_value_survives() {
        let text = "DB_PASSWORD=hunter2   # rotate monthly\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(
            masked(&protected.text),
            "DB_PASSWORD=<SEALED>   # rotate monthly\n"
        );
        assert_eq!(opened(&protected.text, "DB_PASSWORD"), "hunter2");
    }

    #[test]
    fn the_export_prefix_and_spacing_survive() {
        let text = "export  DB_PASSWORD =  hunter2\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(masked(&protected.text), "export  DB_PASSWORD =  <SEALED>\n");
    }

    #[test]
    fn crlf_line_endings_survive() {
        let text = "DB_HOST=db01\r\nDB_PASSWORD=hunter2\r\nAPI_TOKEN=\"t\"\r\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(
            masked(&protected.text),
            "DB_HOST=db01\r\nDB_PASSWORD=<SEALED>\r\nAPI_TOKEN=\"<SEALED>\"\r\n"
        );
        assert_eq!(opened(&protected.text, "DB_PASSWORD"), "hunter2");
        assert_eq!(opened(&protected.text, "API_TOKEN"), "t");
    }

    #[test]
    fn an_already_sealed_value_of_every_provider_is_left_alone() {
        let sealed = reference::format_v1("k2", &[0u8; reference::MIN_BLOB_LEN]);
        let text = format!(
            "A_PASSWORD={sealed}\nB_PASSWORD=seal:vault:secret/app#password\nC_PASSWORD=seal:conjur:prod/db/password\nD_PASSWORD=seal:ccp:Safe/obj#Content\n"
        );
        let protected = protect(&text, true, &[]).unwrap();
        assert_eq!(protected.sealed, 0);
        assert_eq!(&*protected.text, &text);
        assert_eq!(
            protected.lines,
            vec![
                "OK A_PASSWORD sealed kid=k2",
                "OK B_PASSWORD vault secret/app#password",
                "OK C_PASSWORD conjur prod/db/password",
                "OK D_PASSWORD ccp Safe/obj#Content",
            ]
        );
    }

    #[test]
    fn protecting_twice_changes_nothing_the_second_time() {
        let text = "DB_PASSWORD=\"a b\"\nexport API_TOKEN=t # c\nLOG_LEVEL=info\n";
        let first = protect(text, false, &[]).unwrap();
        assert_eq!(first.sealed, 2);
        let second = protect(&first.text, false, &[]).unwrap();
        assert_eq!(second.sealed, 0);
        assert_eq!(&*second.text, &*first.text);
    }

    #[test]
    fn a_malformed_reference_aborts_with_the_line_and_the_name() {
        let text = "DB_PASSWORD=hunter2\nAPI_TOKEN=seal:v1:k1:!!!\n";
        let mut calls = 0;
        let result = Protector::new(false, &[]).unwrap().protect_text(text, |_| {
            calls += 1;
            Ok(reference::format_v1("k1", &[0u8; reference::MIN_BLOB_LEN]))
        });
        let Err(err) = result else {
            panic!("a malformed reference must abort the whole file");
        };
        let message = err.to_string();
        assert!(message.starts_with("line 2: API_TOKEN: "), "{message}");
        assert!(message.contains("base64url"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
        assert_eq!(
            calls, 1,
            "the value before the malformed one is sealed first"
        );
    }

    #[test]
    fn an_empty_sensitive_value_is_not_sealed() {
        let text = "DB_PASSWORD=\nAPI_TOKEN=\"\"\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(protected.sealed, 0);
        assert_eq!(&*protected.text, text);
        assert_eq!(protected.lines[0], "OK DB_PASSWORD plaintext");
    }

    #[test]
    fn a_comment_marker_right_after_the_equals_sign_is_sealed_literally() {
        // The dotenv parser reads `A= # note` as the value "# note", and that is what `exec`
        // would deliver, so that is what is sealed.
        let text = "DB_PASSWORD= # note\n";
        let protected = protect(text, false, &[]).unwrap();
        assert_eq!(protected.sealed, 1);
        assert_eq!(masked(&protected.text), "DB_PASSWORD= <SEALED>\n");
        assert_eq!(opened(&protected.text, "DB_PASSWORD"), "# note");
    }

    #[test]
    fn report_lines_never_hold_the_plaintext() {
        let text = "DB_PASSWORD=hunter2\nLOG_LEVEL=verbose-value\n";
        let protected = protect(text, true, &[]).unwrap();
        for line in &protected.lines {
            assert!(!line.contains("hunter2"), "{line}");
            assert!(!line.contains("verbose-value"), "{line}");
        }
    }

    #[test]
    fn refuses_a_file_with_placeholders() {
        let text = "[db]\npassword = hunter2\ntoken = {{seal:vault:secret/app#token}}\n";
        let err = protect(text, false, &[])
            .err()
            .expect("placeholders are refused");
        assert!(err.to_string().contains("dotenv files only"));
    }

    #[test]
    fn a_dotenv_syntax_error_names_the_line_without_a_path() {
        let err = protect("A=1\nJUST_A_NAME\n", false, &[])
            .err()
            .expect("a syntax error is reported");
        assert_eq!(err.to_string(), "line 2: expected KEY=value");
    }

    #[test]
    fn a_sealing_failure_names_the_line_and_the_variable() {
        let result = Protector::new(false, &[])
            .unwrap()
            .protect_text("LOG_LEVEL=info\nDB_PASSWORD=hunter2\n", |_| {
                Err(Error::NoKeySource)
            });
        let message = result.err().expect("the failure propagates").to_string();
        assert!(
            message.starts_with("line 2: DB_PASSWORD: no key source"),
            "{message}"
        );
        assert!(!message.contains("hunter2"));
    }

    #[test]
    fn nothing_to_seal_never_calls_the_sealer() {
        let text = "LOG_LEVEL=info\nDB_PASSWORD=seal:vault:secret/app#password\n";
        let protected = Protector::new(false, &[])
            .unwrap()
            .protect_text(text, |_| panic!("no value needs sealing"))
            .unwrap();
        assert_eq!(protected.sealed, 0);
    }
}
