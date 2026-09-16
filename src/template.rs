//! Template rendering and in-place reference rewriting.
//!
//! A template is any text file that contains `{{seal:...}}` placeholders. Everything outside a
//! placeholder is copied byte for byte, so the same code renders an INI file, a YAML file, or an
//! XML file without knowing anything about them.
//!
//! `rewrap` works on the same raw text rather than on a parsed model, which is what makes
//! "every other byte of the file is unchanged" true by construction instead of by care.

use zeroize::Zeroizing;

use crate::reference::{self, Reference};
use crate::{Error, Result};

const OPEN: &str = "{{";
const CLOSE: &str = "}}";

/// A `{{seal:...}}` occurrence in a template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    /// Byte range of the whole `{{...}}` occurrence.
    pub start: usize,
    /// Exclusive end of the occurrence.
    pub end: usize,
    /// The reference text between the braces, trimmed.
    pub inner: String,
    /// 1-based source line of the opening brace.
    pub line: usize,
}

/// Find every `{{seal:...}}` occurrence, in source order.
///
/// `{{` groups whose contents do not start with `seal:` are left alone: a template may well
/// contain another tool's braces.
pub fn placeholders(text: &str) -> Vec<Placeholder> {
    let mut found = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = text[cursor..].find(OPEN) {
        let start = cursor + rel;
        let body_start = start + OPEN.len();
        let Some(rel_end) = text[body_start..].find(CLOSE) else {
            break;
        };
        let body_end = body_start + rel_end;
        let inner = text[body_start..body_end].trim();
        if reference::is_reference(inner) {
            found.push(Placeholder {
                start,
                end: body_end + CLOSE.len(),
                inner: inner.to_string(),
                line: line_of(text, start),
            });
            cursor = body_end + CLOSE.len();
        } else {
            cursor = body_start;
        }
    }
    found
}

/// 1-based line number of a byte offset.
pub fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

/// Render a template, replacing every `{{seal:...}}` with the value `resolve` returns.
///
/// A single failure aborts the whole render, so a caller never writes a half-resolved file.
pub fn render<F>(text: &str, mut resolve: F) -> Result<Zeroizing<String>>
where
    F: FnMut(&Reference, &str) -> Result<Zeroizing<String>>,
{
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    let mut cursor = 0usize;
    for placeholder in placeholders(text) {
        let parsed = Reference::parse(&placeholder.inner)
            .map_err(|e| e.at(format!("line {}", placeholder.line)))?;
        let value = resolve(&parsed, &placeholder.inner)?;
        out.push_str(&text[cursor..placeholder.start]);
        out.push_str(&value);
        cursor = placeholder.end;
    }
    out.push_str(&text[cursor..]);
    Ok(out)
}

/// A `seal:v1:<kid>:<ciphertext>` token found in arbitrary text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1Token {
    /// Byte range of the token.
    pub start: usize,
    /// Exclusive end of the token.
    pub end: usize,
    /// The key id the token names.
    pub kid: String,
    /// The whole token text.
    pub text: String,
}

/// Find every `seal:v1:` token in raw text, wherever it sits.
///
/// The scan is character-class based rather than line based, so a token inside quotes, inside a
/// `{{ }}` placeholder, or in the middle of a JSON blob is found the same way.
pub fn v1_tokens(text: &str) -> Vec<V1Token> {
    const MARKER: &str = "seal:v1:";
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = text[cursor..].find(MARKER) {
        let start = cursor + rel;
        let mut i = start + MARKER.len();
        let kid_start = i;
        while i < bytes.len() && is_kid_byte(bytes[i]) {
            i += 1;
        }
        let kid_end = i;
        if kid_end == kid_start || i >= bytes.len() || bytes[i] != b':' {
            cursor = start + MARKER.len();
            continue;
        }
        i += 1;
        let blob_start = i;
        while i < bytes.len() && is_base64url_byte(bytes[i]) {
            i += 1;
        }
        if i == blob_start {
            cursor = start + MARKER.len();
            continue;
        }
        found.push(V1Token {
            start,
            end: i,
            kid: text[kid_start..kid_end].to_string(),
            text: text[start..i].to_string(),
        });
        cursor = i;
    }
    found
}

fn is_kid_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
}

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Re-encrypt every `seal:v1:<from>:...` token under `to`, leaving all other bytes untouched.
///
/// Returns the new text and the number of tokens rewritten.
pub fn rewrap_text<F>(text: &str, from: &str, mut rewrap: F) -> Result<(String, usize)>
where
    F: FnMut(&Reference) -> Result<String>,
{
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut count = 0usize;
    for token in v1_tokens(text) {
        if token.kid != from {
            continue;
        }
        let parsed = Reference::parse(&token.text)
            .map_err(|e| e.at(format!("line {}", line_of(text, token.start))))?;
        let replacement = rewrap(&parsed)?;
        out.push_str(&text[cursor..token.start]);
        out.push_str(&replacement);
        cursor = token.end;
        count += 1;
    }
    out.push_str(&text[cursor..]);
    Ok((out, count))
}

/// Line numbers of raw `-----BEGIN ... PRIVATE KEY-----` markers.
///
/// A private key pasted into a config file is the failure mode this tool exists to catch, and it
/// never looks like a `KEY=value` assignment, so it needs its own scan.
pub fn private_key_blocks(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let line = line.trim();
            line.starts_with("-----BEGIN") && line.contains("PRIVATE KEY-----")
        })
        .map(|(index, _)| index + 1)
        .collect()
}

/// Read a file as text, with the path in any error.
pub fn read_text(path: &std::path::Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::io(path.display().to_string(), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{format_v1, MIN_BLOB_LEN};

    fn sample() -> String {
        format_v1("k1", &[3u8; MIN_BLOB_LEN])
    }

    #[test]
    fn finds_placeholders_and_ignores_other_braces() {
        let token = sample();
        let text =
            format!("a={{{{{token}}}}}\nb={{{{ seal:vault:secret/x#f }}}}\nc={{{{ other }}}}\n");
        let found = placeholders(&text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].inner, token);
        assert_eq!(found[0].line, 1);
        assert_eq!(found[1].inner, "seal:vault:secret/x#f");
        assert_eq!(found[1].line, 2);
    }

    #[test]
    fn ignores_an_unterminated_placeholder() {
        assert!(placeholders(&format!("a={{{{{}\n", sample())).is_empty());
    }

    #[test]
    fn renders_multiple_references_and_leaves_other_text_alone() {
        let token = sample();
        let text = format!("[db]\nuser = app\npassword = {{{{{token}}}}}\ntoken = {{{{ seal:vault:secret/x#f }}}}\n# {{{{ not-a-reference }}}}\n");
        let text = text.as_str();
        let rendered = render(text, |r, _| match r {
            Reference::V1(_) => Ok(Zeroizing::new("first".to_string())),
            _ => Ok(Zeroizing::new("second".to_string())),
        })
        .unwrap();
        assert_eq!(
            &*rendered,
            "[db]\nuser = app\npassword = first\ntoken = second\n# {{ not-a-reference }}\n"
        );
    }

    #[test]
    fn render_fails_whole_when_one_reference_fails() {
        let token = sample();
        let text = format!("a={{{{{token}}}}}\nb={{{{{token}}}}}\n");
        let text = text.as_str();
        let mut calls = 0;
        let err = render(text, |_, _| {
            calls += 1;
            Err(Error::Msg("nope".to_string()))
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn render_rejects_an_unknown_provider() {
        let err = render("a={{seal:nope:x}}\n", |_, _| {
            Ok(Zeroizing::new(String::new()))
        })
        .unwrap_err();
        assert!(err.to_string().contains("unknown reference provider"));
    }

    #[test]
    fn render_leaves_text_without_placeholders_identical() {
        let text = "nothing to do here\n";
        let rendered = render(text, |_, _| Ok(Zeroizing::new("x".to_string()))).unwrap();
        assert_eq!(&*rendered, text);
    }

    #[test]
    fn finds_v1_tokens_in_quotes_and_placeholders() {
        let token = sample();
        let text = format!("A={token}\nB=\"{token}\"\nC={{{{{token}}}}}\nD=plain\n");
        let found = v1_tokens(&text);
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|t| t.kid == "k1" && t.text == token));
    }

    #[test]
    fn ignores_a_malformed_token_marker() {
        assert!(v1_tokens("seal:v1:\nseal:v1:k1:\n").is_empty());
    }

    #[test]
    fn rewrap_only_touches_the_named_key_id() {
        let from = format_v1("k1", &[1u8; MIN_BLOB_LEN]);
        let other = format_v1("k2", &[2u8; MIN_BLOB_LEN]);
        let text = format!("# comment\nA={from}\nB={other}\nC=plain\n");
        let (out, count) = rewrap_text(&text, "k1", |_| Ok("REPLACED".to_string())).unwrap();
        assert_eq!(count, 1);
        assert_eq!(out, format!("# comment\nA=REPLACED\nB={other}\nC=plain\n"));
    }

    #[test]
    fn rewrap_reports_zero_when_nothing_matches() {
        let text = "A=plain\n";
        let (out, count) = rewrap_text(text, "k1", |_| Ok("x".to_string())).unwrap();
        assert_eq!(count, 0);
        assert_eq!(out, text);
    }

    #[test]
    fn finds_private_key_blocks() {
        let text = "a=1\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(private_key_blocks(text), vec![2]);
        assert!(private_key_blocks("-----BEGIN CERTIFICATE-----\n").is_empty());
    }
}
