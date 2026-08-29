//! A small dotenv parser.
//!
//! Supported: `KEY=value`, an optional `export ` prefix, `#` comments, and single- or
//! double-quoted values. Not supported, on purpose: variable interpolation and shell expansion.
//! Interpolation would introduce escaping and injection questions that a secret loader should not
//! have to answer.
//!
//! Parsing keeps the source line number of every entry so a failure can point at a line, and it
//! never rewrites the file: `rewrap` edits the original text in place, so lines this parser does
//! not care about stay byte-identical.

use std::path::Path;

use crate::{Error, Result};

/// One `KEY=value` assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The variable name.
    pub key: String,
    /// The value with quotes removed and escapes applied.
    pub value: String,
    /// 1-based source line.
    pub line: usize,
}

/// Parse dotenv text. `path` is used only for error messages.
pub fn parse(text: &str, path: &str) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let bad = |reason: &str| Error::Dotenv {
            path: path.to_string(),
            line,
            reason: reason.to_string(),
        };
        let stripped = raw.strip_suffix('\r').unwrap_or(raw);
        let content = stripped.trim_start();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let content = match content.strip_prefix("export") {
            Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
            _ => content,
        };
        let (key, rest) = content
            .split_once('=')
            .ok_or_else(|| bad("expected KEY=value"))?;
        let key = key.trim_end();
        if key.is_empty() {
            return Err(bad("the variable name is empty"));
        }
        if key.chars().any(char::is_whitespace) {
            return Err(bad("the variable name contains whitespace"));
        }
        let value = parse_value(rest, &bad)?;
        entries.push(Entry {
            key: key.to_string(),
            value,
            line,
        });
    }
    Ok(entries)
}

/// Read and parse a dotenv file.
pub fn parse_file(path: &Path) -> Result<Vec<Entry>> {
    let text =
        std::fs::read_to_string(path).map_err(|e| Error::io(path.display().to_string(), e))?;
    parse(&text, &path.display().to_string())
}

fn parse_value(rest: &str, bad: &impl Fn(&str) -> Error) -> Result<String> {
    let rest = rest.trim_start();
    let mut chars = rest.chars();
    match chars.next() {
        Some('"') => {
            let (value, remainder) = read_double_quoted(chars.as_str(), bad)?;
            check_trailer(remainder, bad)?;
            Ok(value)
        }
        Some('\'') => {
            let body = chars.as_str();
            let end = body.find('\'').ok_or_else(|| bad("unterminated \" ' \""))?;
            check_trailer(&body[end + 1..], bad)?;
            Ok(body[..end].to_string())
        }
        _ => Ok(strip_inline_comment(rest).trim_end().to_string()),
    }
}

fn read_double_quoted<'a>(
    body: &'a str,
    bad: &impl Fn(&str) -> Error,
) -> Result<(String, &'a str)> {
    let mut value = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Ok((value, chars.as_str())),
            '\\' => match chars.next() {
                Some('n') => value.push('\n'),
                Some('r') => value.push('\r'),
                Some('t') => value.push('\t'),
                Some('0') => value.push('\0'),
                Some(other) => value.push(other),
                None => return Err(bad("a backslash ends the line")),
            },
            other => value.push(other),
        }
    }
    Err(bad("unterminated double quote"))
}

fn check_trailer(remainder: &str, bad: &impl Fn(&str) -> Error) -> Result<()> {
    let trailer = remainder.trim();
    if trailer.is_empty() || trailer.starts_with('#') {
        Ok(())
    } else {
        Err(bad("unexpected text after the closing quote"))
    }
}

/// Strip a trailing `# comment` from an unquoted value.
///
/// A `#` only starts a comment when whitespace precedes it, so
/// `seal:vault:secret/app#password` keeps its field.
fn strip_inline_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'#' && i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return &value[..i];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> Vec<Entry> {
        parse(text, "test.env").unwrap()
    }

    fn value_of(text: &str) -> String {
        let entries = parsed(text);
        assert_eq!(entries.len(), 1, "expected exactly one entry");
        entries[0].value.clone()
    }

    #[test]
    fn parses_a_plain_assignment() {
        let entries = parsed("DB_HOST=db01\n");
        assert_eq!(entries[0].key, "DB_HOST");
        assert_eq!(entries[0].value, "db01");
        assert_eq!(entries[0].line, 1);
    }

    #[test]
    fn skips_blank_lines_and_comments() {
        let entries = parsed("# header\n\n  \nA=1\n\t# indented comment\nB=2\n");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].line, 6);
    }

    #[test]
    fn accepts_the_export_prefix() {
        let entries = parsed("export A=1\n");
        assert_eq!(entries[0].key, "A");
        assert_eq!(entries[0].value, "1");
    }

    #[test]
    fn does_not_treat_exported_as_a_prefix() {
        let entries = parsed("exportA=1\n");
        assert_eq!(entries[0].key, "exportA");
    }

    #[test]
    fn keeps_equals_signs_inside_the_value() {
        assert_eq!(value_of("A=b=c=d\n"), "b=c=d");
    }

    #[test]
    fn parses_an_empty_value() {
        assert_eq!(value_of("A=\n"), "");
        assert_eq!(value_of("A=\"\"\n"), "");
        assert_eq!(value_of("A=''\n"), "");
    }

    #[test]
    fn double_quotes_apply_escapes() {
        assert_eq!(
            value_of("A=\"line1\\nline2\\t\\\"q\\\"\"\n"),
            "line1\nline2\t\"q\""
        );
    }

    #[test]
    fn single_quotes_are_literal() {
        assert_eq!(
            value_of("A='no \\n escape # or comment'\n"),
            "no \\n escape # or comment"
        );
    }

    #[test]
    fn quotes_preserve_surrounding_spaces() {
        assert_eq!(value_of("A=\"  padded  \"\n"), "  padded  ");
    }

    #[test]
    fn unquoted_values_lose_trailing_whitespace() {
        assert_eq!(value_of("A=  value   \n"), "value");
    }

    #[test]
    fn strips_an_inline_comment_after_whitespace() {
        assert_eq!(value_of("A=value # trailing note\n"), "value");
        assert_eq!(value_of("A=value#notacomment\n"), "value#notacomment");
    }

    #[test]
    fn keeps_the_field_of_a_vault_reference() {
        assert_eq!(
            value_of("A=seal:vault:secret/myapp/prod#password\n"),
            "seal:vault:secret/myapp/prod#password"
        );
    }

    #[test]
    fn allows_a_comment_after_a_quoted_value() {
        assert_eq!(value_of("A=\"v\" # note\n"), "v");
    }

    #[test]
    fn handles_crlf_line_endings() {
        assert_eq!(value_of("A=value\r\n"), "value");
    }

    #[test]
    fn rejects_a_line_without_equals() {
        assert!(parse("JUST_A_NAME\n", "test.env").is_err());
    }

    #[test]
    fn rejects_an_empty_name() {
        assert!(parse("=value\n", "test.env").is_err());
    }

    #[test]
    fn rejects_a_name_with_whitespace() {
        assert!(parse("A B=value\n", "test.env").is_err());
    }

    #[test]
    fn rejects_an_unterminated_quote() {
        assert!(parse("A=\"open\n", "test.env").is_err());
        assert!(parse("A='open\n", "test.env").is_err());
    }

    #[test]
    fn rejects_text_after_a_closing_quote() {
        assert!(parse("A=\"v\" junk\n", "test.env").is_err());
    }
}
