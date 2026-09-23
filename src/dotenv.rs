//! A small dotenv parser.
//!
//! Supported: `KEY=value`, an optional `export ` prefix, `#` comments, and single- or
//! double-quoted values. Not supported, on purpose: variable interpolation and shell expansion.
//! Interpolation would introduce escaping and injection questions that a secret loader should not
//! have to answer.
//!
//! Parsing keeps the source line number of every entry so a failure can point at a line, and it
//! never rewrites the file: `rewrap` edits the original text in place, so lines this parser does
//! not care about stay byte-identical. `protect` edits the original text too, which is why every
//! entry also records where its value sits in that text.

use std::ops::Range;
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
    /// Byte range of the value in the whole source text: the unquoted token without surrounding
    /// whitespace or an inline comment, or the text between the quotes of a quoted value. An
    /// empty unquoted value has an empty range where the value would start.
    pub value_span: Range<usize>,
}

/// Parse dotenv text. `path` is used only for error messages.
pub fn parse(text: &str, path: &str) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut next_start = 0usize;
    // `split_inclusive` rather than `lines`, so the offset of every line in the whole text is
    // known. Stripping one `\n`, and one `\r` only when a `\n` was stripped, is what `lines` does.
    for (index, piece) in text.split_inclusive('\n').enumerate() {
        let line = index + 1;
        let line_start = next_start;
        next_start += piece.len();
        let raw = match piece.strip_suffix('\n') {
            Some(without_newline) => without_newline
                .strip_suffix('\r')
                .unwrap_or(without_newline),
            None => piece,
        };
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
        // `rest` is a suffix of `stripped`, and `stripped` starts at `line_start`.
        let rest_start = line_start + stripped.len() - rest.len();
        let (value, span) = parse_value(rest, &bad)?;
        entries.push(Entry {
            key: key.to_string(),
            value,
            line,
            value_span: rest_start + span.start..rest_start + span.end,
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

/// Parse the text after `=`, returning the value and its span relative to `rest`.
fn parse_value(rest: &str, bad: &impl Fn(&str) -> Error) -> Result<(String, Range<usize>)> {
    let trimmed = rest.trim_start();
    let start = rest.len() - trimmed.len();
    let mut chars = trimmed.chars();
    match chars.next() {
        Some('"') => {
            let body = chars.as_str();
            let (value, remainder) = read_double_quoted(body, bad)?;
            check_trailer(remainder, bad)?;
            // `remainder` starts right after the closing quote.
            let inner = body.len() - remainder.len() - 1;
            Ok((value, start + 1..start + 1 + inner))
        }
        Some('\'') => {
            let body = chars.as_str();
            let end = body.find('\'').ok_or_else(|| bad("unterminated \" ' \""))?;
            check_trailer(&body[end + 1..], bad)?;
            Ok((body[..end].to_string(), start + 1..start + 1 + end))
        }
        _ => {
            let token = strip_inline_comment(trimmed).trim_end();
            Ok((token.to_string(), start..start + token.len()))
        }
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

    /// The text the span of the only entry covers.
    fn spanned(text: &str) -> &str {
        let entries = parsed(text);
        assert_eq!(entries.len(), 1, "expected exactly one entry");
        &text[entries[0].value_span.clone()]
    }

    #[test]
    fn spans_a_plain_value() {
        assert_eq!(spanned("A=value\n"), "value");
        assert_eq!(parsed("A=value\n")[0].value_span, 2..7);
    }

    #[test]
    fn spans_the_text_between_double_quotes() {
        assert_eq!(spanned("A=\"a \\\"b\\\" c\"\n"), "a \\\"b\\\" c");
        assert_eq!(spanned("A=\"\"\n"), "");
        assert_eq!(parsed("A=\"\"\n")[0].value_span, 3..3);
    }

    #[test]
    fn spans_the_text_between_single_quotes() {
        assert_eq!(spanned("A='x # y'\n"), "x # y");
        assert_eq!(parsed("A=''\n")[0].value_span, 3..3);
    }

    #[test]
    fn spans_a_padded_value_without_its_padding() {
        assert_eq!(spanned("A  =   value   \n"), "value");
        assert_eq!(spanned("A = \"  padded  \" \n"), "  padded  ");
    }

    #[test]
    fn spans_stop_before_an_inline_comment() {
        assert_eq!(spanned("A=value # note\n"), "value");
        assert_eq!(spanned("A=value#kept\n"), "value#kept");
        assert_eq!(spanned("A=\"v\" # note\n"), "v");
        assert_eq!(spanned("A=\"v\"#note\n"), "v");
        assert_eq!(spanned("A='v'#note\n"), "v");
    }

    #[test]
    fn spans_a_value_after_the_export_prefix() {
        assert_eq!(spanned("export A=value\n"), "value");
        assert_eq!(parsed("export A=value\n")[0].value_span, 9..14);
    }

    #[test]
    fn spans_an_empty_value_where_the_value_would_start() {
        assert_eq!(parsed("A=\n")[0].value_span, 2..2);
        assert_eq!(parsed("A=   \n")[0].value_span, 5..5);
        assert_eq!(parsed("A=")[0].value_span, 2..2);
    }

    #[test]
    fn spans_exclude_crlf_line_endings() {
        assert_eq!(spanned("A=value\r\n"), "value");
        assert_eq!(spanned("A=\"v\"\r\n"), "v");
    }

    #[test]
    fn a_doubled_carriage_return_is_stripped_as_before() {
        // `lines` strips "\r\n" and the parser then strips one more "\r", so the value is "1".
        let entries = parsed("A=1\r\r\n");
        assert_eq!(entries[0].value, "1");
        assert_eq!(entries[0].value_span, 2..3);
    }

    #[test]
    fn spans_are_offsets_in_the_whole_text() {
        let text = "# header\r\nA=1\n\nexport  B = 'two' # note\r\nC=\"three\"";
        let entries = parsed(text);
        assert_eq!(entries.len(), 3);
        assert_eq!(&text[entries[0].value_span.clone()], "1");
        assert_eq!(&text[entries[1].value_span.clone()], "two");
        assert_eq!(&text[entries[2].value_span.clone()], "three");
        assert_eq!(entries[1].line, 4);
        assert_eq!(entries[2].value_span, text.len() - 6..text.len() - 1);
    }

    #[test]
    fn a_comment_marker_right_after_the_equals_sign_is_part_of_the_value() {
        // Leading whitespace is trimmed first, so the `#` sits at index 0 and is not a comment.
        assert_eq!(value_of("A= # note\n"), "# note");
        assert_eq!(spanned("A= # note\n"), "# note");
    }
}
