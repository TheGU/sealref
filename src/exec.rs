//! Build a resolved environment, render any templates, then hand the process over.
//!
//! On unix the command replaces this process with `execvp`, so the container keeps one PID and
//! normal SIGTERM handling. On Windows there is no `exec`, so the child is spawned and its exit
//! code is passed through.
//!
//! Everything that can fail is done before the command starts: every reference is resolved and
//! every template is rendered in memory first. A run either starts the command with a complete
//! environment or it starts nothing at all.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::reference::{self, Reference};
use crate::resolve::Resolver;
use crate::{dotenv, template, Error, Result};

/// What to run and what to give it.
#[derive(Debug, Default, Clone)]
pub struct ExecOptions {
    /// Dotenv files layered over the inherited environment, in order.
    pub env_files: Vec<PathBuf>,
    /// `(source, destination)` template pairs rendered before the command starts.
    pub templates: Vec<(PathBuf, PathBuf)>,
    /// The command and its arguments.
    pub command: Vec<String>,
}

/// Split a `--template SRC:DST` argument.
///
/// A Windows drive letter is not a separator, so `C:\in.tmpl:C:\out.ini` splits where a human
/// would split it.
pub fn split_template_spec(spec: &str) -> Result<(PathBuf, PathBuf)> {
    let bytes = spec.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b':' && !is_drive_colon(bytes, index) {
            let (src, dst) = spec.split_at(index);
            let dst = &dst[1..];
            if src.is_empty() || dst.is_empty() {
                break;
            }
            return Ok((PathBuf::from(src), PathBuf::from(dst)));
        }
        index += 1;
    }
    Err(Error::Msg(format!(
        "--template expects <source>:<destination>, got \"{spec}\""
    )))
}

fn is_drive_colon(bytes: &[u8], index: usize) -> bool {
    index == 1 && bytes[0].is_ascii_alphabetic() && matches!(bytes.get(2), Some(b'\\') | Some(b'/'))
}

/// Layer the inherited environment and the env files, then resolve every `seal:` value.
pub fn build_env(
    env_files: &[PathBuf],
    resolver: &mut Resolver,
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let mut env: BTreeMap<String, Zeroizing<String>> = std::env::vars()
        .map(|(k, v)| (k, Zeroizing::new(v)))
        .collect();
    for path in env_files {
        for entry in dotenv::parse_file(path)? {
            env.insert(entry.key, Zeroizing::new(entry.value));
        }
    }
    for (name, value) in env.iter_mut() {
        if !reference::is_reference(value) {
            continue;
        }
        let parsed = Reference::parse(value).map_err(|e| e.at(name.clone()))?;
        *value = resolver.resolve(&parsed).map_err(|e| e.at(name.clone()))?;
    }
    Ok(env)
}

/// Render every template into memory, then write each one with owner-only permissions.
pub fn render_templates(
    templates: &[(PathBuf, PathBuf)],
    resolver: &mut Resolver,
) -> Result<Vec<PathBuf>> {
    let mut rendered: Vec<(&PathBuf, Zeroizing<String>)> = Vec::with_capacity(templates.len());
    for (src, dst) in templates {
        let text = template::read_text(src)?;
        let out = template::render(&text, |reference, _| resolver.resolve(reference))
            .map_err(|e| e.at(src.display().to_string()))?;
        rendered.push((dst, out));
    }
    let mut written = Vec::with_capacity(rendered.len());
    for (dst, text) in rendered {
        write_private(dst, text.as_bytes())?;
        written.push(dst.clone());
    }
    Ok(written)
}

/// Write a file that only its owner can read.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| Error::io(path.display().to_string(), e))?;
    file.write_all(bytes)
        .map_err(|e| Error::io(path.display().to_string(), e))?;
    file.flush()
        .map_err(|e| Error::io(path.display().to_string(), e))?;
    Ok(())
}

/// Resolve everything, then run the command.
///
/// On unix this never returns on success. On Windows it returns the child's exit code.
pub fn run(options: &ExecOptions, resolver: &mut Resolver) -> Result<i32> {
    let (program, args) = options
        .command
        .split_first()
        .ok_or_else(|| Error::Msg("no command given after \"--\"".to_string()))?;
    let env = build_env(&options.env_files, resolver)?;
    render_templates(&options.templates, resolver)?;
    spawn(program, args, &env)
}

#[cfg(unix)]
fn spawn(program: &str, args: &[String], env: &BTreeMap<String, Zeroizing<String>>) -> Result<i32> {
    use std::os::unix::process::CommandExt;

    let mut command = std::process::Command::new(program);
    command.args(args).env_clear();
    for (key, value) in env {
        command.env(key, value.as_str());
    }
    // exec replaces this process, so anything after it is a failure.
    let error = command.exec();
    Err(Error::io(format!("cannot exec {program}"), error))
}

#[cfg(not(unix))]
fn spawn(program: &str, args: &[String], env: &BTreeMap<String, Zeroizing<String>>) -> Result<i32> {
    let mut command = std::process::Command::new(program);
    command.args(args).env_clear();
    for (key, value) in env {
        command.env(key, value.as_str());
    }
    let status = command
        .status()
        .map_err(|e| Error::io(format!("cannot run {program}"), e))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_plain_template_spec() {
        let (src, dst) = split_template_spec("config.ini.tmpl:/run/sealref/config.ini").unwrap();
        assert_eq!(src, PathBuf::from("config.ini.tmpl"));
        assert_eq!(dst, PathBuf::from("/run/sealref/config.ini"));
    }

    #[test]
    fn splits_a_spec_with_windows_drive_letters() {
        let (src, dst) = split_template_spec(r"C:\in\app.tmpl:D:\out\app.ini").unwrap();
        assert_eq!(src, PathBuf::from(r"C:\in\app.tmpl"));
        assert_eq!(dst, PathBuf::from(r"D:\out\app.ini"));
    }

    #[test]
    fn rejects_a_spec_without_a_separator() {
        assert!(split_template_spec("only-one-path").is_err());
        assert!(split_template_spec(":/dst").is_err());
        assert!(split_template_spec("src:").is_err());
    }
}
