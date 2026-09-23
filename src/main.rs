//! The `sealref` command line.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use sealref::check::Checker;
use sealref::exec::{split_template_spec, ExecOptions};
use sealref::reference::Reference;
use sealref::resolve::Resolver;
use sealref::{crypto, template, utc_date_stamp, Error, Result};

#[derive(Parser)]
#[command(
    name = "sealref",
    version,
    about = "Resolve seal: secret references at process start-up",
    long_about = "SealRef resolves seal: references into plaintext for software that cannot talk \
                  to a secret manager itself. References are resolved into the environment of a \
                  command, or into a rendered configuration file, and the application never has \
                  to know where its secret came from."
)]
struct Cli {
    /// Suppress informational output on stdout. Errors and command results are still printed.
    #[arg(short = 'q', long = "quiet", global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print one new keyring line with a fresh random 256-bit key.
    Keygen {
        /// Key id for the new line. Defaults to "k" plus today's UTC date.
        #[arg(long)]
        kid: Option<String>,
    },

    /// Encrypt the plaintext on stdin into a seal:v1 reference.
    Seal {
        /// Key id to seal under. Defaults to the first key in the keyring.
        #[arg(long)]
        kid: Option<String>,

        /// Strip trailing whitespace from stdin before sealing.
        #[arg(long)]
        trim: bool,

        /// Not accepted: a plaintext argument would land in the shell history.
        #[arg(value_name = "PLAINTEXT", hide = true)]
        plaintext: Option<String>,
    },

    /// Decrypt a seal:v1 reference. Local references only.
    Unseal {
        /// The reference. Read from stdin when omitted.
        #[arg(long = "ref", value_name = "REFERENCE")]
        reference: Option<String>,

        /// Print a trailing newline after the plaintext.
        #[arg(long)]
        newline: bool,
    },

    /// Resolve any reference, dispatching to the provider that owns it.
    Resolve {
        /// The reference. Read from stdin when omitted.
        #[arg(long = "ref", value_name = "REFERENCE")]
        reference: Option<String>,

        /// Print a trailing newline after the plaintext.
        #[arg(long)]
        newline: bool,
    },

    /// Resolve the environment, render templates, then run a command.
    Exec {
        /// A dotenv file layered over the inherited environment. Repeatable, applied in order.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,

        /// Render SRC to DST before the command starts. Repeatable.
        #[arg(long = "template", value_name = "SRC:DST")]
        template: Vec<String>,

        /// The command to run, after "--".
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },

    /// Render a template, replacing every {{seal:...}} placeholder.
    Render {
        /// The template file.
        #[arg(value_name = "SRC")]
        src: PathBuf,

        /// Write to this path with owner-only permissions instead of stdout.
        #[arg(long, value_name = "DST")]
        out: Option<PathBuf>,
    },

    /// Report where each value comes from, without decrypting anything.
    Check {
        /// A dotenv file to check. Repeatable.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,

        /// Template or dotenv files to check.
        #[arg(value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Fail when a secret-looking name holds a non-empty plaintext value.
        #[arg(long = "require-sealed")]
        require_sealed: bool,

        /// An extra case-insensitive name pattern treated as secret-looking. Repeatable.
        #[arg(long = "pattern", value_name = "REGEX")]
        pattern: Vec<String>,
    },

    /// Re-encrypt every seal:v1 reference from one key id to another, in place.
    Rewrap {
        /// The key id currently protecting the references.
        #[arg(long, value_name = "KID")]
        from: String,

        /// The key id to re-encrypt under.
        #[arg(long, value_name = "KID")]
        to: String,

        /// The files to rewrite.
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("sealref: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Keygen { kid } => keygen(kid),
        Command::Seal {
            kid,
            trim,
            plaintext,
        } => seal(kid, trim, plaintext),
        Command::Unseal { reference, newline } => open(reference, newline, false),
        Command::Resolve { reference, newline } => open(reference, newline, true),
        Command::Exec {
            env_file,
            template,
            command,
        } => exec(env_file, template, command),
        Command::Render { src, out } => render(src, out),
        Command::Check {
            env_file,
            files,
            require_sealed,
            pattern,
        } => check(env_file, files, require_sealed, pattern, cli.quiet),
        Command::Rewrap { from, to, files } => rewrap(&from, &to, &files, cli.quiet),
    }
}

fn keygen(kid: Option<String>) -> Result<i32> {
    let kid = kid.unwrap_or_else(|| format!("k{}", utc_date_stamp()));
    if !sealref::reference::is_valid_kid(&kid) {
        return Err(Error::InvalidKid(kid));
    }
    let key = crypto::random_key()?;
    println!("{kid} {}", URL_SAFE_NO_PAD.encode(*key));
    Ok(0)
}

fn seal(kid: Option<String>, trim: bool, plaintext: Option<String>) -> Result<i32> {
    if plaintext.is_some() {
        return Err(Error::Msg(
            "seal does not take a plaintext argument: it would be recorded in the shell history \
             and visible in the process list. Pipe the secret on stdin instead, for example: \
             printf '%s' 'secret' | sealref seal"
                .to_string(),
        ));
    }
    let mut buffer = Zeroizing::new(Vec::new());
    std::io::stdin()
        .read_to_end(&mut buffer)
        .map_err(|e| Error::io("stdin", e))?;
    let mut bytes: &[u8] = &buffer;
    if trim {
        while let Some((last, rest)) = bytes.split_last() {
            if last.is_ascii_whitespace() {
                bytes = rest;
            } else {
                break;
            }
        }
    }
    let mut resolver = Resolver::new();
    let keyring = resolver.keyring()?;
    let key = match &kid {
        Some(kid) => keyring.get(kid)?,
        None => keyring.default_key()?,
    };
    println!("{}", crypto::seal(key.bytes(), key.kid(), bytes)?);
    Ok(0)
}

fn open(reference: Option<String>, newline: bool, any_provider: bool) -> Result<i32> {
    let text = match reference {
        Some(text) => text,
        None => {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| Error::io("stdin", e))?;
            buffer
        }
    };
    let text = text.trim();
    let parsed = Reference::parse(text)?;
    let mut resolver = Resolver::new();
    let value = if any_provider {
        resolver.resolve(&parsed)?
    } else {
        resolver.unseal(&parsed)?
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(value.as_bytes())
        .map_err(|e| Error::io("stdout", e))?;
    if newline {
        stdout
            .write_all(b"\n")
            .map_err(|e| Error::io("stdout", e))?;
    }
    stdout.flush().map_err(|e| Error::io("stdout", e))?;
    Ok(0)
}

fn exec(env_file: Vec<PathBuf>, templates: Vec<String>, command: Vec<String>) -> Result<i32> {
    let templates = templates
        .iter()
        .map(|spec| split_template_spec(spec))
        .collect::<Result<Vec<_>>>()?;
    let options = ExecOptions {
        env_files: env_file,
        templates,
        command,
    };
    let mut resolver = Resolver::new();
    sealref::exec::run(&options, &mut resolver)
}

fn render(src: PathBuf, out: Option<PathBuf>) -> Result<i32> {
    let text = template::read_text(&src)?;
    let mut resolver = Resolver::new();
    let rendered = template::render(&text, |reference, _| resolver.resolve(reference))
        .map_err(|e| e.at(src.display().to_string()))?;
    match out {
        Some(path) => sealref::exec::write_private(&path, rendered.as_bytes())?,
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(rendered.as_bytes())
                .map_err(|e| Error::io("stdout", e))?;
            stdout.flush().map_err(|e| Error::io("stdout", e))?;
        }
    }
    Ok(0)
}

fn check(
    env_file: Vec<PathBuf>,
    files: Vec<PathBuf>,
    require_sealed: bool,
    patterns: Vec<String>,
    quiet: bool,
) -> Result<i32> {
    if env_file.is_empty() && files.is_empty() {
        return Err(Error::Msg(
            "check needs at least one --env-file or one file argument".to_string(),
        ));
    }
    let checker = Checker::new(require_sealed, &patterns)?;
    let report = checker.run(&env_file, &files)?;
    for finding in &report.findings {
        if finding.failed || !quiet {
            println!("{}", finding.line);
        }
    }
    Ok(report.exit_code())
}

fn rewrap(from: &str, to: &str, files: &[PathBuf], quiet: bool) -> Result<i32> {
    let mut resolver = Resolver::new();
    let keyring = resolver.keyring()?;
    let from_key = keyring.get(from)?;
    let to_key = keyring.get(to)?;
    for path in files {
        let text = template::read_text(path)?;
        let (rewritten, count) = template::rewrap_text(&text, from, |reference| {
            let Reference::V1(v1) = reference else {
                return Err(Error::Msg(
                    "rewrap handles seal:v1 references only".to_string(),
                ));
            };
            let plaintext = crypto::open(from_key.bytes(), &v1.kid, &v1.blob)?;
            crypto::seal(to_key.bytes(), to_key.kid(), &plaintext)
        })
        .map_err(|e| e.at(path.display().to_string()))?;
        if count > 0 {
            replace_file(path, &rewritten)?;
        }
        if !quiet {
            println!("{} {count}", path.display());
        }
    }
    Ok(0)
}

/// Replace a file's contents without ever leaving a truncated file behind.
///
/// The temporary file is created beside the original so the rename stays on one filesystem, and
/// it inherits the original's permissions before it takes its place.
fn replace_file(path: &Path, contents: &str) -> Result<()> {
    let directory = path.parent().filter(|p| !p.as_os_str().is_empty());
    let name = path
        .file_name()
        .ok_or_else(|| Error::Msg(format!("{} is not a file", path.display())))?;
    let mut temporary = name.to_os_string();
    temporary.push(".sealref-tmp");
    let temporary = match directory {
        Some(directory) => directory.join(temporary),
        None => PathBuf::from(temporary),
    };

    let result = (|| -> Result<()> {
        // The temporary file is created owner-only and then widened to the original's permissions,
        // rather than created at the umask and narrowed afterwards. Rewrapped text holds
        // ciphertext rather than plaintext, but a file that is briefly world-readable while it is
        // being written is not a habit worth having in this tool. It must also not already exist:
        // a leftover from a crashed run and a planted symlink look the same from here.
        sealref::exec::create_private(&temporary, contents.as_bytes())?;
        let permissions = std::fs::metadata(path)
            .map_err(|e| Error::io(path.display().to_string(), e))?
            .permissions();
        std::fs::set_permissions(&temporary, permissions)
            .map_err(|e| Error::io(temporary.display().to_string(), e))?;
        std::fs::rename(&temporary, path).map_err(|e| Error::io(path.display().to_string(), e))
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
