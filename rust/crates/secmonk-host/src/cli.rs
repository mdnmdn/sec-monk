//! The command line shared by `secmonk-server`, `secmonk-headless` and `secmonk-desktop` (server mode).
//!
//! ```text
//! secmonk-server [serve] [OPTIONS]
//! secmonk-server apikey create --name N --scope S [--scope S ...] [--expires-days D]
//! secmonk-server apikey list
//! secmonk-server apikey revoke <id|name>
//! secmonk-server config show
//! secmonk-server version | help
//! ```
//!
//! Global options: `--config FILE`, `--set key=value` (repeatable), and conveniences that are translated into
//! `--set` entries in the order given (so precedence is uniform: file, environment, then the command line, the
//! last one winning): `--data-dir DIR`, `--listen ADDR`, `--tls-cert FILE`, `--tls-key FILE`, `--allow-actions`,
//! `--no-actions`, `--auth MODE`. Exit codes: 0 ok, 1 runtime error, 2 usage error.
//!
//! [`parse`] is pure; [`run`] executes. The `apikey` and `config` commands read the configuration and the keys
//! file only: they never start the engine, uv or Python.

use std::path::PathBuf;
use std::sync::Arc;

use secmonk_auth::Scopes;
use secmonk_config::{Config, LoadOptions, load, parse_set};

use crate::apikeys;
use crate::serve::{ServeOptions, serve_blocking};

/// Program name used in messages when the caller does not give one.
pub const DEFAULT_PROG: &str = "secmonk-server";

/// What to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the server (the default of `secmonk-server`).
    Serve,
    /// `apikey create`: print a new key once.
    ApiKeyCreate {
        name: String,
        scopes: Vec<String>,
        expires_days: Option<u64>,
    },
    /// `apikey list`.
    ApiKeyList,
    /// `apikey revoke <id|name>`.
    ApiKeyRevoke { target: String },
    /// `config show`: the effective configuration as TOML.
    ConfigShow,
    /// `version`.
    Version,
    /// `help`.
    Help,
}

/// A parsed command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cli {
    /// `--config FILE`.
    pub config: Option<PathBuf>,
    /// `--set` entries, the convenience flags included, in command-line order.
    pub overrides: Vec<String>,
    /// Defaults of the running application, below the config file ([`secmonk_config::LoadOptions::app_defaults`]):
    /// a bundled desktop app points `[modules] python_project` at its own copy. Not set by [`parse`].
    pub app_defaults: Vec<String>,
    /// The subcommand (or `--serve`); `None` when none was given: `secmonk-server` serves, the desktop app opens
    /// its window.
    pub command: Option<Command>,
}

impl Cli {
    /// The configuration inputs: the real environment, `--config` and the overrides.
    pub fn load_options(&self) -> LoadOptions {
        let mut o = LoadOptions::from_env(self.config.clone());
        o.cli_overrides = self.overrides.clone();
        o.app_defaults = self.app_defaults.clone();
        o
    }

    /// Load the configuration.
    pub fn load_config(&self) -> Result<Config, String> {
        load(&self.load_options()).map_err(|e| e.to_string())
    }
}

/// The usage text for `prog`.
pub fn usage(prog: &str) -> String {
    format!(
        "\
usage: {prog} [serve] [OPTIONS]
       {prog} apikey create --name NAME --scope SCOPE [--scope SCOPE ...] [--expires-days DAYS]
       {prog} apikey list
       {prog} apikey revoke <ID|NAME>
       {prog} config show
       {prog} version | help

commands:
  serve                  run the API and the UI over HTTP(S) (the default)
  apikey create          create an API key; the key is printed once, on stdout
  apikey list            id, name, scopes, created, expires, revoked (never the key or its hash)
  apikey revoke          revoke a key by id or name
  config show            print the effective configuration (file, environment and options merged)
  version                print the version

options:
  --config FILE          configuration file (else $SECMONK_CONFIG, ./sec-monk.toml, the per-user file)
  --set KEY=VALUE        override one setting, e.g. --set server.listen=0.0.0.0:8765 (repeatable)
  --data-dir DIR         same as --set data_dir=DIR
  --listen ADDR          same as --set server.listen=ADDR (default 127.0.0.1:8765)
  --tls-cert FILE        same as --set server.tls_cert=FILE (PEM certificate chain)
  --tls-key FILE         same as --set server.tls_key=FILE (PEM private key)
  --allow-actions        same as --set server.allow_actions=true
  --no-actions           same as --set server.allow_actions=false (read-only: no scans or syncs)
  --auth MODE            same as --set server.auth=MODE (auto, required, off)
  -h, --help             this text
  -V, --version          print the version

scopes: ui:read, ui:actions, feed:read, match, vulninfo:read, admin (admin implies all)
exit codes: 0 ok, 1 runtime error, 2 usage error
"
    )
}

/// A `--set` entry for a string value: a JSON string is a TOML basic string, so the value reaches the schema as
/// text whatever it looks like (`8765`, `true`, a path with a backslash).
fn set_entry(key: &str, value: &str) -> String {
    format!("{key}={}", serde_json::to_string(value).unwrap_or_default())
}

/// Parse the arguments (without the program name).
pub fn parse(args: &[String]) -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut positional: Vec<&str> = Vec::new();
    let mut flag_serve = false;
    let mut flag_help = false;
    let mut flag_version = false;
    let mut allow_actions: Option<bool> = None;
    // the options of `apikey create`
    let mut name: Option<String> = None;
    let mut scopes: Vec<String> = Vec::new();
    let mut expires_days: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        i += 1;
        if !arg.starts_with('-') || arg == "-" {
            positional.push(arg);
            continue;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_owned())),
            _ => (arg, None),
        };
        // the value of a flag that takes one: `--flag=value` or the next argument
        let mut value = |what: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            let v = args
                .get(i)
                .ok_or_else(|| format!("{flag} needs {what}"))?
                .clone();
            i += 1;
            Ok(v)
        };
        match flag {
            "--config" => cli.config = Some(PathBuf::from(value("a file")?)),
            "--set" => {
                let v = value("key=value")?;
                parse_set(&v).map_err(|e| e.to_string())?;
                cli.overrides.push(v);
            }
            "--data-dir" => cli
                .overrides
                .push(set_entry("data_dir", &value("a directory")?)),
            "--listen" => cli
                .overrides
                .push(set_entry("server.listen", &value("an address")?)),
            "--tls-cert" => cli
                .overrides
                .push(set_entry("server.tls_cert", &value("a file")?)),
            "--tls-key" => cli
                .overrides
                .push(set_entry("server.tls_key", &value("a file")?)),
            "--auth" => cli
                .overrides
                .push(set_entry("server.auth", &value("a mode")?)),
            "--allow-actions" | "--no-actions" => {
                let on = flag == "--allow-actions";
                if allow_actions.is_some_and(|prev| prev != on) {
                    return Err("--allow-actions and --no-actions contradict each other".into());
                }
                allow_actions = Some(on);
                cli.overrides.push(format!("server.allow_actions={on}"));
            }
            "--serve" => flag_serve = true,
            "-h" | "--help" => flag_help = true,
            "-V" | "--version" => flag_version = true,
            "--name" => name = Some(value("a name")?),
            "--scope" => {
                for s in value("a scope")?.split(',') {
                    scopes.push(s.trim().to_owned());
                }
            }
            "--expires-days" => {
                let v = value("a number of days")?;
                let d: u64 = v
                    .parse()
                    .ok()
                    .filter(|d| (1..=36_500).contains(d))
                    .ok_or_else(|| {
                        format!("--expires-days {v:?}: expected a number of days from 1 to 36500")
                    })?;
                expires_days = Some(d);
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }

    let command = match positional.as_slice() {
        [] => None,
        ["serve"] => Some(Command::Serve),
        ["version"] => Some(Command::Version),
        ["help"] => Some(Command::Help),
        ["config", "show"] => Some(Command::ConfigShow),
        ["config"] => return Err("config needs a subcommand: show".into()),
        ["apikey", "create"] => {
            let name = name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .ok_or("apikey create needs --name")?;
            if scopes.is_empty() {
                return Err("apikey create needs at least one --scope".into());
            }
            Scopes::parse(scopes.iter().map(String::as_str)).map_err(|e| e.to_string())?;
            Some(Command::ApiKeyCreate {
                name,
                scopes: scopes.clone(),
                expires_days,
            })
        }
        ["apikey", "list"] => Some(Command::ApiKeyList),
        ["apikey", "revoke", target] => Some(Command::ApiKeyRevoke {
            target: (*target).to_owned(),
        }),
        ["apikey", "revoke"] => return Err("apikey revoke needs a key id or name".into()),
        ["apikey"] => return Err("apikey needs a subcommand: create, list or revoke".into()),
        [other, ..] => return Err(format!("unknown command {other:?}")),
    };
    if command
        .as_ref()
        .is_none_or(|c| !matches!(c, Command::ApiKeyCreate { .. }))
        && (name.is_some() || !scopes.is_empty() || expires_days.is_some())
    {
        return Err("--name, --scope and --expires-days belong to `apikey create`".into());
    }
    cli.command = match (command, flag_serve) {
        (Some(c), true) if c != Command::Serve => {
            return Err("--serve contradicts the command".into());
        }
        (None, true) => Some(Command::Serve),
        (c, _) => c,
    };
    if flag_help {
        cli.command = Some(Command::Help);
    } else if flag_version && cli.command.is_none() {
        cli.command = Some(Command::Version);
    }
    Ok(cli)
}

/// Parse and run for `secmonk-server`.
pub fn main(args: &[String]) -> i32 {
    main_named(DEFAULT_PROG, args)
}

/// Parse and run; `prog` names the program in messages. Returns the exit code.
pub fn main_named(prog: &str, args: &[String]) -> i32 {
    match parse(args) {
        Ok(cli) => run(prog, &cli),
        Err(m) => {
            eprintln!("{prog}: {m}\nTry `{prog} help`.");
            2
        }
    }
}

/// Run a parsed command line (`serve` when no command was given). Returns the exit code.
pub fn run(prog: &str, cli: &Cli) -> i32 {
    let command = cli.command.clone().unwrap_or(Command::Serve);
    match command {
        Command::Help => {
            print_out(&usage(prog));
            0
        }
        Command::Version => {
            print_out(&format!("{prog} {}\n", env!("CARGO_PKG_VERSION")));
            0
        }
        other => {
            let config = match cli.load_config() {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    eprintln!("{prog}: {e}");
                    return 1;
                }
            };
            run_with_config(prog, other, config)
        }
    }
}

fn run_with_config(prog: &str, command: Command, config: Arc<Config>) -> i32 {
    match command {
        Command::Serve => serve_blocking(prog, config, ServeOptions::from_env()),
        Command::ConfigShow => {
            print_out(&secmonk_config::effective_toml(&config));
            0
        }
        Command::ApiKeyCreate {
            name,
            scopes,
            expires_days,
        } => match apikeys::create(&config, &name, &scopes, expires_days) {
            Ok(key) => {
                eprintln!(
                    "{prog}: API key {name:?} created. It is shown once and cannot be recovered: store it now."
                );
                print_out(&format!("{key}\n"));
                0
            }
            Err(e) => fail(prog, &e),
        },
        Command::ApiKeyList => match apikeys::list(&config) {
            Ok(table) => {
                print_out(&table);
                0
            }
            Err(e) => fail(prog, &e),
        },
        Command::ApiKeyRevoke { target } => match apikeys::revoke(&config, &target) {
            Ok(id) => {
                eprintln!(
                    "{prog}: key {id} revoked (a running server picks this up on its next request)"
                );
                0
            }
            Err(e) => fail(prog, &e),
        },
        Command::Help | Command::Version => 0, // handled before the configuration is loaded
    }
}

fn fail(prog: &str, e: &str) -> i32 {
    eprintln!("{prog}: {e}");
    1
}

/// Write to stdout. Allowed here: this CLI is not a module process, so stdout carries no frames; it is where the
/// one-time API key, the key list, the configuration and the usage go.
#[allow(clippy::print_stdout)]
fn print_out(text: &str) {
    print!("{text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Result<Cli, String> {
        parse(&v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn empty_has_no_command() {
        let c = p(&[]).unwrap();
        assert_eq!(c, Cli::default());
    }

    #[test]
    fn serve_forms_and_global_options_anywhere() {
        assert_eq!(p(&["serve"]).unwrap().command, Some(Command::Serve));
        assert_eq!(p(&["--serve"]).unwrap().command, Some(Command::Serve));
        assert_eq!(
            p(&["--serve", "serve"]).unwrap().command,
            Some(Command::Serve)
        );
        let c = p(&["--config", "a.toml", "serve", "--set", "log.level=debug"]).unwrap();
        assert_eq!(c.config, Some("a.toml".into()));
        assert_eq!(c.overrides, vec!["log.level=debug"]);
        let c = p(&["--config=b.toml", "--set=log.level=trace"]).unwrap();
        assert_eq!(c.config, Some("b.toml".into()));
        assert_eq!(c.overrides, vec!["log.level=trace"]);
        assert_eq!(c.command, None);
    }

    #[test]
    fn convenience_flags_become_ordered_set_entries() {
        let c = p(&[
            "--data-dir",
            "/srv/secmonk",
            "--listen=0.0.0.0:8765",
            "--tls-cert",
            "c.pem",
            "--tls-key",
            "k.pem",
            "--no-actions",
            "--auth",
            "required",
            "--set",
            "server.listen=\"127.0.0.1:1\"",
        ])
        .unwrap();
        assert_eq!(
            c.overrides,
            vec![
                "data_dir=\"/srv/secmonk\"",
                "server.listen=\"0.0.0.0:8765\"",
                "server.tls_cert=\"c.pem\"",
                "server.tls_key=\"k.pem\"",
                "server.allow_actions=false",
                "server.auth=\"required\"",
                "server.listen=\"127.0.0.1:1\"",
            ]
        );
        assert!(p(&["--allow-actions", "--no-actions"]).is_err());
        assert_eq!(
            p(&["--allow-actions", "--allow-actions"])
                .unwrap()
                .overrides,
            vec!["server.allow_actions=true", "server.allow_actions=true"]
        );
    }

    #[test]
    fn overrides_are_valid_for_the_config_parser() {
        let c = p(&["--listen", "[::1]:8765", "--data-dir", "C:\\data \"x\""]).unwrap();
        for o in &c.overrides {
            parse_set(o).unwrap();
        }
        assert!(p(&["--set", "nokey"]).is_err());
    }

    #[test]
    fn apikey_create() {
        let c = p(&[
            "apikey",
            "create",
            "--name",
            "ci",
            "--scope",
            "ui:read",
            "--scope=match,feed:read",
            "--expires-days",
            "30",
        ])
        .unwrap();
        assert_eq!(
            c.command,
            Some(Command::ApiKeyCreate {
                name: "ci".into(),
                scopes: vec!["ui:read".into(), "match".into(), "feed:read".into()],
                expires_days: Some(30),
            })
        );
        assert!(p(&["apikey", "create", "--scope", "admin"]).is_err());
        assert!(p(&["apikey", "create", "--name", "x"]).is_err());
        assert!(
            p(&["apikey", "create", "--name", "x", "--scope", "bogus"])
                .unwrap_err()
                .contains("bogus")
        );
        assert!(
            p(&[
                "apikey",
                "create",
                "--name",
                "x",
                "--scope",
                "admin",
                "--expires-days",
                "0"
            ])
            .is_err()
        );
        assert!(p(&["apikey", "list", "--name", "x"]).is_err());
    }

    #[test]
    fn apikey_list_revoke_config_version_help() {
        assert_eq!(
            p(&["apikey", "list"]).unwrap().command,
            Some(Command::ApiKeyList)
        );
        assert_eq!(
            p(&["apikey", "revoke", "ci"]).unwrap().command,
            Some(Command::ApiKeyRevoke {
                target: "ci".into()
            })
        );
        assert!(p(&["apikey", "revoke"]).is_err());
        assert!(p(&["apikey"]).is_err());
        assert_eq!(
            p(&["config", "show"]).unwrap().command,
            Some(Command::ConfigShow)
        );
        assert!(p(&["config"]).is_err());
        assert_eq!(p(&["version"]).unwrap().command, Some(Command::Version));
        assert_eq!(p(&["--version"]).unwrap().command, Some(Command::Version));
        assert_eq!(p(&["help"]).unwrap().command, Some(Command::Help));
        assert_eq!(p(&["serve", "-h"]).unwrap().command, Some(Command::Help));
    }

    #[test]
    fn usage_errors() {
        assert!(p(&["frobnicate"]).unwrap_err().contains("unknown command"));
        assert!(p(&["--nope"]).unwrap_err().contains("unknown option"));
        assert!(p(&["--listen"]).unwrap_err().contains("needs"));
        assert!(p(&["--serve", "version"]).is_err());
        assert!(p(&["serve", "extra"]).is_err());
    }

    #[test]
    fn usage_names_the_program() {
        assert!(usage("secmonk-desktop").starts_with("usage: secmonk-desktop [serve]"));
    }
}
