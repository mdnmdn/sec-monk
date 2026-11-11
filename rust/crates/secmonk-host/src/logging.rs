//! Logging of the app: `tracing` to stderr and to `<data_dir>/logs/secmonk-desktop.log.<date>` (0600), old files
//! pruned after `[log] keep_days`. Module stderr lines arrive through `tracing` (target `module`) already scrubbed.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use secmonk_config::Config;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

const FILE_PREFIX: &str = "secmonk-desktop.log.";

#[derive(Clone)]
struct Tee {
    file: Option<Arc<Mutex<File>>>,
    stderr: bool,
}

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.stderr {
            let _ = io::stderr().write_all(buf);
        }
        if let Some(f) = &self.file {
            let _ = f.lock().unwrap_or_else(|p| p.into_inner()).write_all(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = &self.file {
            let _ = f.lock().unwrap_or_else(|p| p.into_inner()).flush();
        }
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Tee {
    type Writer = Tee;
    fn make_writer(&'a self) -> Tee {
        self.clone()
    }
}

fn open_log(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Delete log files older than `keep_days`.
fn prune(dir: &Path, keep_days: u32) {
    let Some(limit) =
        SystemTime::now().checked_sub(Duration::from_secs(u64::from(keep_days) * 86_400))
    else {
        return;
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        if name.to_string_lossy().starts_with(FILE_PREFIX)
            && e.metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| t < limit)
        {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Install the global subscriber. `RUST_LOG` wins over `[log] level`. Returns false when one was already
/// installed (tests, a second call).
pub fn init(config: &Config, to_stderr: bool) -> bool {
    let logs = config.layout().logs();
    let _ = std::fs::create_dir_all(&logs);
    prune(&logs, config.log_keep_days);
    let day = secmonk_model::time::now_iso();
    let day = day.get(..10).unwrap_or("today");
    let file = open_log(&logs.join(format!("{FILE_PREFIX}{day}")))
        .ok()
        .map(|f| Arc::new(Mutex::new(f)));
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(Tee {
            file,
            stderr: to_stderr,
        })
        .try_init()
        .is_ok()
}
