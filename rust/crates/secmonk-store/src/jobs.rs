//! Process identity of run-history owners (`db.this_owner`, `db.owner_alive`).

use secmonk_model::JobOwner;

/// The process recording a run: `{pid, host}`.
pub fn this_owner() -> JobOwner {
    JobOwner {
        pid: i64::from(std::process::id()),
        host: host_name(),
    }
}

/// The host name (`socket.gethostname()`).
pub fn host_name() -> String {
    #[cfg(unix)]
    {
        rustix::system::uname()
            .nodename()
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}

/// Whether the process owning a `running` row still runs. Unknown owner, another host or a gone pid -> false;
/// on Windows only this process's own rows count as alive (as in Python).
pub fn owner_alive(owner: Option<&JobOwner>) -> bool {
    let Some(o) = owner else { return false };
    if o.host != host_name() || o.pid <= 0 {
        return false;
    }
    if o.pid == i64::from(std::process::id()) {
        return true;
    }
    #[cfg(unix)]
    {
        let Ok(raw) = i32::try_from(o.pid) else {
            return false;
        };
        let Some(pid) = rustix::process::Pid::from_raw(raw) else {
            return false;
        };
        match rustix::process::test_kill_process(pid) {
            Ok(()) => true,
            Err(e) => e == rustix::io::Errno::PERM,
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_alive() {
        assert!(owner_alive(Some(&this_owner())));
        assert!(!owner_alive(None));
        let other_host = JobOwner {
            pid: 1,
            host: "no-such-host.invalid".into(),
        };
        assert!(!owner_alive(Some(&other_host)));
    }
}
