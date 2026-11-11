//! Timestamps as the Python version writes them: ISO-8601 UTC, seconds precision, `+00:00` offset
//! (`datetime.now(UTC).replace(microsecond=0).isoformat()`).

use std::time::{SystemTime, UNIX_EPOCH};

/// Now, formatted like Python's `db.now()`: `2026-11-11T08:00:00+00:00`.
pub fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix(secs as i64)
}

/// Format seconds since the Unix epoch (UTC) as `YYYY-MM-DDTHH:MM:SS+00:00`.
pub fn format_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}+00:00",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 -> (year, month, day), proleptic Gregorian (H. Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_unix(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(format_unix(951_782_400), "2000-02-29T00:00:00+00:00");
        assert_eq!(format_unix(1_794_384_000), "2026-11-11T08:00:00+00:00");
        assert_eq!(format_unix(-1), "1969-12-31T23:59:59+00:00");
    }

    #[test]
    fn now_has_python_shape() {
        let n = now_iso();
        assert_eq!(n.len(), 25);
        assert!(n.ends_with("+00:00"));
    }
}
