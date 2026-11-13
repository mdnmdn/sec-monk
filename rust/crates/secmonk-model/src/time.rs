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

/// Days since 1970-01-01 of a proleptic Gregorian date (inverse of `civil_from_days`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Shift an ISO-8601 timestamp by `delta_secs` (negative: earlier), keeping its shape: the separator and everything
/// after the seconds (fraction, `Z`, `+00:00`) are copied, so the result compares as text with timestamps written
/// the same way. Understands `YYYY-MM-DDTHH:MM:SS...` (or a space as separator) and a bare `YYYY-MM-DD` (shifted
/// as midnight, written with a time). The offset is not interpreted (all sources publish UTC). `None` when `ts`
/// is not in one of these shapes.
pub fn shift_iso(ts: &str, delta_secs: i64) -> Option<String> {
    let b = ts.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = ts.get(r)?;
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, mo, d) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let (sep, hh, mi, ss, rest) = if b.len() == 10 {
        ('T', 0, 0, 0, "")
    } else {
        if b.len() < 19 || !(b[10] == b'T' || b[10] == b' ') || b[13] != b':' || b[16] != b':' {
            return None;
        }
        (
            b[10] as char,
            digits(11..13)?,
            digits(14..16)?,
            digits(17..19)?,
            &ts[19..],
        )
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + hh * 3600 + mi * 60 + ss + delta_secs;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    Some(format!(
        "{y:04}-{m:02}-{d:02}{sep}{:02}:{:02}:{:02}{rest}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    ))
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

    #[test]
    fn shifts_keep_the_shape() {
        assert_eq!(
            shift_iso("2026-11-11T08:00:00+00:00", -3600).unwrap(),
            "2026-11-11T07:00:00+00:00"
        );
        assert_eq!(
            shift_iso("2024-01-01T00:30:00.123Z", -3600).unwrap(),
            "2023-12-31T23:30:00.123Z"
        );
        assert_eq!(
            shift_iso("2024-03-01 00:00:00", -1).unwrap(),
            "2024-02-29 23:59:59"
        );
        assert_eq!(
            shift_iso("2024-01-01", -86_400).unwrap(),
            "2023-12-31T00:00:00"
        );
        assert_eq!(
            shift_iso("2024-01-01T00:00:00Z", 0).unwrap(),
            "2024-01-01T00:00:00Z"
        );
        assert!(shift_iso("yesterday", -1).is_none());
        let t = 1_794_384_000;
        assert_eq!(
            shift_iso(&format_unix(t), -7200).unwrap(),
            format_unix(t - 7200)
        );
    }
}
