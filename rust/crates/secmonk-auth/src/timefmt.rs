//! Tiny RFC 3339 (UTC, seconds) formatter and parser.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Format a time as `YYYY-MM-DDTHH:MM:SSZ` (UTC). Times before the epoch clamp to the epoch.
pub fn format_rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (UTC only) into a time.
pub fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = s.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let days = days_from_civil(y as i64, mo, d);
    if days < 0 {
        return None;
    }
    let secs = days as u64 * 86_400 + h as u64 * 3600 + mi as u64 * 60 + se as u64;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

pub(crate) fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        assert_eq!(format_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_709_210_096);
        assert_eq!(format_rfc3339(t), "2024-02-29T12:34:56Z");
        assert_eq!(parse_rfc3339("2024-02-29T12:34:56Z"), Some(t));
    }

    #[test]
    fn roundtrip_many() {
        for s in (0..4_000_000_000u64).step_by(86_399 * 37) {
            let t = UNIX_EPOCH + Duration::from_secs(s);
            assert_eq!(parse_rfc3339(&format_rfc3339(t)), Some(t));
        }
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_rfc3339("2024-02-29 12:34:56Z"), None);
        assert_eq!(parse_rfc3339("2024-13-29T12:34:56Z"), None);
        assert_eq!(parse_rfc3339("+024-02-29T12:34:56Z"), None);
    }
}
