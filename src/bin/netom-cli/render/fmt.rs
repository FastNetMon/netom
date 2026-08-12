//! Formatting helpers shared by the renderers.

/// Format a duration the way a router console does, picking the unit by
/// magnitude: `01:23:45` under a day, `3d04h` under a week, then `4w2d`.
pub fn uptime(secs: u64) -> String {
    const MIN: u64 = 60;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;
    const WEEK: u64 = 7 * DAY;

    if secs < DAY {
        format!(
            "{:02}:{:02}:{:02}",
            secs / HOUR,
            (secs % HOUR) / MIN,
            secs % MIN,
        )
    } else if secs < WEEK {
        format!("{}d{:02}h", secs / DAY, (secs % DAY) / HOUR)
    } else {
        format!("{}w{}d", secs / WEEK, (secs % WEEK) / DAY)
    }
}

/// Human-readable byte count.
pub fn bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Thousands-separated count, for the large numbers a RIB produces.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Render a BGP identifier, which the API serializes as four bytes, as the
/// dotted-quad router-id operators expect.
pub fn router_id(bytes: &[u8]) -> String {
    if bytes.len() != 4 {
        return "-".to_string();
    }
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_uses_hms_under_a_day() {
        assert_eq!(uptime(0), "00:00:00");
        assert_eq!(uptime(59), "00:00:59");
        assert_eq!(uptime(3661), "01:01:01");
        assert_eq!(uptime(86399), "23:59:59");
    }

    #[test]
    fn uptime_uses_days_and_hours_under_a_week() {
        assert_eq!(uptime(86400), "1d00h");
        assert_eq!(uptime(86400 * 3 + 3600 * 4), "3d04h");
    }

    #[test]
    fn uptime_uses_weeks_and_days_beyond_that() {
        assert_eq!(uptime(86400 * 7), "1w0d");
        assert_eq!(uptime(86400 * 30), "4w2d");
    }

    #[test]
    fn bytes_scales_by_unit() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(8_402_138_624), "7.8 GiB");
    }

    #[test]
    fn count_groups_thousands() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(921034), "921,034");
        assert_eq!(count(1234567), "1,234,567");
    }

    #[test]
    fn router_id_renders_the_byte_array_form() {
        assert_eq!(router_id(&[10, 99, 0, 1]), "10.99.0.1");
        // Anything else is missing data, not a router-id.
        assert_eq!(router_id(&[1, 2]), "-");
        assert_eq!(router_id(&[]), "-");
    }
}
