use std::collections::HashSet;

/// Minimal semantic version parse: "8.2p1" -> (8,2,1); "2.4.49" -> (2,4,49).
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim();
    let digits: String = s
        .chars()
        .map(|c| if c.is_ascii_digit() || c == '.' { c } else { ' ' })
        .collect();
    let mut parts = digits.split_whitespace().flat_map(|p| p.split('.'));
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let patch = parts
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// Is `ver` in [min, max]? (inclusive bounds, None = unbounded)
pub fn version_in(ver: (u64, u64, u64), min: Option<(u64, u64, u64)>, max: Option<(u64, u64, u64)>) -> bool {
    if let Some(m) = min {
        if ver < m {
            return false;
        }
    }
    if let Some(m) = max {
        if ver > m {
            return false;
        }
    }
    true
}

pub fn strip_domain(name: &str) -> String {
    name.trim_end_matches('.').to_string()
}

pub fn dedup_str(v: Vec<String>) -> Vec<String> {
    let set: HashSet<String> = v.into_iter().collect();
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort();
    out
}

pub fn sanitize_label(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " .-_/:@#".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .replace(['"', '`', '\n'], "'")
}

/// Extract <title> from HTML (very small best-effort parser).
pub fn html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after = &body[start..];
    let gt = after.find('>')?;
    let rest = &after[gt + 1..];
    let end = rest.find("</title>")?;
    let title: String = rest[..end]
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if title.is_empty() {
        None
    } else {
        Some(title)
    }
}

pub fn pct_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .to_string()
}

pub fn now_string() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn timestamp_slug() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S").to_string()
}

pub fn safe_dir_name(s: &str) -> String {
    s.replace(':', "_")
        .replace('/', "_")
        .replace('.', "_")
}
