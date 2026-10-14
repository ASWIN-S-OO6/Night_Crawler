use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub nvidia: NvidiaCfg,
    #[serde(default)]
    pub dorking: DorkCfg,
    #[serde(default)]
    pub scan: ScanCfg,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NvidiaCfg {
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DorkCfg {
    pub google_cse_key: Option<String>,
    pub google_cse_cx: Option<String>,
    pub serpapi_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanCfg {
    pub timeout_ms: u64,
    pub max_concurrency: usize,
    pub http_timeout_ms: u64,
    pub max_subdirs: usize,
    pub max_subdomains: usize,
}

impl Default for ScanCfg {
    fn default() -> Self {
        ScanCfg {
            timeout_ms: 2200,
            max_concurrency: 400,
            http_timeout_ms: 8000,
            max_subdirs: 300,
            max_subdomains: 400,
        }
    }
}

impl Config {
    /// Load order: explicit path > ./nightcrawler.toml > ~/.config/nightcrawler/config.toml
    pub fn load(explicit: Option<&PathBuf>) -> Config {
        let candidates: Vec<PathBuf> = match explicit {
            Some(p) => vec![p.clone()],
            None => vec![
                PathBuf::from("nightcrawler.toml"),
                dirs_config_path(),
            ],
        };
        for path in candidates {
            if path.exists() {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match toml::from_str::<Config>(&content) {
                        Ok(cfg) => {
                            eprintln!(
                                "[*] config loaded from {}",
                                path.display()
                            );
                            return cfg;
                        }
                        Err(e) => eprintln!("[!] config parse error in {}: {}", path.display(), e),
                    },
                    Err(e) => eprintln!("[!] config read error {}: {}", path.display(), e),
                }
            }
        }
        Config::default()
    }
}

fn dirs_config_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".config")
            .join("nightcrawler")
            .join("config.toml")
    } else {
        PathBuf::from("/dev/null-nonexistent")
    }
}

/// Resolve the NVIDIA API key from CLI > env > config.
pub fn resolve_nvidia_key(cli_key: Option<&str>, cfg: &Config) -> Option<String> {
    if let Some(k) = cli_key {
        if !k.is_empty() {
            return Some(k.to_string());
        }
    }
    if let Ok(k) = std::env::var("NVIDIA_API_KEY") {
        if !k.is_empty() {
            return Some(k);
        }
    }
    if let Ok(k) = std::env::var("NVCRAWLER_API_KEY") {
        if !k.is_empty() {
            return Some(k);
        }
    }
    cfg.nvidia.api_key.clone().filter(|k| !k.is_empty())
}

pub fn default_model() -> String {
    std::env::var("NVIDIA_MODEL").unwrap_or_else(|_| "meta/llama-3.3-70b-instruct".to_string())
}

pub fn default_base_url() -> String {
    std::env::var("NVIDIA_BASE_URL")
        .unwrap_or_else(|_| "https://integrate.api.nvidia.com/v1".to_string())
}

pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports: Vec<u16> = Vec::new();
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("full") {
        return Ok((1u16..=65535).collect());
    }
    if spec.is_empty() || spec.eq_ignore_ascii_case("top") {
        return Ok(top_ports());
    }
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().context("bad port in range")?;
            let b: u16 = b.trim().parse().context("bad port in range")?;
            for p in a..=b {
                ports.push(p);
            }
        } else {
            ports.push(part.parse().context("bad port")?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

pub fn top_ports() -> Vec<u16> {
    const TOP: &[u16] = &[
        21, 22, 23, 25, 26, 53, 69, 80, 81, 88, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143,
        144, 161, 162, 179, 199, 389, 427, 443, 444, 445, 465, 500, 502, 503, 512, 513, 514, 515,
        540, 543, 544, 548, 554, 587, 631, 636, 646, 873, 902, 990, 992, 993, 995, 1000, 1025,
        1026, 1027, 1028, 1029, 1080, 1099, 1194, 1234, 1433, 1434, 1470, 1521, 1604, 1701, 1723,
        1761, 1883, 1900, 1998, 2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2100, 2121, 2222,
        2375, 2376, 2381, 2525, 3000, 3001, 3052, 3128, 3260, 3268, 3269, 3299, 3306, 3389, 3535,
        3632, 3690, 3900, 4000, 4040, 4369, 4443, 4444, 4567, 4659, 4840, 5000, 5001, 5060, 5061,
        5222, 5269, 5432, 5555, 5601, 5672, 5683, 5800, 5900, 5901, 5984, 6000, 6001, 6379, 6443,
        6566, 6660, 6661, 6662, 6663, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 6996, 7000, 7001,
        7002, 7070, 7100, 7180, 7443, 7500, 7676, 7777, 7778, 7999, 8000, 8001, 8002, 8003, 8004,
        8005, 8006, 8007, 8008, 8009, 8010, 8011, 8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019,
        8020, 8021, 8022, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091,
        8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8118, 8123, 8125, 8126, 8180, 8181,
        8200, 8222, 8243, 8280, 8333, 8334, 8383, 8443, 8444, 8445, 8500, 8585, 8642, 8686, 8757,
        8765, 8786, 8800, 8812, 8834, 8866, 8880, 8881, 8888, 8889, 8890, 8899, 8983, 9000, 9001,
        9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9011, 9020, 9030, 9040, 9042, 9043,
        9080, 9081, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100, 9101, 9102,
        9103, 9104, 9105, 9110, 9111, 9150, 9191, 9200, 9201, 9202, 9203, 9204, 9205, 9206, 9207,
        9208, 9209, 9210, 9222, 9251, 9290, 9300, 9418, 9440, 9441, 9442, 9443, 9444, 9445, 9450,
        9451, 9452, 9453, 9454, 9455, 9460, 9461, 9462, 9463, 9464, 9465, 9500, 9530, 9595, 9600,
        9630, 9666, 9711, 9800, 9869, 9981, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998,
        9999, 10000, 10001, 10050, 10051, 10080, 10081, 10110, 10162, 10250, 11311, 12345, 13075,
        13514, 14000, 14265, 15000, 15200, 16080, 16085, 17000, 17777, 18080, 18112, 19071, 20000,
        20720, 26000, 27015, 28015, 30000, 30518, 31000, 32764, 32765, 33000, 34573, 50000, 50001,
        50050, 50070, 54321, 55553, 5666, 61212, 61613, 61616, 65000,
    ];
    TOP.to_vec()
}

/// Map a port to a well-known service name.
pub fn service_for_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        69 => "tftp",
        80 => "http",
        81 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        179 => "bgp",
        389 => "ldap",
        445 => "microsoft-ds",
        465 => "smtps",
        500 => "isakmp",
        502 => "modbus",
        512 => "exec",
        513 => "login",
        514 => "shell",
        515 => "printer",
        540 => "uucp",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        990 => "telnets",
        992 => "telnets",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1099 => "java-rmi",
        1433 => "ms-sql-s",
        1434 => "ms-sql-m",
        1521 => "oracle",
        1701 => "l2tp",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2082 => "cpanel",
        2083 => "cpanel-ssl",
        2086 => "whm",
        2095 => "webmail",
        2375 => "docker",
        2376 => "docker-tls",
        3000 => "node-http",
        3128 => "squid",
        3260 => "iscsi",
        3268 => "globalcat-ldap",
        3269 => "globalcat-ldaps",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        3690 => "svn",
        4443 => "https-alt",
        4444 => "https-alt",
        4848 => "glassfish",
        5000 => "upnp",
        5060 => "sip",
        5222 => "xmpp-client",
        5269 => "xmpp-server",
        5432 => "postgresql",
        5555 => "adb",
        5601 => "kibana",
        5672 => "amqp",
        5683 => "coap",
        5800 => "vnc-http",
        5900 => "vnc",
        5901 => "vnc-1",
        5984 => "couchdb",
        6379 => "redis",
        6443 => "kubernetes-api",
        6667 => "irc",
        7000 => "cassandra",
        7070 => "http-alt",
        7470 => "neo4j",
        7687 => "neo4j-bolt",
        7777 => "http-alt",
        8000 => "http-alt",
        8008 => "http-alt",
        8009 => "ajp13",
        8010 => "http-alt",
        8080 => "http-proxy",
        8081 => "http-alt",
        8088 => "http-alt",
        8089 => "splunkd",
        8090 => "http-alt",
        8161 => "activemq",
        8180 => "http-alt",
        8222 => "http-alt",
        8332 => "http-alt",
        8333 => "http-alt",
        8443 => "https-alt",
        8500 => "http-alt",
        8642 => "http-alt",
        8765 => "http-alt",
        8786 => "http-alt",
        8800 => "http-alt",
        8834 => "http-alt",
        8888 => "http-alt",
        9000 => "http-alt",
        9001 => "http-alt",
        9090 => "http-alt",
        9092 => "http-alt",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        9300 => "elasticsearch",
        9443 => "https-alt",
        9595 => "http-alt",
        9800 => "weblogic",
        10000 => "webmin",
        10050 => "zabbix-agent",
        10051 => "zabbix-server",
        11211 => "memcached",
        15672 => "rabbitmq-mgmt",
        55553 => "https-alt",
        61616 => "http-alt",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Provider setup: accept a raw API key OR a provider config file
// (TOML / JSON / env-style text). The file supplies key + model + base URL.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProviderSetup {
    pub api_key: String,
    pub base_url: String,
    pub model: Option<String>,
}

fn expand_home(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(p)
}

/// Parse whatever the user typed/pasted in onboarding:
/// - a raw API key (nvapi-..., or a long token)
/// - a path to a provider config file (.toml, .json, .txt, .env, .conf)
pub fn resolve_provider_input(input: &str) -> Result<ProviderSetup> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty provider input");
    }

    let looks_like_key = trimmed.starts_with("nvapi-")
        || trimmed.starts_with("sk-")
        || (trimmed.len() >= 32
            && !trimmed.contains('/')
            && !trimmed.contains('\\')
            && !trimmed.contains('.')
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

    if looks_like_key {
        return Ok(ProviderSetup {
            api_key: trimmed.to_string(),
            base_url: default_base_url(),
            model: None,
        });
    }

    let path = expand_home(trimmed);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("provider config not readable: {}", path.display()))?;
    let lower = path
        .to_string_lossy()
        .to_ascii_lowercase();

    let setup: ProviderSetup = if lower.ends_with(".json") {
        parse_json_provider(&content)?
    } else if lower.ends_with(".toml") {
        // round-trip through serde_json so one finder handles both formats
        let json: serde_json::Value = toml::from_str::<toml::Value>(&content)
            .with_context(|| "invalid provider TOML")?
            .try_into()
            .context("convert TOML to JSON")?;
        parse_json_provider(&json.to_string())?
    } else {
        parse_text_provider(&content)?
    };

    Ok(setup)
}

fn find_str(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    if let serde_json::Value::Object(map) = v {
        // exact / normalized match at this level
        for (k, val) in map {
            let norm = k.to_ascii_lowercase().replace('-', "_");
            if keys.contains(&norm.as_str()) || keys.contains(&k.as_str()) {
                if let Some(s) = val.as_str() {
                    if !s.trim().is_empty() {
                        return Some(s.trim().to_string());
                    }
                }
            }
        }
        // then recurse (nested tables like [nvidia] or {"nvidia": {...}})
        for (k, val) in map {
            let norm = k.to_ascii_lowercase().replace('-', "_");
            if keys.contains(&norm.as_str()) || keys.contains(&k.as_str()) {
                continue;
            }
            if let Some(hit) = find_str(val, keys) {
                return Some(hit);
            }
        }
    }
    None
}

fn parse_json_provider(content: &str) -> Result<ProviderSetup> {
    let v: serde_json::Value =
        serde_json::from_str(content).context("invalid provider JSON")?;
    let api_key = find_str(&v, &["api_key", "key", "nvidia_api_key", "nim_api_key", "token", "nvapi"])
        .ok_or_else(|| anyhow::anyhow!("no api_key found in provider JSON"))?;
    let model = find_str(&v, &["model", "model_id", "model_name", "model_name_or_path"]);
    let base_url = find_str(&v, &["base_url", "endpoint", "api_base", "url", "server_url"]);
    Ok(ProviderSetup {
        api_key,
        base_url: base_url.unwrap_or_else(default_base_url),
        model,
    })
}

fn parse_text_provider(content: &str) -> Result<ProviderSetup> {
    let mut api_key: Option<String> = None;
    let mut model: Option<String> = None;
    let mut base_url: Option<String> = None;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            // still allow a bare key on a comment-free line later
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().trim_matches('"').trim_matches('\'');
            match k.as_str() {
                "nvidia_api_key" | "nvapi_key" | "nim_api_key" | "api_key" | "key" | "token" => {
                    if !v.is_empty() {
                        api_key = Some(v.to_string());
                    }
                }
                "model" | "model_id" | "model_name" | "nvidia_model" => {
                    if !v.is_empty() {
                        model = Some(v.to_string());
                    }
                }
                "base_url" | "nvidia_base_url" | "endpoint" | "api_base" | "url" => {
                    if !v.is_empty() {
                        base_url = Some(v.to_string());
                    }
                }
                _ => {}
            }
        } else if line.starts_with("nvapi-") && api_key.is_none() {
            api_key = Some(line.to_string());
        }
    }
    let api_key = api_key.ok_or_else(|| anyhow::anyhow!("no API key found in provider file (expected api_key= or a bare nvapi-... line)"))?;
    Ok(ProviderSetup {
        api_key,
        base_url: base_url.unwrap_or_else(default_base_url),
        model,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_raw_key() {
        let p = resolve_provider_input("nvapi-test123").unwrap();
        assert_eq!(p.api_key, "nvapi-test123");
        assert_eq!(p.base_url, "https://integrate.api.nvidia.com/v1");
        assert!(p.model.is_none());
    }

    #[test]
    fn provider_toml_nested() {
        let content = r#"
[nvidia]
api_key = "nvapi-from-toml"
model = "meta/llama-3.3-70b-instruct"
base_url = "https://integrate.api.nvidia.com/v1"
"#;
        let dir = std::env::temp_dir().join(format!("ncprov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("provider.toml");
        std::fs::write(&f, content).unwrap();
        let p = resolve_provider_input(f.to_str().unwrap()).unwrap();
        assert_eq!(p.api_key, "nvapi-from-toml");
        assert_eq!(p.model.as_deref(), Some("meta/llama-3.3-70b-instruct"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn provider_json_nested() {
        let content = r#"{"nvidia": {"api_key": "nvapi-json", "model_id": "qwen/qwen2.5-72b-instruct"}}"#;
        let dir = std::env::temp_dir().join(format!("ncprov2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("provider.json");
        std::fs::write(&f, content).unwrap();
        let p = resolve_provider_input(f.to_str().unwrap()).unwrap();
        assert_eq!(p.api_key, "nvapi-json");
        assert_eq!(p.model.as_deref(), Some("qwen/qwen2.5-72b-instruct"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn provider_env_style() {
        let content = "# provider\nNVIDIA_API_KEY=nvapi-env-style\nMODEL=deepseek-ai/deepseek-r1\n";
        let dir = std::env::temp_dir().join(format!("ncprov3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("provider.env");
        std::fs::write(&f, content).unwrap();
        let p = resolve_provider_input(f.to_str().unwrap()).unwrap();
        assert_eq!(p.api_key, "nvapi-env-style");
        assert_eq!(p.model.as_deref(), Some("deepseek-ai/deepseek-r1"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn provider_missing_file() {
        assert!(resolve_provider_input("/definitely/not/a/real/path.toml").is_err());
    }
}
