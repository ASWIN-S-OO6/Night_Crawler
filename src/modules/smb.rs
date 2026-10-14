use crate::types::SmbResults;
use anyhow::Result;
use std::net::IpAddr;
use std::time::Duration;

/// Run external SMB/Windows enumeration tools when they are installed.
/// We check `command -v` first and degrade gracefully when absent.
pub async fn smb_enum(ip: IpAddr) -> Result<SmbResults> {
    let mut res = SmbResults {
        tools_available: Vec::new(),
        shares: Vec::new(),
        users: Vec::new(),
        groups: Vec::new(),
        notes: Vec::new(),
    };

    for tool in ["smbclient", "rpcclient", "enum4linux", "nmblookup", "crackmapexec", "netexec"] {
        if which(&tool).await {
            res.tools_available.push(tool.to_string());
        }
    }
    if res.tools_available.is_empty() {
        res.notes.push(
            "No SMB tooling installed (smbclient/rpcclient/enum4linux). Install samba-client or enum4linux for share/user enumeration.".into(),
        );
        return Ok(res);
    }

    let ip_s = ip.to_string();

    // Shares via smbclient -L with null session
    if res.tools_available.contains(&"smbclient".to_string()) {
        match run_tool(
            "smbclient",
            &[
                "-L", &format!("//{}", ip_s), "-N", "-m", "SMB3", "-t", "10",
            ],
            Duration::from_secs(25),
        )
        .await
        {
            Some(out) => {
                for line in out.lines() {
                    let l = line.trim();
                    if l.starts_with("Disk") || l.starts_with("Printer") || l.starts_with("IPC") {
                        let name = l
                            .split_whitespace()
                            .nth(1)
                            .map(|s| s.trim_end_matches('$').to_string());
                        if let Some(n) = name {
                            res.shares.push(format!("{} — {}", n, l));
                        }
                    }
                }
                if out.contains("NT_STATUS_ACCESS_DENIED") {
                    res.notes.push("Null session denied by host (good sign).".into());
                } else if res.shares.is_empty() {
                    res.notes.push("smbclient ran but no shares parsed (maybe empty listing).".into());
                }
            }
            None => res.notes.push("smbclient timed out".into()),
        }
    }

    // Users/groups via rpcclient null session
    if res.tools_available.contains(&"rpcclient".to_string()) {
        for cmd in ["enumdomusers", "enumdomgroups"] {
            if let Some(out) = run_tool(
                "rpcclient",
                &["-U", "", "-N", &ip_s, "-c", cmd],
                Duration::from_secs(20),
            )
            .await
            {
                let target = if cmd == "enumdomusers" {
                    &mut res.users
                } else {
                    &mut res.groups
                };
                for line in out.lines().take(200) {
                    let l = line.trim();
                    if !l.is_empty() && l.contains("0x") {
                        target.push(l.to_string());
                    }
                }
            }
        }
    }

    // enum4linux full sweep (optional, slow) — only if explicitly present
    if res.tools_available.contains(&"enum4linux".to_string()) && res.shares.is_empty() && res.users.is_empty() {
        if let Some(out) = run_tool("enum4linux", &["-a", "-o", &ip_s], Duration::from_secs(90)).await {
            for line in out.lines() {
                let l = line.trim();
                if l.starts_with("[+] Got ") || l.starts_with("Check for accounts") {
                    res.notes.push(l.to_string());
                }
            }
        }
    }

    Ok(res)
}

async fn which(tool: &str) -> bool {
    tokio::process::Command::new("sh")
        .args(["-c", &format!("command -v {} >/dev/null 2>&1", tool)])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn run_tool(tool: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut cmd = tokio::process::Command::new(tool);
    cmd.args(args);
    cmd.kill_on_drop(true);
    match tokio::time::timeout(timeout, cmd.output()).await {
        Ok(Ok(out)) => {
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            Some(text)
        }
        _ => None,
    }
}
