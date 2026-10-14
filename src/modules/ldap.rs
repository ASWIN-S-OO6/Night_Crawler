use crate::types::LdapResults;
use anyhow::{anyhow, Result};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::net::IpAddr;

/// LDAP enumeration: anonymous bind -> RootDSE -> users/groups/computers.
pub async fn ldap_enum(ip: IpAddr, port: u16) -> Result<LdapResults> {
    let url = format!("ldap://{}:{}", ip, port);
    let (conn, mut ldap) = LdapConnAsync::new(&url)
        .await
        .map_err(|e| anyhow!("ldap connect: {}", e))?;
    let drive = tokio::spawn(async move {
        let _ = conn.drive().await;
    });

    let mut res = LdapResults {
        server: url.clone(),
        anonymous_bind: false,
        root_dse: Vec::new(),
        naming_context: None,
        users: Vec::new(),
        groups: Vec::new(),
        computers: Vec::new(),
        note: String::new(),
    };

    // Anonymous bind (simple bind with empty DN/password)
    match ldap.simple_bind("", "").await {
        Ok(r) if r.rc == 0 => res.anonymous_bind = true,
        Ok(r) => {
            res.note = format!("anonymous bind rejected (rc={} {})", r.rc, r.text);
            drive.abort();
            return Ok(res);
        }
        Err(e) => {
            res.note = format!("bind error: {}", e);
            drive.abort();
            return Ok(res);
        }
    }

    // RootDSE
    let attrs = vec![
        "namingContexts",
        "defaultNamingContext",
        "rootDomainNamingContext",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
        "dnsHostName",
        "ldapServiceName",
        "serverName",
        "supportedCapabilities",
        "currentTime",
        "vendorName",
        "vendorVersion",
        "isGlobalCatalogReady",
    ];
    if let Ok(sr) = ldap
        .search("", Scope::Base, "(objectClass=*)", attrs)
        .await
    {
        for e in sr.0 {
            let se = SearchEntry::construct(e);
            let mut keys: Vec<&String> = se.attrs.keys().collect();
            keys.sort();
            for k in keys {
                if let Some(vals) = se.attrs.get(k) {
                    for v in vals {
                        res.root_dse.push((k.clone(), v.clone()));
                    }
                }
            }
        }
    }

    // Pick a naming context
    let nc = res
        .root_dse
        .iter()
        .find(|(k, _)| k == "defaultNamingContext")
        .or_else(|| res.root_dse.iter().find(|(k, _)| k == "rootDomainNamingContext"))
        .or_else(|| res.root_dse.iter().find(|(k, _)| k == "namingContexts"))
        .map(|(_, v)| v.clone());
    res.naming_context = nc.clone();

    if let Some(base) = nc {
        // AD-style users
        if let Ok(sr) = ldap
            .search(
                &base,
                Scope::Subtree,
                "(&(objectClass=user)(objectCategory=person))",
                vec!["sAMAccountName", "displayName", "mail", "uid"],
            )
            .await
        {
            for e in sr.0 {
                let se = SearchEntry::construct(e);
                let name = se
                    .attrs
                    .get("sAMAccountName")
                    .or_else(|| se.attrs.get("uid"))
                    .and_then(|v| v.first().cloned());
                if let Some(n) = name {
                    res.users.push(n);
                }
            }
        }
        if res.users.is_empty() {
            // OpenLDAP-style
            if let Ok(sr) = ldap
                .search(&base, Scope::Subtree, "(objectClass=posixAccount)", vec!["uid", "cn"])
                .await
            {
                for e in sr.0 {
                    let se = SearchEntry::construct(e);
                    if let Some(v) = se.attrs.get("uid").and_then(|v| v.first()) {
                        res.users.push(v.clone());
                    }
                }
            }
        }

        // Groups
        let mut group_done = false;
        if let Ok(sr) = ldap
            .search(&base, Scope::Subtree, "(objectClass=group)", vec!["name", "sAMAccountName", "cn"])
            .await
        {
            for e in sr.0 {
                let se = SearchEntry::construct(e);
                let name = se
                    .attrs
                    .get("sAMAccountName")
                    .or_else(|| se.attrs.get("name"))
                    .or_else(|| se.attrs.get("cn"))
                    .and_then(|v| v.first().cloned());
                if let Some(n) = name {
                    res.groups.push(n);
                    group_done = true;
                }
            }
        }
        if !group_done {
            if let Ok(sr) = ldap
                .search(&base, Scope::Subtree, "(objectClass=posixGroup)", vec!["cn"])
                .await
            {
                for e in sr.0 {
                    let se = SearchEntry::construct(e);
                    if let Some(v) = se.attrs.get("cn").and_then(|v| v.first()) {
                        res.groups.push(v.clone());
                    }
                }
            }
        }

        // Computers (AD)
        if let Ok(sr) = ldap
            .search(&base, Scope::Subtree, "(objectClass=computer)", vec!["cn", "operatingSystem"])
            .await
        {
            for e in sr.0 {
                let se = SearchEntry::construct(e);
                let cn = se.attrs.get("cn").and_then(|v| v.first().cloned());
                let os = se.attrs.get("operatingSystem").and_then(|v| v.first().cloned());
                if let Some(cn) = cn {
                    res.computers.push(match os {
                        Some(os) => format!("{} ({})", cn, os),
                        None => cn,
                    });
                }
            }
        }
    } else {
        res.note = "no naming context discovered; directory browsing limited".into();
    }

    let _ = ldap.unbind().await;
    drive.abort();
    res.users.truncate(500);
    res.groups.truncate(200);
    res.computers.truncate(300);
    Ok(res)
}
