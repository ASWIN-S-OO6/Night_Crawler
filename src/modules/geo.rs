//! Enhanced Geo IP location with multiple free providers and map visualization.
//! Provides accurate location data: coordinates, city, region, country, ISP, ASN, timezone.

use crate::types::{GeoInfo, TraceHop};
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;

/// Multiple free geo IP providers for redundancy and accuracy
const PROVIDERS: &[(&str, &str)] = &[
    ("ipapi", "http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"),
    ("ipinfo", "https://ipinfo.io/{}/json"),
    ("ipgeolocation", "https://api.ipgeolocation.io/ipgeo?apiKey=free&ip={}"),
];

#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: String,
    message: Option<String>,
    country: Option<String>,
    countryCode: Option<String>,
    region: Option<String>,
    regionName: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    as_str: Option<String>,
    asname: Option<String>,
    query: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    ip: Option<String>,
    hostname: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    loc: Option<String>,
    org: Option<String>,
    postal: Option<String>,
    timezone: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpGeoResponse {
    ip: Option<String>,
    country_name: Option<String>,
    country_code2: Option<String>,
    state_prov: Option<String>,
    city: Option<String>,
    zipcode: Option<String>,
    latitude: Option<String>,
    longitude: Option<String>,
    time_zone: Option<TimeZone>,
    isp: Option<String>,
    organization: Option<String>,
    asn: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TimeZone {
    name: Option<String>,
}

/// Enhanced geo IP lookup with multiple provider fallback
pub async fn geo_lookup(ip: IpAddr) -> Result<GeoInfo> {
    let client = reqwest::Client::builder()
        .user_agent("NightCrawler/0.1 (recon agent)")
        .timeout(Duration::from_secs(10))
        .build()?;

    // Try ip-api.com first (free, no key, good accuracy)
    if let Ok(geo) = try_ipapi(&client, ip).await {
        return Ok(geo);
    }

    // Fallback to ipinfo.io (free tier: 50k req/month)
    if let Ok(geo) = try_ipinfo(&client, ip).await {
        return Ok(geo);
    }

    // Fallback to ipgeolocation.io (free tier)
    if let Ok(geo) = try_ipgeolocation(&client, ip).await {
        return Ok(geo);
    }

    Err(anyhow!("all geo providers failed"))
}

async fn try_ipapi(client: &reqwest::Client, ip: IpAddr) -> Result<GeoInfo> {
    let url = PROVIDERS[0].1.replace("{}", &ip.to_string());
    let resp: IpApiResponse = client.get(&url).send().await?.error_for_status()?.json().await?;
    if resp.status != "success" {
        return Err(anyhow!("ip-api: {}", resp.message.unwrap_or("unknown error".into())));
    }
    Ok(GeoInfo {
        query: resp.query.unwrap_or_else(|| ip.to_string()),
        country: resp.country,
        region: resp.regionName.or(resp.region),
        city: resp.city,
        isp: resp.isp,
        org: resp.org.or(resp.asname),
        asn: resp.as_str,
        lat: resp.lat,
        lon: resp.lon,
        timezone: resp.timezone,
        zip: resp.zip,
    })
}

async fn try_ipinfo(client: &reqwest::Client, ip: IpAddr) -> Result<GeoInfo> {
    let url = PROVIDERS[1].1.replace("{}", &ip.to_string());
    let resp: IpInfoResponse = client.get(&url).send().await?.error_for_status()?.json().await?;

    let (lat, lon) = resp.loc.as_ref().and_then(|l| {
        let parts: Vec<&str> = l.split(',').collect();
        if parts.len() == 2 {
            Some((parts[0].parse().ok()?, parts[1].parse().ok()?))
        } else {
            None
        }
    }).unwrap_or((0.0, 0.0));

    Ok(GeoInfo {
        query: resp.ip.unwrap_or_else(|| ip.to_string()),
        country: resp.country,
        region: resp.region,
        city: resp.city,
        isp: resp.org.as_ref().map(|o| o.split_whitespace().next().unwrap_or("").to_string()),
        org: resp.org,
        asn: None,
        lat: Some(lat),
        lon: Some(lon),
        timezone: resp.timezone,
        zip: resp.postal,
    })
}

async fn try_ipgeolocation(client: &reqwest::Client, ip: IpAddr) -> Result<GeoInfo> {
    let url = PROVIDERS[2].1.replace("{}", &ip.to_string());
    let resp: IpGeoResponse = client.get(&url).send().await?.error_for_status()?.json().await?;

    let lat = resp.latitude.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let lon = resp.longitude.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0.0);

    Ok(GeoInfo {
        query: resp.ip.unwrap_or_else(|| ip.to_string()),
        country: resp.country_name,
        region: resp.state_prov,
        city: resp.city,
        isp: resp.isp,
        org: resp.organization,
        asn: resp.asn,
        lat: Some(lat),
        lon: Some(lon),
        timezone: resp.time_zone.as_ref().and_then(|t| t.name.clone()),
        zip: resp.zipcode,
    })
}

/// Generate Leaflet.js map HTML for the dashboard/report
pub fn generate_map_html(geo: &GeoInfo, target: &str) -> String {
    // Default coordinates if not available
    let (lat, lon) = if let (Some(city), Some(country)) = (&geo.city, &geo.country) {
        // Use a geocoding approximation for major cities
        approximate_coords(city, country).unwrap_or((0.0, 0.0))
    } else {
        (0.0, 0.0)
    };

    format!(r#"
<div id="geo-map" style="height: 300px; border-radius: 8px; margin: 10px 0;"></div>
<script>
    // Leaflet from CDN
    if (!window.L) {{
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
        document.head.appendChild(link);
        var script = document.createElement('script');
        script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
        script.onload = function() {{ initMap(); }};
        document.head.appendChild(script);
    }} else {{
        initMap();
    }}

    function initMap() {{
        if (window.mapInitialized) return;
        window.mapInitialized = true;
        var map = L.map('geo-map').setView([{}, {}], 10);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '&copy; OpenStreetMap contributors'
        }}).addTo(map);

        var marker = L.marker([{}, {}]).addTo(map);
        var popupContent = '<b>Target:</b> {}<br>' +
            '<b>City:</b> {}<br>' +
            '<b>Region:</b> {}<br>' +
            '<b>Country:</b> {}<br>' +
            '<b>ISP:</b> {}<br>' +
            '<b>ASN:</b> {}';
        marker.bindPopup(popupContent).openPopup();
    }}
</script>
"#, lat, lon, lat, lon, 
    html_escape(target),
    html_escape(geo.city.as_deref().unwrap_or("Unknown")),
    html_escape(geo.region.as_deref().unwrap_or("Unknown")),
    html_escape(geo.country.as_deref().unwrap_or("Unknown")),
    html_escape(geo.isp.as_deref().unwrap_or("Unknown")),
    html_escape(geo.asn.as_deref().unwrap_or("Unknown"))
    )
}

/// Approximate coordinates for major cities (fallback when provider doesn't return lat/lon)
fn approximate_coords(city: &str, country: &str) -> Option<(f64, f64)> {
    let key = format!("{}|{}", city.to_lowercase(), country.to_lowercase());
    let coords = match key.as_str() {
        "new york|united states" => (40.7128, -74.0060),
        "london|united kingdom" => (51.5074, -0.1278),
        "tokyo|japan" => (35.6762, 139.6503),
        "singapore|singapore" => (1.3521, 103.8198),
        "sydney|australia" => (-33.8688, 151.2093),
        "frankfurt|germany" => (50.1109, 8.6821),
        "amsterdam|netherlands" => (52.3676, 4.9041),
        "paris|france" => (48.8566, 2.3522),
        "mumbai|india" => (19.0760, 72.8777),
        "bangalore|india" => (12.9716, 77.5946),
        "delhi|india" => (28.7041, 77.1025),
        "hong kong|hong kong" => (22.3193, 114.1694),
        "seoul|south korea" => (37.5665, 126.9780),
        "toronto|canada" => (43.6532, -79.3832),
        "sao paulo|brazil" => (-23.5505, -46.6333),
        _ => return None,
    };
    Some(coords)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&")
        .replace('<', "<")
        .replace('>', ">")
        .replace('"', "\"")
        .replace('\'', "'")
}

/// Enhanced traceroute with geo IP for each hop
pub async fn enrich_traceroute(hops: &mut [TraceHop]) -> Result<()> {
    for hop in hops.iter_mut() {
        if hop.ip != "*" && hop.ip != "timeout" {
            if let Ok(ip) = hop.ip.parse::<IpAddr>() {
                if let Ok(geo) = geo_lookup(ip).await {
                    hop.host = format!("{} ({}, {})", 
                        hop.host, 
                        geo.city.unwrap_or_default(), 
                        geo.country.unwrap_or_default()
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approximate_coords() {
        assert_eq!(approximate_coords("New York", "United States"), Some((40.7128, -74.0060)));
        assert_eq!(approximate_coords("London", "United Kingdom"), Some((51.5074, -0.1278)));
        assert_eq!(approximate_coords("Unknown", "Unknown"), None);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>alert(1)</script>"), "<script>alert(1)</script>");
        assert_eq!(html_escape("O'Reilly"), "O'Reilly");
    }
}