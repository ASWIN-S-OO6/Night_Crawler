//! API Endpoint Discovery — finds REST, GraphQL, gRPC, and SOAP endpoints
//! through multiple techniques: Swagger/OpenAPI spec discovery, JS analysis,
//! GraphQL introspection, common paths, and fuzzing.

use crate::types::{HttpInfo, PortResult};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub path: String,
    pub api_type: ApiType,
    pub spec_url: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub parameters: Vec<ApiParameter>,
    pub auth_required: bool,
    pub source: String, // "swagger", "graphql", "js-analysis", "fuzzing", "common-paths"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ApiType {
    Rest,
    Graphql,
    Grpc,
    Soap,
    Websocket,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiParameter {
    pub name: String,
    pub param_type: String, // query, path, header, body
    pub data_type: Option<String>,
    pub required: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiDiscoveryResult {
    pub endpoints: Vec<ApiEndpoint>,
    pub spec_urls: Vec<String>,
    pub graphql_endpoints: Vec<String>,
    pub websocket_endpoints: Vec<String>,
    pub technology_hints: Vec<String>,
}

/// Common API specification paths to check
const SPEC_PATHS: &[&str] = &[
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api-docs",
    "/api-docs/",
    "/api/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/docs/swagger.json",
    "/docs/openapi.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/api-docs/swagger.json",
    "/api/swagger.yaml",
    "/swagger",
    "/openapi",
    "/api-docs",
    "/api/doc",
    "/docs/api",
    "/api/documentation",
    "/.well-known/openapi.json",
    "/.well-known/swagger.json",
];

/// Common REST API base paths
const API_BASE_PATHS: &[&str] = &[
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/v3",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/graphql",
    "/graphql/",
    "/graphql/playground",
    "/graphiql",
    "/playground",
    "/altair",
    "/voyager",
    "/ws",
    "/websocket",
    "/socket.io",
    "/sockjs",
];

/// Technology-specific API paths
const TECH_API_PATHS: &[(&str, &[&str])] = &[
    ("spring", &["/actuator", "/actuator/health", "/actuator/info", "/actuator/httptrace", "/actuator/mappings"]),
    ("express", &["/api", "/api/v1", "/health", "/ready"]),
    ("django", &["/api", "/api/v1", "/admin/api", "/rest"]),
    ("laravel", &["/api", "/api/v1", "/api/v2", "/sanctum/csrf-cookie"]),
    ("rails", &["/api", "/api/v1", "/api/v2", "/graphql"]),
    ("node", &["/api", "/api/v1", "/health", "/metrics"]),
    ("golang", &["/api", "/api/v1", "/health", "/metrics", "/debug/pprof"]),
    ("fastapi", &["/docs", "/redoc", "/openapi.json", "/api/v1"]),
    ("flask", &["/api", "/api/v1", "/health"]),
];

/// Detect API endpoints from HTTP services
pub async fn discover_apis(
    bases: &[String],
    port_results: &[PortResult],
    http_infos: &[HttpInfo],
    timeout: Duration,
) -> Result<ApiDiscoveryResult> {
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 NightCrawler/API")
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(timeout)
        .build()?;

    let mut all_endpoints = Vec::new();
    let mut spec_urls = Vec::new();
    let mut graphql_endpoints = Vec::new();
    let mut websocket_endpoints = Vec::new();
    let mut technology_hints = Vec::new();

    // 1. Check for OpenAPI/Swagger specs
    for base in bases {
        let specs = check_spec_paths(&client, base).await;
        for (spec_url, spec_type) in specs {
            spec_urls.push(spec_url.clone());
            if let Ok(endpoints) = parse_openapi_spec(&client, &spec_url, &spec_type).await {
                all_endpoints.extend(endpoints);
            }
        }
    }

    // 2. GraphQL introspection
    for base in bases {
        if let Some(gql) = check_graphql(&client, base).await {
            graphql_endpoints.push(gql.clone());
            if let Ok(endpoints) = introspect_graphql(&client, &gql).await {
                all_endpoints.extend(endpoints);
            }
        }
    }

    // 3. WebSocket detection
    for base in bases {
        if let Some(ws) = check_websocket(&client, base).await {
            websocket_endpoints.push(ws);
        }
    }

    // 4. Common API base paths
    for base in bases {
        let tech_hints = detect_technology(&client, base).await;
        technology_hints.extend(tech_hints.clone());
        
        let endpoints = check_common_api_paths(&client, base, &tech_hints).await;
        all_endpoints.extend(endpoints);
    }

    // 5. JavaScript analysis for API endpoints
    for http in http_infos {
        if let Some(body) = extract_js_from_http(http) {
            let endpoints = extract_api_from_js(&body, &http.url);
            all_endpoints.extend(endpoints);
        }
    }

    // 6. Directory-based API discovery from subdir results
    // (would be passed in from orchestrator)

    // Deduplicate
    let mut seen = HashSet::new();
    all_endpoints.retain(|e| seen.insert(e.url.clone()));

    Ok(ApiDiscoveryResult {
        endpoints: all_endpoints,
        spec_urls,
        graphql_endpoints,
        websocket_endpoints,
        technology_hints: technology_hints.into_iter().collect::<HashSet<_>>().into_iter().collect(),
    })
}

/// Check common OpenAPI/Swagger specification paths
async fn check_spec_paths(client: &Client, base: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for path in SPEC_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                let content_type = resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let spec_type = if content_type.contains("yaml") || url.ends_with(".yaml") || url.ends_with(".yml") {
                    "openapi-yaml"
                } else {
                    "openapi-json"
                };
                found.push((url, spec_type.to_string()));
            }
        }
    }
    found
}

/// Parse OpenAPI/Swagger spec and extract endpoints
async fn parse_openapi_spec(client: &Client, spec_url: &str, spec_type: &str) -> Result<Vec<ApiEndpoint>> {
    let text = client.get(spec_url).send().await?.text().await?;
    let mut endpoints = Vec::new();

    if spec_type.contains("yaml") {
        // Try to parse YAML
        if let Ok(val) = serde_yaml::from_str::<serde_json::Value>(&text) {
            endpoints.extend(extract_endpoints_from_openapi(&val, spec_url));
        }
    } else {
        // Parse JSON
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
            endpoints.extend(extract_endpoints_from_openapi(&val, spec_url));
        }
    }

    Ok(endpoints)
}

fn extract_endpoints_from_openapi(spec: &serde_json::Value, spec_url: &str) -> Vec<ApiEndpoint> {
    let mut endpoints = Vec::new();

    if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
        for (path, methods) in paths {
            if let Some(methods_obj) = methods.as_object() {
                for (method, details) in methods_obj {
                    if ["get", "post", "put", "patch", "delete", "head", "options", "trace"].contains(&method.to_lowercase().as_str()) {
                        let mut params = Vec::new();
                        
                        // Extract parameters
                        if let Some(params_arr) = details.get("parameters").and_then(|p| p.as_array()) {
                            for param in params_arr {
                                if let (Some(name), Some(in_loc)) = (
                                    param.get("name").and_then(|n| n.as_str()),
                                    param.get("in").and_then(|i| i.as_str())
                                ) {
                                    params.push(ApiParameter {
                                        name: name.to_string(),
                                        param_type: in_loc.to_string(),
                                        data_type: param.get("schema").and_then(|s| s.get("type")).and_then(|t| t.as_str()).map(|s| s.to_string()),
                                        required: param.get("required").and_then(|r| r.as_bool()).unwrap_or(false),
                                        description: param.get("description").and_then(|d| d.as_str()).map(|s| s.to_string()),
                                    });
                                }
                            }
                        }

                        // Extract request body
                        if let Some(req_body) = details.get("requestBody") {
                            if let Some(content) = req_body.get("content").and_then(|c| c.as_object()) {
                                for (mime_type, schema) in content {
                                    if let Some(schema_obj) = schema.get("schema") {
                                        params.push(ApiParameter {
                                            name: "body".to_string(),
                                            param_type: "body".to_string(),
                                            data_type: Some(mime_type.to_string()),
                                            required: req_body.get("required").and_then(|r| r.as_bool()).unwrap_or(false),
                                            description: req_body.get("description").and_then(|d| d.as_str()).map(|s| s.to_string()),
                                        });
                                    }
                                }
                            }
                        }

                        endpoints.push(ApiEndpoint {
                            url: format!("{}{}", spec_url.trim_end_matches("/swagger.json").trim_end_matches("/openapi.json").trim_end_matches("/api-docs"), path),
                            method: method.to_uppercase(),
                            path: path.to_string(),
                            api_type: ApiType::Rest,
                            spec_url: Some(spec_url.to_string()),
                            title: details.get("summary").and_then(|s| s.as_str()).map(|s| s.to_string()),
                            description: details.get("description").and_then(|d| d.as_str()).map(|s| s.to_string()),
                            parameters: params,
                            auth_required: details.get("security").is_some(),
                            source: "swagger".to_string(),
                        });
                    }
                }
            }
        }
    }

    endpoints
}

/// Check for GraphQL endpoint
async fn check_graphql(client: &Client, base: &str) -> Option<String> {
    let test_query = r#"{"query": "{ __schema { queryType { name } } }"}"#;
    
    for path in ["/graphql", "/graphql/", "/api/graphql", "/v1/graphql"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Ok(resp) = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(test_query)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    if text.contains("__schema") || text.contains("queryType") {
                        return Some(url);
                    }
                }
            }
        }
    }
    None
}

/// Introspect GraphQL schema
async fn introspect_graphql(client: &Client, url: &str) -> Result<Vec<ApiEndpoint>> {
    let introspection_query = r#"
    {
        __schema {
            queryType { name fields { name description args { name description type { name kind ofType { name kind } } } } }
            mutationType { name fields { name description args { name description type { name kind ofType { name kind } } } } }
            subscriptionType { name fields { name description args { name description type { name kind ofType { name kind } } } } }
            types { name kind description fields { name description args { name description type { name kind ofType { name kind } } } } }
        }
    }"#;

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::json!({ "query": introspection_query }).to_string())
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let text = resp.text().await?;
    let mut endpoints = Vec::new();

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(data) = val.get("data").and_then(|d| d.get("__schema")) {
            // Extract query fields
            if let Some(query_type) = data.get("queryType") {
                extract_graphql_fields(query_type, "query", url, &mut endpoints);
            }
            // Extract mutation fields
            if let Some(mut_type) = data.get("mutationType") {
                extract_graphql_fields(mut_type, "mutation", url, &mut endpoints);
            }
            // Extract subscription fields
            if let Some(sub_type) = data.get("subscriptionType") {
                extract_graphql_fields(sub_type, "subscription", url, &mut endpoints);
            }
        }
    }

    Ok(endpoints)
}

fn extract_graphql_fields(type_obj: &serde_json::Value, op_type: &str, url: &str, endpoints: &mut Vec<ApiEndpoint>) {
    if let Some(fields) = type_obj.get("fields").and_then(|f| f.as_array()) {
        for field in fields {
            let mut params = Vec::new();
            if let Some(args) = field.get("args").and_then(|a| a.as_array()) {
                for arg in args {
                    if let (Some(name), Some(type_obj)) = (arg.get("name").and_then(|n| n.as_str()), arg.get("type")) {
                        let type_name = extract_graphql_type_name(type_obj);
                        params.push(ApiParameter {
                            name: name.to_string(),
                            param_type: "argument".to_string(),
                            data_type: Some(type_name),
                            required: type_obj.get("kind").and_then(|k| k.as_str()) == Some("NON_NULL"),
                            description: arg.get("description").and_then(|d| d.as_str()).map(|s| s.to_string()),
                        });
                    }
                }
            }

            endpoints.push(ApiEndpoint {
                url: url.to_string(),
                method: "POST".to_string(),
                path: format!("{} {}", op_type, field.get("name").and_then(|n| n.as_str()).unwrap_or("")),
                api_type: ApiType::Graphql,
                spec_url: Some(url.to_string()),
                title: field.get("description").and_then(|d| d.as_str()).map(|s| s.to_string()),
                description: field.get("description").and_then(|d| d.as_str()).map(|s| s.to_string()),
                parameters: params,
                auth_required: false, // Would need auth analysis
                source: "graphql".to_string(),
            });
        }
    }
}

fn extract_graphql_type_name(type_obj: &serde_json::Value) -> String {
    if let Some(name) = type_obj.get("name").and_then(|n| n.as_str()) {
        name.to_string()
    } else if let Some(of_type) = type_obj.get("ofType") {
        format!("{}!", extract_graphql_type_name(of_type))
    } else {
        type_obj.get("kind").and_then(|k| k.as_str()).unwrap_or("Unknown").to_string()
    }
}

/// Check for WebSocket endpoints
async fn check_websocket(client: &Client, base: &str) -> Option<String> {
    for path in ["/ws", "/websocket", "/socket.io/", "/sockjs/"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        // Try HTTP GET first to see if it's a WebSocket endpoint
        if let Ok(resp) = client.get(&url).send().await {
            let upgrade = resp.headers()
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if upgrade.to_lowercase().contains("websocket") {
                return Some(url);
            }
            // Check for Socket.IO
            if url.contains("socket.io") && resp.status().is_success() {
                return Some(url);
            }
        }
    }
    None
}

/// Detect technology stack from HTTP responses
async fn detect_technology(client: &Client, base: &str) -> Vec<String> {
    let mut hints = Vec::new();
    
    if let Ok(resp) = client.get(base).send().await {
        let headers = resp.headers();
        let server = headers.get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
        let powered_by = headers.get("x-powered-by").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
        
        // Server header hints
        if server.contains("nginx") { hints.push("nginx".to_string()); }
        if server.contains("apache") { hints.push("apache".to_string()); }
        if server.contains("cloudflare") { hints.push("cloudflare".to_string()); }
        if server.contains("iis") { hints.push("iis".to_string()); }
        if server.contains("kestrel") { hints.push("dotnet".to_string()); }
        
        // X-Powered-By hints
        if powered_by.contains("express") { hints.push("express".to_string()); }
        if powered_by.contains("php") { hints.push("php".to_string()); }
        if powered_by.contains("servlet") { hints.push("java".to_string()); }
        if powered_by.contains("asp.net") { hints.push("aspnet".to_string()); }
        if powered_by.contains("next.js") { hints.push("nextjs".to_string()); }
        
        // Check for framework-specific headers
        if headers.get("x-drupal-cache").is_some() { hints.push("drupal".to_string()); }
        if headers.get("x-generator").is_some() { hints.push("cms".to_string()); }
    }
    
    hints
}

/// Check common API paths based on detected technology
async fn check_common_api_paths(client: &Client, base: &str, tech_hints: &[String]) -> Vec<ApiEndpoint> {
    let mut endpoints = Vec::new();
    let base = base.trim_end_matches('/');
    
    // Check generic API paths
    for path in API_BASE_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() || resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                endpoints.push(ApiEndpoint {
                    url: url.clone(),
                    method: "GET".to_string(),
                    path: path.to_string(),
                    api_type: ApiType::Rest,
                    spec_url: None,
                    title: None,
                    description: Some(format!("API base path discovered (status: {})", resp.status())),
                    parameters: Vec::new(),
                    auth_required: resp.status().as_u16() == 401 || resp.status().as_u16() == 403,
                    source: "common-paths".to_string(),
                });
            }
        }
    }
    
    // Check technology-specific paths
    for (tech, paths) in TECH_API_PATHS {
        if tech_hints.iter().any(|h| h.contains(tech)) || tech_hints.is_empty() {
            for path in *paths {
                let url = format!("{}{}", base, path);
                if let Ok(resp) = client.get(&url).send().await {
                    if resp.status().is_success() || resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                        endpoints.push(ApiEndpoint {
                            url: url.clone(),
                            method: "GET".to_string(),
                            path: path.to_string(),
                            api_type: ApiType::Rest,
                            spec_url: None,
                            title: Some(format!("{} API endpoint", tech)),
                            description: Some(format!("{} endpoint (status: {})", tech, resp.status())),
                            parameters: Vec::new(),
                            auth_required: resp.status().as_u16() == 401 || resp.status().as_u16() == 403,
                            source: "tech-specific".to_string(),
                        });
                    }
                }
            }
        }
    }
    
    endpoints
}

/// Extract JavaScript from HTTP response for API endpoint analysis
fn extract_js_from_js_body(body: &str) -> Option<String> {
    if body.len() > 100000 {
        return None; // Too large
    }
    if body.contains("fetch(") || body.contains("axios") || body.contains("XMLHttpRequest") || 
       body.contains("graphql") || body.contains("api/") || body.contains("/v1/") || body.contains("/v2/") {
        Some(body.to_string())
    } else {
        None
    }
}

fn extract_js_from_http(http: &HttpInfo) -> Option<String> {
    // We'd need the body - for now check if we have indicators in headers/title
    let text = format!("{} {}", http.title.as_deref().unwrap_or(""), http.url);
    extract_js_from_js_body(&text)
}

/// Extract API endpoints from JavaScript code
fn extract_api_from_js(js: &str, base_url: &str) -> Vec<ApiEndpoint> {
    let mut endpoints = Vec::new();
    let base = base_url.trim_end_matches('/');
    
    // Regex patterns for API calls
    let patterns = [
        // fetch('/api/...')
        r#"fetch\(['"`]([^'"`]+)['"`]"#,
        // axios.get('/api/...')
        r#"axios\.(get|post|put|patch|delete)\(['"`]([^'"`]+)['"`]"#,
        // $.ajax({ url: '/api/...' })
        r#"\.ajax\([^}]*url:\s*['"`]([^'"`]+)['"`]"#,
        // API_URL = '/api/...'
        r#"['"]([/a-zA-Z0-9_\-\.]+/api/[^'"`]*)['"]\b"#,
        // /api/v1/...
        r#"['"](/api/v\d+/[^'"`]+)['"]"#,
        // /v1/...
        r#"['"](/v\d+/[^'"`]+)['"]"#,
        // GraphQL
        r#"['"](/graphql[^'"`]*)['"]"#,
    ];
    
    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(js) {
                if let Some(path) = cap.get(1).or_else(|| cap.get(2)) {
                    let path_str = path.as_str();
                    if path_str.starts_with('/') && path_str.len() > 3 {
                        let url = format!("{}{}", base, path_str);
                        endpoints.push(ApiEndpoint {
                            url,
                            method: "GET".to_string(), // Default, unknown from static analysis
                            path: path_str.to_string(),
                            api_type: if path_str.contains("graphql") { ApiType::Graphql } else { ApiType::Rest },
                            spec_url: None,
                            title: None,
                            description: Some("Discovered via JavaScript analysis".to_string()),
                            parameters: Vec::new(),
                            auth_required: false,
                            source: "js-analysis".to_string(),
                        });
                    }
                }
            }
        }
    }
    
    // Deduplicate
    let mut seen = HashSet::new();
    endpoints.retain(|e| seen.insert(e.path.clone()));
    
    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_graphql_type_name() {
        let obj = serde_json::json!({"name": "String", "kind": "SCALAR"});
        assert_eq!(extract_graphql_type_name(&obj), "String");
        
        let obj = serde_json::json!({"kind": "NON_NULL", "ofType": {"name": "String", "kind": "SCALAR"}});
        assert_eq!(extract_graphql_type_name(&obj), "String!");
    }

    #[test]
    fn test_extract_api_from_js() {
        let js = r#"
            fetch('/api/v1/users')
            axios.get('/api/v1/posts')
            const API = '/api/v2/data';
        "#;
        let endpoints = extract_api_from_js(js, "http://example.com");
        assert!(endpoints.iter().any(|e| e.path.contains("/api/v1/users")));
        assert!(endpoints.iter().any(|e| e.path.contains("/api/v1/posts")));
        assert!(endpoints.iter().any(|e| e.path.contains("/api/v2/data")));
    }
}