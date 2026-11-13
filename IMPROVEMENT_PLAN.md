# Night Crawler — Comprehensive Improvement Plan

## Issues to Fix

### 1. UI Loading Completion Bug
**Problem**: Dashboard shows `s.done` but loading indicator may not update properly; progress bar doesn't reach 100%
**Root Cause**: `s.done` is set but progress polling continues, or phase statuses not all marked done
**Fix**: Ensure proper phase completion tracking and progress finalization

### 2. Location/Geo IP Accuracy
**Problem**: Location API endpoints not accurate, no map visualization
**Fix**: 
- Use multiple free geo IP APIs (ip-api.com, ipinfo.io, ipgeolocation.io)
- Add Leaflet.js map to dashboard and HTML report
- Show precise coordinates, ISP, ASN, timezone

### 3. WHOIS Details Accuracy
**Problem**: WHOIS parsing misses fields, referral following incomplete
**Fix**:
- Improved field extraction patterns
- Better referral chain following
- Support for more WHOIS server formats
- Add RDAP support

### 4. Directory Enumeration Accuracy
**Problem**: False positives, misses important paths, soft-404 detection weak
**Fix**:
- Better soft-404 baseline (multiple random probes)
- Enhanced wordlists with technology-specific paths
- Content-based filtering (not just status codes)
- Recursive directory discovery

### 5. API Endpoint Discovery
**Problem**: No dedicated API endpoint discovery
**Fix**:
- Add Swagger/OpenAPI spec discovery
- GraphQL introspection detection
- REST endpoint fuzzing from JS analysis
- API documentation enumeration

### 6. Nmap Integration Enhancement
**Problem**: Limited NSE script selection, no vuln-specific scripts
**Fix**:
- Expand NSE script categories (vuln, auth, exploit, etc.)
- Add `--script-args` for targeted checks
- Parse NSE script output for structured findings
- Integration with CVE mapping

### 7. Vulnerability Mapping & CVE Details
**Problem**: Basic CVE matching, no exploitability assessment
**Fix**:
- Enhanced NVD parsing with CPE matching
- Exploit availability (ExploitDB, Metasploit, Nuclei templates)
- CVSS 4.0 support
- Remediation priority scoring

### 8. Actionable Next Steps
**Problem**: No concrete exploitation recommendations
**Fix**:
- Attack path generation with specific tools/commands
- Prioritized exploitation checklist
- Post-exploitation enumeration suggestions
- Pivot/lateral movement guidance

### 9. Default Model Update
**Change**: Default to `nvidia/nemotron-3.5-lightning-30b-a3b`

### 10. Advanced UI/UX
**Enhancements**:
- Real-time map with geo location
- Interactive attack graph
- Phase timeline visualization
- Findings filter/search
- Export options (PDF, JSON, SARIF)
- Dark/light theme toggle
- Responsive design

## Implementation Order

1. **Core Fixes** (UI loading, geo IP, WHOIS, directory enum)
2. **New Modules** (API endpoint discovery, enhanced nmap)
3. **Vulnerability Engine** (CVE mapping, exploit data, next steps)
4. **UI/UX** (Map, interactive graphs, improved dashboard)
5. **AI Agent** (Model default, better prompts, reasoning)
6. **Reporting** (Enhanced HTML report with map, attack paths)
7. **Testing** (Integration tests, regression tests)