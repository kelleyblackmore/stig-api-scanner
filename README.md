# stig-api-scanner

Automated black-box API security scanner mapped to the **DISA Application Programming Interface (API) Security Requirements Guide V1R0.1** — the first standalone DISA STIG specifically for REST/HTTP APIs.

Pipeline-ready: exits non-zero when findings meet the configured severity threshold. Outputs `text`, `json`, **SARIF 2.1.0**, and **JUnit XML** for integration with GitHub Advanced Security, GitLab SAST, SonarQube, Jenkins, and any CI tool that reads JUnit.

---

## STIG Coverage

| Check module | Controls covered | Auto / Manual |
|---|---|---|
| `transport` | V-274710 (TLS 1.2+), V-274497 (HTTPS enforce), V-274600 (HSTS) | Auto |
| `headers` | V-274600, V-274497, V-274615, V-274767 (security headers) | Auto |
| `cors` | V-274613 (CORS origin allowlist) | Auto |
| `auth` | V-274557, V-274507 (auth bypass), V-274559, V-274643, V-274672, V-274679 | Auto + Manual |
| `tokens` | V-274680, V-274712, V-274678, V-274783, V-274681, V-274603, V-274606 | Auto (JWT) + Manual |
| `rate_limit` | V-274612, V-274682 (active probe optional), V-274525, V-274526 | Auto + Manual |
| `input_validation` | V-274714 (SQL), V-274715 (path traversal / oversize), V-274767 (XSS) | Auto |
| `error_handling` | V-274615 (no stack traces / internal paths in errors) | Auto |
| `cache` | V-274607, V-274709 (pagination), V-274677 (invalidation) | Auto + Manual |

**50 controls total** from the API SRG V1R0.1. Controls that require architecture review (audit logging, ICAM provider, vault integration) are flagged as `MANUAL` with detailed remediation guidance.

---

## Install

```sh
# From source (Rust 1.70+)
cargo build --release
cp target/release/stig-api-scanner /usr/local/bin/

# Or run directly
cargo run -- --config config.yaml
```

---

## Quick start

```sh
cp config.example.yaml config.yaml
# Edit config.yaml with your target URL, auth, and endpoints

export API_BEARER_TOKEN="eyJ..."
stig-api-scanner --config config.yaml
```

---

## Usage

```
stig-api-scanner [OPTIONS]

Options:
  -c, --config <FILE>          YAML config [default: config.yaml]
  -f, --format <FORMAT>        Output format: text|json|sarif|junit [default: text]
  -o, --output <FILE>          Write report to file (default: stdout)
      --include-passed         Show PASS findings too
  -v, --verbose                Print fix text and extra detail
      --fail-severity <LEVEL>  Exit 1 when findings >= this: critical|high|medium|low|info
      --list-checks            Print all available checks with STIG IDs
  -h, --help                   Print help
  -V, --version                Print version
```

---

## Configuration

See [`config.example.yaml`](config.example.yaml) for the full annotated schema.

Key fields:

```yaml
target:
  base_url: "https://api.example.com"

auth:
  type: bearer                      # none | bearer | api_key | basic
  bearer_token: "${API_BEARER_TOKEN}"

endpoints:
  - path: "/api/v1/users"
    methods: ["GET", "POST"]
    auth_required: true

checks:
  allowed_origins:                  # CORS allowlist (empty = flag any)
    - "https://app.example.com"
  rate_limit_probe_count: 50        # 0 = disabled; sends N rapid requests to test 429

pipeline:
  fail_severity: high               # CI gate threshold
  exit_code_on_fail: 1
```

### Environment variable substitution

`${VAR_NAME}` in any config value is replaced with the environment variable at runtime. This keeps secrets out of YAML files committed to version control.

---

## Pipeline integration

### GitHub Actions

```yaml
- name: STIG API Scan
  run: |
    stig-api-scanner \
      --config config.yaml \
      --format sarif \
      --output stig-results.sarif \
      --fail-severity high
  env:
    API_BEARER_TOKEN: ${{ secrets.API_TOKEN }}

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: stig-results.sarif
```

### GitLab CI

```yaml
stig-scan:
  script:
    - stig-api-scanner --config config.yaml --format json --output stig-report.json
  artifacts:
    reports:
      sast: stig-report.json
```

### Jenkins

```groovy
sh 'stig-api-scanner --config config.yaml --format junit --output stig-results.xml'
junit 'stig-results.xml'
```

---

## Output formats

| Format | Use case |
|---|---|
| `text` | Human-readable terminal output with colour |
| `json` | Machine-readable; pipe into `jq` or store as artifact |
| `sarif` | GitHub Advanced Security, VS Code SARIF Viewer |
| `junit` | Jenkins, GitLab, any CI that accepts JUnit XML |

---

## Finding statuses

| Status | Meaning |
|---|---|
| `PASS` | Control satisfied |
| `FAIL` | Control violated — remediation required |
| `MANUAL` | Cannot be verified automatically; human review required |
| `SKIP` | Check disabled in config or prerequisites not met |
| `N/A` | Not applicable to this target |

---

## STIG reference

- **DISA API SRG V1R0.1** — *Application Programming Interface (API) Security Requirements Guide* (draft released for comment 2025, finalised 2026)
- **DISA ASD STIG V6** — *Application Security and Development STIG* (parent document)
- NIST SP 800-53 Rev 5 (underlying control framework)

---

## Caveats

- This tool performs **read-only black-box probing**. It does not exploit vulnerabilities or modify data.
- Input validation probes use **safe, benign payloads** designed to detect error patterns, not to extract data or cause damage.
- Passing all automated checks does not constitute an ATO. Manual findings and architecture-level controls must be addressed separately.
- Verify STIG control IDs against the version of the SRG in effect for your accreditation boundary — DISA renumbers controls between releases.
