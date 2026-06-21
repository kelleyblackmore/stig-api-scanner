# stig-api-scanner

Automated black-box compliance scanner for the **DISA Application Programming Interface (API) Security Requirements Guide V1R0.1** (V-274XXX controls).

Runs a suite of HTTP checks against a live API endpoint and reports findings mapped to DISA control IDs. Designed for CI/CD pipeline integration — exits non-zero when findings meet or exceed a configurable severity threshold.

## Features

- **9 check modules** covering 30+ automatable controls
- **YAML configuration** with `${ENV_VAR}` substitution for secrets
- **Four output formats**: colored text, JSON, SARIF 2.1.0, JUnit XML
- **Pipeline gate**: configurable `fail_severity` (high/medium/low/info/critical)
- **Manual findings**: non-automatable controls are surfaced with fix guidance rather than silently skipped
- **SARIF upload**: integrates with GitHub Code Scanning / Security tab

## Check Modules

| Module | Controls |
|---|---|
| `transport` | TLS required (V-274497), HTTP→HTTPS redirect (V-274498), HSTS (V-274499) |
| `headers` | Server header (V-274500), X-Frame-Options/CSP (V-274501), X-Content-Type-Options (V-274502), Referrer-Policy |
| `cors` | Wildcard ACAO (V-274503), origin reflection with credentials |
| `auth` | Unauthenticated access (V-274511), privilege escalation (V-274512) |
| `tokens` | JWT algorithm confusion, expiry, key strength |
| `rate_limit` | Rate-limit headers (V-274515), active 429 probe |
| `input_validation` | SQLi (V-274520), XSS, command injection, XXE, buffer overflow |
| `error_handling` | Stack trace leakage (V-274525), malformed payload handling |
| `cache` | Cache-Control on authenticated responses (V-274530) |

## Installation

```bash
cargo build --release
# binary at target/release/stig-api-scanner
```

Requires Rust 1.70+. Uses `rustls` (no OpenSSL dependency).

## Usage

```bash
stig-api-scanner --config config.yaml

# Extra options
stig-api-scanner --config config.yaml \
  --format sarif \
  --output results.sarif \
  --include-passed \
  --verbose \
  --fail-severity high
```

```
Options:
  -c, --config <FILE>        Path to YAML config [default: config.yaml]
  -f, --format <FORMAT>      Output format: text|json|sarif|junit [default: text]
  -o, --output <FILE>        Write report to file instead of stdout
      --include-passed       Include PASS findings in output
  -v, --verbose              Print fix text and error context
      --fail-severity <SEV>  Minimum severity for non-zero exit [default: high]
      --list-checks          Print all available checks and exit
```

## Configuration

```yaml
target:
  base_url: "https://api.example.com"
  timeout_seconds: 10
  verify_tls: true

auth:
  type: bearer                   # bearer | apikey | basic | none
  bearer_token: "${API_TOKEN}"   # ${ENV_VAR} expanded at load time

endpoints:
  - path: "/api/v1/users"
    auth_required: true
    tags: ["users"]

checks:
  transport: true
  cors: true
  auth: true
  tokens: false
  rate_limiting: true
  input_validation: true
  error_handling: true
  cache: true
  headers: true
  allowed_origins: ["https://app.example.com"]
  rate_limit_probe_count: 0      # set > 0 to enable active 429 probe

report:
  format: text
  include_passed: false
  verbose: false

pipeline:
  fail_severity: high
  exit_code_on_fail: 1
```

## CI/CD Integration

The bundled GitHub Actions workflow (`.github/workflows/ci.yml`) demonstrates a complete pipeline:

1. Build & lint (fmt, clippy, release)
2. Generate a self-signed TLS cert
3. Start the bundled intentionally-insecure example API (`examples/test-api/server.py`)
4. Run four scan passes (text, JSON, SARIF, JUnit)
5. Upload SARIF to GitHub Security tab
6. Publish JUnit results as a check annotation
7. Gate the pipeline on `fail_severity: critical`

```yaml
- name: Run STIG scan
  run: |
    ./stig-api-scanner \
      --config config.yaml \
      --format sarif \
      --output results.sarif
  env:
    API_TOKEN: ${{ secrets.API_TOKEN }}

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
    category: stig-api-scan
```

## Example Output

```
[FAIL] V-274497  HIGH    Protect confidentiality and integrity in transit — TLS required
       Endpoint : http://api.example.com/
       Evidence : Endpoint reachable over plain HTTP (no TLS)
       Fix      : Disable HTTP listeners. Enforce HTTPS at the load balancer or
                  application layer. Redirect all HTTP traffic to HTTPS.

[PASS] V-274499  MEDIUM  Protect integrity of remote access sessions — HSTS
       Endpoint : https://api.example.com/
       Evidence : Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## Relationship to stig-asd-scanner

[stig-asd-scanner](https://github.com/kelleyblackmore/stig-asd-scanner) targets the DISA **ASD STIG V6R4** (application security development controls, V-222XXX). This tool targets the DISA **API SRG V1R0.1** (REST/HTTP API-specific controls, V-274XXX). They are complementary: the ASD STIG covers a broader set of web application security behaviors; the API SRG focuses narrowly on REST API design.

## License

[MIT](LICENSE)
