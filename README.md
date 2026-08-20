# SubShark

 $$$$$$\  $$\   $$\ $$$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\  $$$$$$$\  $$\   $$\ 
$$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$ | $$  |
$$ /  \__|$$ |  $$ |$$ |  $$ |$$ /  \__|$$ |  $$ |$$ /  $$ |$$ |  $$ |$$ |$$  / 
\$$$$$$\  $$ |  $$ |$$$$$$$\ |\$$$$$$\  $$$$$$$$ |$$$$$$$$ |$$$$$$$  |$$$$$  /  
 \____$$\ $$ |  $$ |$$  __$$\  \____$$\ $$  __$$ |$$  __$$ |$$  __$$< $$  $$<   
$$\   $$ |$$ |  $$ |$$ |  $$ |$$\   $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |\$$\  
\$$$$$$  |\$$$$$$  |$$$$$$$  |\$$$$$$  |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ | \$$\ 
 \______/  \______/ \_______/  \______/ \__|  \__|\__|  \__|\__|  \__|\__|  \__|

> A fast, concurrent subdomain takeover scanner that identifies potential hijacking vulnerabilities by matching HTTP response bodies against predefined service fingerprints.

**Developed by D-XPL01T**

---

## Overview

**SubShark** is a lightweight Python-based scanner designed to detect potential **subdomain takeover** vulnerabilities.

It accepts one or more domains/subdomains through standard input, probes them over HTTP/HTTPS, and compares their response bodies against a configurable collection of service-specific fingerprints.

SubShark is designed to be:

- **Fast** — concurrent scanning with configurable workers
- **Simple** — Python standard library only
- **Flexible** — service inclusion/exclusion and custom fingerprints
- **Automation-friendly** — JSON and file output support
- **Resilient** — crash-safe resume functionality
- **Easy to customize** — fingerprint definitions are stored in JSON

> **Important:** A fingerprint match indicates a **potential** takeover condition. Always manually validate findings before treating them as confirmed vulnerabilities.

---

## Features

| Feature | Description |
|---|---|
| 🚀 **Fast Concurrent Scanning** | Scan multiple subdomains in parallel with configurable concurrency. |
| 🎨 **Colored Output** | Color-coded terminal output for easier result identification. |
| 📊 **JSON Output** | Export findings as structured JSON for automation and further processing. |
| 💾 **File Output** | Save unique findings to a file with automatic deduplication. |
| 🔍 **Protocol Fallback** | Tries HTTPS first, then HTTP when HTTPS fails. |
| 🎯 **Service Filtering** | Include only selected services or exclude specific services. |
| 📁 **Automatic Configuration** | Downloads `fingerprints.json` automatically when the default file is missing. |
| 🔧 **Customizable** | Extensive command-line options for fine-grained control. |
| ♻️ **Crash-Safe Resume** | Resume interrupted stdin scans using `resume.cfg`. |
| 🧩 **Custom Fingerprints** | Use your own fingerprint database with `--fingerprints`. |
| 🐍 **Zero External Dependencies** | Uses only Python's standard library. |

---

## Requirements

- Python **3.8+**
- Internet/network connectivity for HTTP/HTTPS probing
- A list of domains or subdomains to scan

No third-party Python packages are required.

---

## Installation

### Clone the Repository

```bash
git clone https://github.com/D-XPL01T/Subshark.git
cd Subshark
```

### Make the Script Executable

```bash
chmod +x subshark.py
```

### Verify the Installation

```bash
python3 subshark.py --version
```

---

## Usage

SubShark reads targets from **standard input**.

### Scan a Single URL

```bash
echo "https://example.com" | python3 subshark.py
```

### Scan Multiple URLs

```bash
cat subdomains.txt | python3 subshark.py
```

### Scan a Domain Without a Scheme

When a target does not include `http://` or `https://`, SubShark automatically attempts:

1. `https://`
2. `http://` if HTTPS fails

Example:

```bash
echo "example.com" | python3 subshark.py
```

---

## Output

### Default Output Format

```text
[service] [severity] url [fingerprint]
```

### Example

```text
[Github] [high] https://achangpro.com [There isn't a GitHub Pages site here.]
[AWS/S3] [high] https://bucket.s3.amazonaws.com [The specified bucket does not exist, BucketName]
```

> The presence of a matching fingerprint does not by itself prove that a subdomain is exploitable. Verify the DNS configuration, service ownership, and provider-specific takeover requirements.

---

## Command-Line Options

### Core Options

| Flag | Short | Description | Default |
|---|---|---|---|
| `--timeout` | — | HTTP request timeout in seconds. | `30` |
| `--User-Agent` | `-H` | Custom `User-Agent` header. | Chrome-style user agent |
| `--concurrency` | — | Number of concurrent subdomain checks. | `50` |
| `--fingerprints` | — | Path to a custom `fingerprints.json`. | `~/.config/subshark/fingerprints.json` |
| `--verbose` | — | Show verbose status information. | Disabled |
| `--version` | — | Print the current version and exit. | — |
| `--silent` | — | Disable the banner. | Disabled |
| `--no-resume` | — | Disable resume support and start a fresh scan. | Disabled |

### Output Options

| Flag | Description |
|---|---|
| `--json` | Output results in JSON format. |
| `--output <file>` | Save unique findings to a file while continuing to print them to stdout. |
| `--nc` | Disable colored terminal output. |

### Service Filtering

| Flag | Description | Example |
|---|---|---|
| `--es` | Exclude services from fingerprint matching. Comma-separated and case-sensitive. | `--es "Cargo Collective, Clever Cloud"` |
| `--onlycheck` | Check only the specified services. Comma-separated and case-sensitive. | `--onlycheck "Github, AWS/S3"` |

> `--es` and `--onlycheck` are mutually exclusive.

---

## Examples

### Basic Scanning

```bash
echo "https://achangpro.com" | python3 subshark.py
```

### Scan a File of Subdomains

```bash
cat subdomains.txt | python3 subshark.py
```

### Start Fresh Without Resuming

```bash
cat subdomains.txt | python3 subshark.py --no-resume
```

### Custom Timeout and Concurrency

```bash
cat subdomains.txt | python3 subshark.py --timeout 60 --concurrency 100
```

### Exclude Specific Services

```bash
echo "https://example.com" | \
  python3 subshark.py \
  --es "Cargo Collective, Clever Cloud" \
  --verbose
```

Verbose output:

```text
[*] Excluded services: Cargo Collective, Clever Cloud
```

### Only Check Specific Services

```bash
echo "https://example.com" | \
  python3 subshark.py \
  --onlycheck "Github, AWS/S3" \
  --verbose
```

Verbose output:

```text
[*] Only checking services: Github, AWS/S3
```

### JSON Output

```bash
cat subdomains.txt | python3 subshark.py --json
```

### Save Results to a File

```bash
cat subdomains.txt | python3 subshark.py --output results.txt --verbose
```

### Custom User-Agent

```bash
cat subdomains.txt | \
  python3 subshark.py \
  -H "MyCustomUserAgent/1.0"
```

### Custom Fingerprint Database

```bash
cat subdomains.txt | \
  python3 subshark.py \
  --fingerprints /path/to/custom/fingerprints.json
```

### Disable Colors

```bash
cat subdomains.txt | python3 subshark.py --nc
```

### Silent Mode

```bash
cat subdomains.txt | python3 subshark.py --silent
```

### Verbose Mode

```bash
cat subdomains.txt | python3 subshark.py --verbose
```

---

## JSON Output

With `--json`, SubShark produces structured output suitable for scripting, pipelines, and automation.

Example:

```json
[
  {
    "service": "Github",
    "severity": "high",
    "url": "https://achangpro.com",
    "fingerprint": [
      "There isn't a GitHub Pages site here."
    ]
  },
  {
    "service": "AWS/S3",
    "severity": "high",
    "url": "https://bucket.s3.amazonaws.com",
    "fingerprint": [
      "The specified bucket does not exist",
      "BucketName"
    ]
  }
]
```

---

## File Output

The `--output` option:

- Saves findings to the specified file.
- Continues printing findings to stdout.
- Deduplicates results using the **URL + service** combination.
- Reports the number of unique saved findings when `--verbose` is enabled.

Example:

```bash
cat subdomains.txt | python3 subshark.py --output results.txt --verbose
```

---

## Fingerprints

SubShark uses a JSON-based fingerprint database to identify known service responses associated with potential takeover conditions.

### Default Location

```text
~/.config/subshark/fingerprints.json
```

### Automatic Download

When the default fingerprint file does not exist, SubShark:

1. Creates the configuration directory:
   ```text
   ~/.config/subshark/
   ```
2. Downloads `fingerprints.json` from the configured repository URL.
3. Uses the downloaded fingerprint database for scanning.

> **Maintainer note:** Update the download URL in `subshark.py` so that it points to the raw `fingerprints.json` hosted by your own repository.

### Custom Fingerprints

Specify a custom fingerprint database with:

```bash
python3 subshark.py --fingerprints /path/to/custom/fingerprints.json
```

---

## Fingerprint Format

A fingerprint entry follows this structure:

```json
[
  {
    "service": "Github",
    "severity": "high",
    "url": "https://example.com",
    "fingerprint": [
      "There isn't a GitHub Pages site here.",
      "For root URLs (like http://example.com/) you must provide an index.html file"
    ],
    "matchcondition": "ANY"
  },
  {
    "service": "AWS/S3",
    "severity": "high",
    "url": "https://another.example.com",
    "fingerprint": [
      "The specified bucket does not exist",
      "BucketName"
    ],
    "matchcondition": "ALL"
  }
]
```

### Fingerprint Fields

| Field | Description |
|---|---|
| `service` | Name of the service/provider. |
| `severity` | Severity assigned to a matching fingerprint. |
| `url` | Example or reference URL associated with the fingerprint. |
| `fingerprint` | Array of strings used to match against the HTTP response body. |
| `matchcondition` | Determines whether **any** or **all** fingerprint strings must match. |

### Match Conditions

#### `ANY`

A result is generated when **at least one** fingerprint string appears in the response body.

```json
"matchcondition": "ANY"
```

#### `ALL`

A result is generated only when **every** fingerprint string appears in the response body.

```json
"matchcondition": "ALL"
```

---

## Protocol Fallback

For input targets without an explicit URL scheme, SubShark performs the following sequence:

```text
Target: example.com

1. https://example.com
2. http://example.com   (only if HTTPS fails)
```

If both attempts fail, the target is skipped and scanning continues.

---

## Resume Functionality

SubShark enables resume support by default when reading targets from stdin.

Progress is stored in:

```text
resume.cfg
```

The file uses a simple statistics format:

```ini
scanned=300000
```

### How Resume Works

If a scan is interrupted because of:

- `CTRL+C`
- terminal closure
- system restart
- another unexpected interruption

SubShark stores the number of processed targets and can continue from that point during the next run.

Run the same command again from the same directory:

```bash
cat subdomains.txt | python3 subshark.py
```

The scanner will skip the already-processed targets and continue scanning from the saved position.

### Disable Resume

To ignore an existing `resume.cfg` and start from the beginning:

```bash
cat subdomains.txt | python3 subshark.py --no-resume
```

### Successful Completion

After a scan completes successfully, `resume.cfg` is automatically removed.

---

## Interrupt Handling

SubShark handles `CTRL+C` gracefully.

On the first interrupt:

- Pending tasks are cancelled.
- Current progress is saved.
- Resume information is written to `resume.cfg`.
- A message is displayed explaining how to continue.

To resume:

```bash
cat subdomains.txt | python3 subshark.py
```

---

## Verbose Mode

Use `--verbose` to display additional runtime information.

Depending on the operation, verbose mode may show:

```text
[*] Config directory: ~/.config/subshark/
[*] Downloading fingerprints.json...
[*] Excluded services: Cargo Collective, Clever Cloud
[*] Only checking services: Github, AWS/S3
[*] Unique results saved: 42
```

---

## Service Filtering

### Exclude Services

```bash
python3 subshark.py --es "Cargo Collective, Clever Cloud"
```

### Allow Only Selected Services

```bash
python3 subshark.py --onlycheck "Github, AWS/S3"
```

Service names are **case-sensitive**.

The two filtering modes cannot be used together:

```text
--es
```

and

```text
--onlycheck
```

---

## Recommended Workflow

A typical SubShark workflow looks like this:

```bash
# 1. Collect subdomains
cat subdomains.txt

# 2. Scan with default settings
cat subdomains.txt | python3 subshark.py

# 3. Save results
cat subdomains.txt | python3 subshark.py --output results.txt

# 4. Export JSON for automation
cat subdomains.txt | python3 subshark.py --json > results.json

# 5. Increase concurrency for larger inventories
cat subdomains.txt | python3 subshark.py \
  --concurrency 100 \
  --timeout 60
```

---

## Security & Ethical Use

SubShark is intended for **authorized security testing, vulnerability assessment, bug bounty programs, and defensive research**.

Only scan domains and systems that you own or have explicit permission to assess.

Unauthorized scanning may violate:

- laws and regulations,
- acceptable-use policies,
- bug bounty program rules,
- terms of service,
- organizational security policies.

The authors are not responsible for misuse of this software.

---

## Responsible Validation

A fingerprint match should be treated as a **candidate finding**, not an automatic proof of takeover.

Before reporting a potential subdomain takeover, validate at minimum:

1. The subdomain's DNS configuration.
2. The CNAME or relevant DNS target.
3. Whether the referenced third-party resource is actually unclaimed.
4. Whether the provider allows registration or claiming of the referenced resource.
5. Whether the HTTP response is a genuine provider-specific error page.
6. Whether the resource can actually be claimed or controlled.

Avoid making changes to third-party infrastructure unless explicitly authorized.

---

## Project Structure

A typical installation may look like:

```text
Subshark/
├── subshark.py
├── fingerprints.json
├── README.md
└── resume.cfg          # Created during an interrupted scan
```

The exact project structure may vary depending on your repository layout.

---

## Troubleshooting

### Fingerprints File Is Missing

Ensure the configured fingerprint download URL in `subshark.py` is valid and points to a raw JSON file.

You can also provide a local fingerprint database:

```bash
python3 subshark.py \
  --fingerprints /path/to/fingerprints.json
```

### Scans Are Too Slow

Increase concurrency:

```bash
python3 subshark.py --concurrency 100
```

You can also tune the timeout:

```bash
python3 subshark.py --timeout 15
```

Use reasonable values for your network and target environment.

### Resume Starts From an Unexpected Position

Resume state is stored in:

```text
resume.cfg
```

To deliberately start a new scan:

```bash
python3 subshark.py --no-resume
```

### Colored Output Causes Problems in Pipelines

Disable ANSI color output:

```bash
python3 subshark.py --nc
```

---

## Contributing

Contributions, bug reports, fingerprint additions, and improvements are welcome.

Before submitting a pull request:

1. Keep changes focused.
2. Test new fingerprints against representative responses.
3. Avoid introducing unnecessary dependencies.
4. Update documentation for new command-line options.
5. Include reproducible details for bug reports.

---

## Roadmap

Potential future improvements include:

- More comprehensive service fingerprints
- Improved HTTP response analysis
- DNS-based takeover detection
- Provider-specific validation
- Better structured logging
- Additional output formats
- Configurable retry behavior
- Improved scanning statistics
- Expanded test coverage

---

Example:

```text
MIT License
```

Replace the example above with the actual license used by the project.

---

## Credits

**SubShark** was developed by **D-XPL01T**.

Built with Python and the standard library.

---

## Disclaimer

SubShark is a security assessment tool for authorized use.

A detected fingerprint represents a **potential** subdomain takeover condition and may produce false positives. Always manually verify findings before taking action or reporting a vulnerability.

Use responsibly.
