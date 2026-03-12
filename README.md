# KeyboardCrumbs MCP Server

Live threat intelligence tools for Claude Desktop. Free, no API key required.

## Tools

| Tool | Description |
|------|-------------|
| `check_ip` | Threat intel for any IP — risk score, geo, ASN, C2 associations, staging clusters |
| `check_cve` | CVE lookup — CVSS, EPSS, KEV status, exploit availability, patch urgency |
| `check_domain` | Domain intel — DNS records, WHOIS, malware associations, subdomains |
| `check_hash` | Malware hash lookup via VirusTotal (68+ engines) + CIRCL (6.3B files) |
| `active_threats` | Live snapshot — KEV count, active C2s, ransomware victims, data freshness |
| `predict_kev` | KEV Oracle — top CVEs predicted to be added to CISA KEV before it happens |
| `check_staging` | GhostWatch — detect pre-attack infrastructure staging for an IP or domain |
| `check_ransomware` | Ransomware group lookup and victim tracking |

## Install

### Option 1 — uvx (no install needed)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "keyboardcrumbs": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/keyboardcrumbs/mcp", "keyboardcrumbs-mcp"]
    }
  }
}
```

### Option 2 — Clone and run locally

```bash
git clone https://github.com/keyboardcrumbs/mcp
cd mcp
uv venv && source .venv/bin/activate
uv add "mcp[cli]" httpx
```

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "keyboardcrumbs": {
      "command": "uv",
      "args": ["--directory", "/path/to/mcp", "run", "server.py"]
    }
  }
}
```

Restart Claude Desktop.

## Example Usage

Once installed, just ask Claude:

- *"Is 45.141.26.73 malicious?"*
- *"Should I patch CVE-2024-3400 immediately?"*
- *"What CVEs are about to be added to CISA KEV?"*
- *"Is this domain staging for an attack?"*
- *"What's the current threat landscape?"*

Claude will call the live KeyboardCrumbs API and return real-time threat intelligence.

## Data Sources

URLhaus · Feodo Tracker · AlienVault OTX · CISA KEV · NVD · EPSS · ExploitDB ·
VirusTotal · CIRCL · SANS ISC DShield · Shodan · RIPE · crt.sh · Ransomware.live

Data updates every 15 minutes. No API key. No signup. No rate limits for normal use.

## Links

- Dashboard: https://threats.keyboardcrumbs.com
- GhostWatch: https://ghost.keyboardcrumbs.com
- KEV Oracle: https://oracle.keyboardcrumbs.com
- API docs: https://api.keyboardcrumbs.com
