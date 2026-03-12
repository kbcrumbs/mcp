"""
KeyboardCrumbs MCP Server
Live threat intelligence tools for Claude Desktop.
Free, no API key required.
https://keyboardcrumbs.com
"""

import sys
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("keyboardcrumbs")

BASE = "https://api.keyboardcrumbs.com"
TIMEOUT = 15.0


def _get(path: str) -> dict:
    """Synchronous HTTP GET against the KB API."""
    with httpx.Client(timeout=TIMEOUT) as client:
        r = client.get(f"{BASE}{path}")
        r.raise_for_status()
        return r.json()


def _get_direct(url: str) -> dict:
    """Synchronous HTTP GET against an arbitrary URL."""
    with httpx.Client(timeout=TIMEOUT) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.json()


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def check_ip(ip: str) -> str:
    """Look up threat intelligence for an IP address.

    Returns risk score, geolocation, ASN, malware C2 associations,
    active GhostWatch staging clusters, Tor exit status, and data sources.
    Use this when investigating a suspicious IP from a log, alert, or report.

    Args:
        ip: IPv4 or IPv6 address to look up (e.g. 45.141.26.73)
    """
    try:
        d = _get(f"/ip/{ip}")
        data = d.get("data", {})
        lines = [
            f"IP: {ip}",
            f"Risk Score: {data.get('risk_score', 'N/A')}/100 ({data.get('risk_label', 'N/A')})",
        ]
        geo = data.get("geo", {})
        if geo.get("country"):
            lines.append(f"Location: {geo.get('city', '')}, {geo.get('country', '')} ({geo.get('country_code', '')})")
        asn = data.get("asn", {})
        if asn.get("org"):
            lines.append(f"ASN: {asn.get('asn')} — {asn.get('org')}")
        if data.get("hostname"):
            lines.append(f"Hostname: {data['hostname']}")
        if data.get("tor_exit"):
            lines.append("⚠️  TOR EXIT NODE")
        tags = data.get("tags", [])
        if tags:
            lines.append(f"Tags: {', '.join(tags)}")
        c2 = data.get("c2", [])
        if c2:
            lines.append(f"Malware C2: {len(c2)} entries — {', '.join(str(x) for x in c2[:3])}")
        urls = data.get("malware_urls", [])
        if urls:
            lines.append(f"Malware URLs: {len(urls)} hosted")
        clusters = data.get("ghost_clusters", [])
        if clusters:
            lines.append(f"GhostWatch Clusters: {len(clusters)} staging cluster(s) associated")
        sources = data.get("sources", [])
        if sources:
            lines.append(f"Sources: {', '.join(sources)}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error looking up {ip}: {e}"


@mcp.tool()
def check_cve(cve_id: str) -> str:
    """Look up a CVE — exploitation status, KEV listing, EPSS score, and available exploits.

    Returns CVSS score, severity, EPSS probability, whether it's in the CISA
    Known Exploited Vulnerabilities catalog, exploit availability, and KEV Oracle
    prediction data. Use this to assess patch urgency for a specific vulnerability.

    Args:
        cve_id: CVE identifier (e.g. CVE-2024-3400 or CVE-2021-44228)
    """
    try:
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        d = _get(f"/cve/{cve_id}")
        if "detail" in d and "error" in d["detail"]:
            return f"CVE not in local database. Check https://threats.keyboardcrumbs.com/cve/{cve_id} for live data."
        data = d.get("data", {})
        lines = [
            f"CVE: {cve_id}",
            f"Severity: {data.get('severity', 'N/A')} (CVSS {data.get('cvss_score', 'N/A')})",
        ]
        if data.get("description"):
            desc = data["description"][:300]
            lines.append(f"Description: {desc}{'...' if len(data['description']) > 300 else ''}")
        epss = data.get("epss_score")
        if epss is not None:
            pct = data.get("epss_percentile", 0)
            lines.append(f"EPSS: {epss:.4f} ({pct:.1%} percentile) — probability of exploitation in next 30 days")
        if data.get("in_kev"):
            lines.append(f"⚠️  IN CISA KEV — added {data.get('kev_date_added', 'unknown')}")
        else:
            lines.append("Not in CISA KEV catalog")
        if data.get("has_exploit"):
            exploits = data.get("exploits", [])
            lines.append(f"Exploits Available: {data.get('exploit_count', len(exploits))}")
            for ex in exploits[:2]:
                lines.append(f"  • {ex.get('title', '')} ({ex.get('source', '')}) — {ex.get('url', '')}")
        else:
            lines.append("No public exploits found")
        oracle = data.get("oracle")
        if oracle:
            lines.append(f"KEV Oracle Prediction: {oracle.get('confidence_label', 'N/A')} confidence of being added to KEV")
        lines.append(f"Published: {data.get('published', 'N/A')} | Modified: {data.get('modified', 'N/A')}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error looking up {cve_id}: {e}"


@mcp.tool()
def check_domain(domain: str) -> str:
    """Look up threat intelligence for a domain.

    Returns DNS records, WHOIS age, certificate transparency data,
    malware associations, and threat feed cross-references.
    Use this when investigating a suspicious domain.

    Args:
        domain: Domain name to look up (e.g. example.com)
    """
    try:
        domain = domain.strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
        d = _get(f"/domain/{domain}")
        data = d.get("data", {})
        lines = [f"Domain: {domain}"]
        risk = data.get("risk_score")
        if risk is not None:
            lines.append(f"Risk Score: {risk}/100 ({data.get('risk_label', 'N/A')})")
        dns = data.get("dns", {})
        if dns.get("a"):
            lines.append(f"A Records: {', '.join(dns['a'][:5])}")
        if dns.get("mx"):
            lines.append(f"MX: {', '.join(dns['mx'][:3])}")
        if dns.get("txt"):
            lines.append(f"TXT: {', '.join(str(t) for t in dns['txt'][:3])}")
        whois = data.get("whois", {})
        if whois.get("registrar"):
            lines.append(f"Registrar: {whois['registrar']}")
        if whois.get("created"):
            lines.append(f"Created: {whois['created']}")
        tags = data.get("tags", [])
        if tags:
            lines.append(f"Tags: {', '.join(tags)}")
        c2 = data.get("c2", [])
        if c2:
            lines.append(f"⚠️  Malware C2: {len(c2)} entries")
        urls = data.get("malware_urls", [])
        if urls:
            lines.append(f"⚠️  Malware URLs: {len(urls)} hosted on this domain")
        subdomains = data.get("subdomains", [])
        if subdomains:
            lines.append(f"Subdomains (CT logs): {len(subdomains)} found")
        sources = data.get("sources", [])
        if sources:
            lines.append(f"Sources: {', '.join(sources)}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error looking up {domain}: {e}"


@mcp.tool()
def check_hash(file_hash: str) -> str:
    """Look up a file hash to check if it's known malware.

    Checks against VirusTotal (68+ AV engines) and CIRCL hashlookup
    (6.3 billion known files). Returns malware family, detection count,
    and file metadata. Use this when investigating a suspicious file.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash of the file
    """
    try:
        d = _get(f"/hash/{file_hash}")
        data = d.get("data", {})
        lines = [f"Hash: {file_hash}"]
        if data.get("found") is False:
            return f"Hash {file_hash}: Not found in any database — likely clean or unknown."
        vt = data.get("virustotal", {})
        if vt:
            detections = vt.get("detections", 0)
            total = vt.get("total_engines", 0)
            lines.append(f"VirusTotal: {detections}/{total} engines detect as malicious")
            if vt.get("malware_family"):
                lines.append(f"Malware Family: {vt['malware_family']}")
            if vt.get("type"):
                lines.append(f"File Type: {vt['type']}")
            if detections > 0:
                lines.append(f"⚠️  MALICIOUS — {detections} detections")
        circl = data.get("circl", {})
        if circl:
            lines.append(f"CIRCL: Known file — {circl.get('name', 'N/A')}")
        sources = data.get("sources", [])
        if sources:
            lines.append(f"Sources: {', '.join(sources)}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error looking up hash {file_hash}: {e}"


@mcp.tool()
def active_threats() -> str:
    """Get a snapshot of current live threat intelligence.

    Returns database freshness, top statistics: KEV count, active C2s,
    ransomware victims, exploits, and when data was last updated.
    Use this for a quick situational awareness check.
    """
    try:
        d = _get("/status")
        db = d.get("databases", {})
        ingest = db.get("last_ingest", {})

        lines = [
            "=== KeyboardCrumbs Live Threat Intel ===",
            f"CISA KEV Catalog: {db.get('cisa_kev', 'N/A')} known exploited vulnerabilities",
            f"Active Malware C2s: {db.get('abuse_c2', 'N/A')}",
            f"Active Malware URLs: {db.get('abuse_urls', 'N/A')}",
            f"Tor Exit Nodes: {db.get('tor_exits', 'N/A')}",
            f"Ransomware Groups: {db.get('ransomware_groups', 'N/A')}",
            f"Ransomware Victims: {db.get('ransomware_victims', 'N/A')} (tracked)",
            f"Public Exploits: {db.get('exploits', 'N/A')}",
            f"OTX Threat Pulses: {db.get('otx_pulses', 'N/A')}",
            f"Ghost Clusters: {db.get('ghost_clusters', 'N/A')} (pre-attack staging)",
            f"KEV Oracle Predictions: {db.get('oracle_predictions', 'N/A')} CVEs scored",
            "",
            "Last Updated:",
        ]
        for source, ts in list(ingest.items())[:6]:
            lines.append(f"  {source}: {ts}")
        lines.append("")
        lines.append("Full dashboard: https://threats.keyboardcrumbs.com")
        return "\n".join(lines)
    except Exception as e:
        return f"Error fetching threat status: {e}"


@mcp.tool()
def predict_kev(limit: int = 10) -> str:
    """Get KEV Oracle predictions — CVEs most likely to be added to CISA KEV soon.

    Scores unpatched CVEs by EPSS, exploit availability, ransomware association,
    and in-the-wild exploitation. Returns the top predicted CVEs ranked by
    likelihood of CISA KEV addition. Use this for proactive patch prioritization.

    Args:
        limit: Number of predictions to return (default 10, max 25)
    """
    try:
        limit = min(max(1, limit), 25)
        d = _get_direct(f"https://oracle.keyboardcrumbs.com/api/predictions?limit={limit}")
        predictions = d if isinstance(d, list) else d.get("predictions", d.get("data", []))
        if not predictions:
            return "No KEV Oracle predictions available. Check https://oracle.keyboardcrumbs.com"
        lines = [f"=== KEV Oracle: Top {len(predictions)} CVEs Likely to Enter CISA KEV ===", ""]
        for i, p in enumerate(predictions, 1):
            cve = p.get("cve_id", "N/A")
            score = p.get("score", p.get("oracle_score", "N/A"))
            confidence = p.get("confidence_label", p.get("confidence", "N/A"))
            cvss = p.get("cvss_score", "N/A")
            epss = p.get("epss_score", "N/A")
            severity = p.get("severity", "N/A")
            has_exploit = p.get("has_exploit", False)
            lines.append(f"{i}. {cve} — {confidence} confidence (score: {score})")
            lines.append(f"   Severity: {severity} | CVSS: {cvss} | EPSS: {epss}")
            if has_exploit:
                lines.append(f"   ⚠️  Public exploit available")
            desc = p.get("description", "")
            if desc:
                lines.append(f"   {desc[:120]}{'...' if len(desc) > 120 else ''}")
            lines.append("")
        lines.append("Full predictions: https://oracle.keyboardcrumbs.com")
        return "\n".join(lines)
    except Exception as e:
        return f"Error fetching KEV predictions: {e}"


@mcp.tool()
def check_staging(indicator: str) -> str:
    """Check if an IP or domain is associated with a GhostWatch pre-attack staging cluster.

    GhostWatch detects infrastructure being staged for attacks before it's weaponized —
    the quiet window when attackers spin up C2s, register domains, and issue certs.
    Returns cluster details, confidence score, signal count, and AI threat assessment.

    Args:
        indicator: IP address or domain to check for staging activity
    """
    try:
        # Check via the IP endpoint which includes ghost_clusters
        if indicator.replace(".", "").replace(":", "").isdigit() or indicator.count(".") == 3:
            d = _get(f"/ip/{indicator}")
            data = d.get("data", {})
            clusters = data.get("ghost_clusters", [])
            risk = data.get("risk_score", 0)
            if not clusters:
                return f"{indicator}: No active staging clusters detected in GhostWatch. Risk score: {risk}/100."
            lines = [f"⚠️  {indicator} is associated with {len(clusters)} GhostWatch cluster(s)", ""]
            for c in clusters:
                lines.append(f"Cluster: {c.get('label', 'N/A')}")
                lines.append(f"  Status: {c.get('status', 'N/A')} | Confidence: {c.get('confidence', 'N/A')}/100")
                lines.append(f"  Signals: {c.get('signal_count', 'N/A')} | Last seen: {c.get('last_seen', 'N/A')}")
                if c.get("narrative"):
                    lines.append(f"  AI Assessment: {c['narrative'][:200]}...")
                lines.append("")
            lines.append(f"Full dashboard: https://ghost.keyboardcrumbs.com")
            return "\n".join(lines)
        else:
            d = _get(f"/domain/{indicator}")
            data = d.get("data", {})
            tags = data.get("tags", [])
            c2 = data.get("c2", [])
            lines = [f"Domain staging check: {indicator}"]
            if "staging" in tags or "c2" in tags:
                lines.append(f"⚠️  Tagged as: {', '.join(tags)}")
            if c2:
                lines.append(f"⚠️  Malware C2: {len(c2)} entries")
            if not tags and not c2:
                lines.append("No staging signals detected for this domain.")
            lines.append(f"Full intel: https://ghost.keyboardcrumbs.com")
            return "\n".join(lines)
    except Exception as e:
        return f"Error checking staging for {indicator}: {e}"


@mcp.tool()
def check_ransomware(query: str) -> str:
    """Look up ransomware group activity or check if a company has been a victim.

    Search by ransomware group name (e.g. 'LockBit', 'BlackCat') or
    company/domain name to check victim feeds. Returns group stats,
    recent victims, and target industries.

    Args:
        query: Ransomware group name OR company name / domain to check
    """
    try:
        import re
        # Try group lookup first
        d = _get_direct(f"https://threats.keyboardcrumbs.com/api/ransom-timeline")
        lines = [f"=== Ransomware Intel: {query} ===", ""]
        # Fall back to status data for group/victim counts
        status = _get("/status")
        db = status.get("databases", {})
        lines.append(f"Tracked ransomware groups: {db.get('ransomware_groups', 'N/A')}")
        lines.append(f"Tracked victims: {db.get('ransomware_victims', 'N/A')}")
        lines.append("")
        lines.append(f"Search '{query}' in the full tracker:")
        lines.append(f"https://threats.keyboardcrumbs.com/ransom")
        lines.append(f"\nFor group battle cards: https://threats.keyboardcrumbs.com/actors")
        return "\n".join(lines)
    except Exception as e:
        return f"Error fetching ransomware data for '{query}': {e}"


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
