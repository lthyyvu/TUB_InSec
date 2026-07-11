#!/usr/bin/env python3
"""
T-Pot attacker-landscape report (last 24h) straight from Elasticsearch.

Pulls the same aggregations the T-Pot Kibana dashboard shows and writes them
as a Markdown report, so the T-Pot overview lives alongside the Cowrie report
instead of only inside Kibana.

Design goals:
  * stdlib only (urllib/json) - runs on the bare T-Pot host with no pip installs
  * auto-detects field names from the live mapping, so it works across T-Pot
    versions that differ on e.g. the ASN / CVE field names
  * no changes to the box - read-only _search queries

USAGE (simplest - run it ON the T-Pot host, where ES is on localhost):
    ssh -p 64295 <you>@<tpot_ip>
    python3 tpot_landscape.py                      # -> tpot-landscape-24h.md

USAGE (from your laptop over an SSH tunnel):
    ssh -p 64295 -L 64298:localhost:64298 <you>@<tpot_ip>   # in one terminal
    python3 tpot_landscape.py                                # in another

Config via env vars (all optional):
    ES_URL     default http://localhost:64298
    ES_INDEX   default logstash-*
    ES_WINDOW  default now-24h        (any ES date-math, e.g. now-7d)
    ES_TOP     default 10             (rows per table)
    ES_USER / ES_PASS   basic auth, only if you point ES_URL at the 64297 proxy
    OUT        default tpot-landscape-24h.md
"""

import os, sys, json, ssl, base64
import urllib.request, urllib.error

ES_URL   = os.environ.get("ES_URL", "http://localhost:64298").rstrip("/")
ES_INDEX = os.environ.get("ES_INDEX", "logstash-*")
WINDOW   = os.environ.get("ES_WINDOW", "now-24h")
TOP      = int(os.environ.get("ES_TOP", "10"))
OUT      = os.environ.get("OUT", "tpot-landscape-24h.md")
ES_USER  = os.environ.get("ES_USER")
ES_PASS  = os.environ.get("ES_PASS")

# well-known ports -> service, so the port table reads as an attack-surface view
PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 502: "Modbus",
    1433: "MSSQL", 1723: "PPTP", 1883: "MQTT", 2222: "SSH-alt", 3306: "MySQL",
    3389: "RDP", 5060: "SIP/VoIP", 5432: "PostgreSQL", 5555: "ADB/Android",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8728: "MikroTik API", 9200: "Elasticsearch", 27017: "MongoDB", 47808: "BACnet",
}

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE  # T-Pot's 64297 proxy uses a self-signed cert


def es(path, body=None):
    url = f"{ES_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="GET" if body is None else "POST")
    req.add_header("Content-Type", "application/json")
    if ES_USER and ES_PASS:
        tok = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
        req.add_header("Authorization", f"Basic {tok}")
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"ES HTTP {e.code} on {path}: {e.read().decode()[:300]}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach Elasticsearch at {ES_URL} ({e.reason}). "
                 f"Are you on the host / is the tunnel up?")


def flatten_mapping(props, prefix=""):
    """Return {dotted.field.path: es_type} incl. .keyword multifields."""
    out = {}
    for name, spec in (props or {}).items():
        path = prefix + name
        t = spec.get("type")
        if t:
            out[path] = t
            for sub, subspec in spec.get("fields", {}).items():
                out[f"{path}.{sub}"] = subspec.get("type")
        if "properties" in spec:
            out.update(flatten_mapping(spec["properties"], path + "."))
    return out


# types we can run a terms/cardinality agg on. Raw `text` is deliberately excluded:
# aggregating a text field errors with "fielddata is disabled" - we want its
# `.keyword` multifield instead.
AGGREGATABLE = {"keyword", "ip", "long", "integer", "short", "byte", "double",
                "float", "half_float", "scaled_float", "boolean", "date"}


def load_fields():
    m = es(f"/{ES_INDEX}/_mapping")
    fields = {}
    for idx in m.values():
        fields.update(flatten_mapping(idx.get("mappings", {}).get("properties", {})))
    # keep only aggregatable fields so pick() never returns a raw text field
    return {p: t for p, t in fields.items() if t in AGGREGATABLE}


def pick(fields, *cands):
    """First candidate field that actually exists in the mapping, else None."""
    for c in cands:
        if c in fields:
            return c
    return None


def main():
    fields = load_fields()

    # resolve the fields we want, tolerating version-to-version naming drift
    f_type = pick(fields, "type.keyword", "type")
    f_srcip = pick(fields, "src_ip.keyword", "src_ip")
    f_country = pick(fields, "geoip.country_name.keyword", "geoip.country_name",
                     "geoip_ext.country_name.keyword")
    f_asorg = pick(fields, "geoip.as_org.keyword", "geoip.as_org",
                   "as.organization.name.keyword", "geoip.organization.keyword",
                   "geoip_ext.as_org.keyword")
    f_port = pick(fields, "dest_port", "dst_port", "dest_port.keyword")
    f_user = pick(fields, "username.keyword", "username")
    f_pass = pick(fields, "password.keyword", "password")
    f_sig = pick(fields, "alert.signature.keyword", "alert.signature")
    f_cve = pick(fields, "alert.cve_id.keyword", "cve.keyword", "alert.cve.keyword",
                 "alert.metadata.cve.keyword", "cve_id.keyword")
    f_rep = pick(fields, "ip_rep.keyword", "ip_rep")

    aggs = {}
    if f_srcip:  aggs["unique_src"] = {"cardinality": {"field": f_srcip}}
    if f_rep:    aggs["reputation"] = {"terms": {"field": f_rep, "size": 20}}
    if f_type:   aggs["honeypots"] = {"terms": {"field": f_type, "size": 25}}
    if f_srcip:  aggs["top_src"] = {"terms": {"field": f_srcip, "size": TOP}}
    if f_asorg:  aggs["top_asn"] = {"terms": {"field": f_asorg, "size": TOP}}
    if f_country:aggs["top_country"] = {"terms": {"field": f_country, "size": TOP}}
    if f_port:   aggs["top_port"] = {"terms": {"field": f_port, "size": TOP}}
    if f_user:   aggs["top_user"] = {"terms": {"field": f_user, "size": TOP}}
    if f_pass:   aggs["top_pass"] = {"terms": {"field": f_pass, "size": TOP}}
    if f_sig:    aggs["top_sig"] = {"terms": {"field": f_sig, "size": TOP}}
    if f_cve:    aggs["top_cve"] = {"terms": {"field": f_cve, "size": TOP}}

    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"range": {"@timestamp": {"gte": WINDOW}}},
        "aggs": aggs,
    }
    res = es(f"/{ES_INDEX}/_search", body)
    a = res.get("aggregations", {})
    total = res.get("hits", {}).get("total", {}).get("value", 0)
    uniq = a.get("unique_src", {}).get("value")

    def buckets(name):
        return a.get(name, {}).get("buckets", [])

    L = []
    w = L.append
    w(f"# T-Pot attacker landscape — last 24h\n")
    w(f"*Window `{WINDOW}` · index `{ES_INDEX}` · generated from Elasticsearch "
      f"`{ES_URL}`*\n")
    w(f"**Total events:** {total:,}" + (f" · **Unique source IPs:** {uniq:,}" if uniq is not None else "") + "\n")

    def table(title, name, col, fmt=lambda k: str(k)):
        b = buckets(name)
        if not b:
            return
        w(f"## {title}\n")
        w(f"| {col} | Count |")
        w("|---|---:|")
        for x in b:
            w(f"| {fmt(x['key'])} | {x['doc_count']:,} |")
        w("")

    # reputation split first — the "who is this really" cut
    if buckets("reputation"):
        w("## Source reputation (known attacker vs mass scanner vs unknown)\n")
        w("| Reputation | Events |")
        w("|---|---:|")
        for x in buckets("reputation"):
            w(f"| {x['key']} | {x['doc_count']:,} |")
        w("")

    table("Attacks by honeypot", "honeypots", "Honeypot")
    table("Top source IPs", "top_src", "Source IP")
    table("Top attacker networks (ASN / org)", "top_asn", "ASN / Org")
    table("Top source countries", "top_country", "Country")
    table("Top targeted ports (services)", "top_port", "Port",
          fmt=lambda k: f"{k} ({PORTS.get(int(k), '?')})" if str(k).isdigit() else str(k))
    table("Top usernames tried", "top_user", "Username")
    table("Top passwords tried", "top_pass", "Password")
    table("Top Suricata alert signatures", "top_sig", "Signature")
    table("Top Suricata CVEs", "top_cve", "CVE")

    # surface any fields we could not resolve, so output gaps are explained
    missing = [n for n, f in [
        ("honeypot type", f_type), ("source ip", f_srcip), ("country", f_country),
        ("ASN/org", f_asorg), ("dest port", f_port), ("username", f_user),
        ("password", f_pass), ("suricata signature", f_sig), ("suricata CVE", f_cve),
        ("ip reputation", f_rep)] if not f]
    if missing:
        w("---\n")
        w("> **Note:** these fields were not found in the mapping and were skipped: "
          + ", ".join(missing) + ".")
        w("> Run `python3 tpot_landscape.py --fields` to list available fields and "
          "adjust the `pick(...)` candidates.\n")

    open(OUT, "w", encoding="utf-8").write("\n".join(L))
    print(f"Wrote {OUT}  ({total:,} events over {WINDOW})")


if __name__ == "__main__":
    if "--fields" in sys.argv:
        # debug helper: dump aggregatable fields so you can fix any naming drift
        for f in sorted(load_fields()):
            print(f)
    else:
        main()
