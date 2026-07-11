#!/usr/bin/env python3
import base64
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


DOMAINS = ["tweakblogs.net", "tweakers.net", "tweakimg.net"]
OUTDIR = Path("/tmp/tweakers-recon/external")
URL_RE = re.compile(
    r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*"
    r"(?:tweakblogs\.net|tweakers\.net|tweakimg\.net)"
    r"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*",
    re.I,
)


def request_json(url, headers=None, timeout=35):
    req = Request(url, headers=headers or {})
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, dict(resp.headers), json.loads(body.decode("utf-8", "replace"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"raw": body[:500]}
        return exc.code, dict(exc.headers), parsed
    except (URLError, TimeoutError) as exc:
        return 0, {}, {"error": str(exc)}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def add_host(hosts, value, domain=None):
    if not value:
        return
    value = value.strip().strip(".").lower()
    if domain and "." not in value:
        value = f"{value}.{domain}"
    if any(value == d or value.endswith(f".{d}") for d in DOMAINS):
        hosts.add(value)


def add_urls(urls, value):
    if not value:
        return
    for match in URL_RE.findall(value):
        urls.add(match.rstrip('"\').,;<>'))


def securitytrails(key, hosts, errors):
    if not key:
        return
    for domain in DOMAINS:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false"
        code, _, data = request_json(url, {"APIKEY": key})
        write_json(OUTDIR / "raw" / f"securitytrails-{domain}.json", {"status": code, "body": data})
        if code == 200:
            for item in data.get("subdomains", []):
                add_host(hosts, item, domain)
        else:
            errors.append({"source": "securitytrails", "domain": domain, "status": code, "body": data})
        time.sleep(1)


def chaos(key, hosts, errors):
    if not key:
        return
    for domain in DOMAINS:
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        code, _, data = request_json(url, {"Authorization": key})
        write_json(OUTDIR / "raw" / f"chaos-{domain}.json", {"status": code, "body": data})
        if code == 200:
            for item in data.get("subdomains", []):
                add_host(hosts, item, domain)
        else:
            errors.append({"source": "chaos", "domain": domain, "status": code, "body": data})
        time.sleep(1)


def binaryedge(key, hosts, errors):
    if not key:
        return
    for domain in DOMAINS:
        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        code, _, data = request_json(url, {"X-Key": key})
        write_json(OUTDIR / "raw" / f"binaryedge-{domain}.json", {"status": code, "body": data})
        if code == 200:
            events = data.get("events", [])
            for item in events:
                add_host(hosts, str(item), domain)
        else:
            errors.append({"source": "binaryedge", "domain": domain, "status": code, "body": data})
        time.sleep(1)


def certspotter(key, hosts, errors):
    if not key:
        return
    headers = {"Authorization": f"Bearer {key}"}
    for domain in DOMAINS:
        qs = urlencode({"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
        url = f"https://api.certspotter.com/v1/issuances?{qs}"
        code, _, data = request_json(url, headers)
        write_json(OUTDIR / "raw" / f"certspotter-{domain}.json", {"status": code, "body": data})
        if code == 200 and isinstance(data, list):
            for cert in data:
                for name in cert.get("dns_names", []):
                    add_host(hosts, name.lstrip("*."))
        else:
            errors.append({"source": "certspotter", "domain": domain, "status": code, "body": data})
        time.sleep(1)


def whoisxmlapi(key, hosts, errors):
    if not key:
        return
    for domain in DOMAINS:
        qs = urlencode({"apiKey": key, "domainName": domain})
        url = f"https://subdomains.whoisxmlapi.com/api/v1?{qs}"
        code, _, data = request_json(url)
        write_json(OUTDIR / "raw" / f"whoisxmlapi-{domain}.json", {"status": code, "body": data})
        if code == 200:
            records = data.get("result", {}).get("records", [])
            for rec in records:
                add_host(hosts, rec.get("domain") or rec.get("domainName"))
        else:
            errors.append({"source": "whoisxmlapi", "domain": domain, "status": code, "body": data})
        time.sleep(1)


def shodan(key, hosts, services, errors):
    if not key:
        return
    for domain in DOMAINS:
        url = f"https://api.shodan.io/dns/domain/{domain}?{urlencode({'key': key})}"
        code, _, data = request_json(url)
        write_json(OUTDIR / "raw" / f"shodan-dns-{domain}.json", {"status": code, "body": data})
        if code == 200:
            for item in data.get("subdomains", []):
                add_host(hosts, item, domain)
            for row in data.get("data", []):
                add_host(hosts, row.get("subdomain"), domain)
        else:
            errors.append({"source": "shodan-dns", "domain": domain, "status": code, "body": data})

        search = f"hostname:{domain}"
        s_url = f"https://api.shodan.io/shodan/host/search?{urlencode({'key': key, 'query': search})}"
        code, _, data = request_json(s_url)
        write_json(OUTDIR / "raw" / f"shodan-search-{domain}.json", {"status": code, "body": data})
        if code == 200:
            for item in data.get("matches", []):
                for hn in item.get("hostnames", []):
                    add_host(hosts, hn)
                services.append(
                    {
                        "source": "shodan",
                        "domain": domain,
                        "ip": item.get("ip_str"),
                        "port": item.get("port"),
                        "transport": item.get("transport"),
                        "hostnames": item.get("hostnames", []),
                        "org": item.get("org"),
                        "product": item.get("product"),
                        "timestamp": item.get("timestamp"),
                    }
                )
        else:
            errors.append({"source": "shodan-search", "domain": domain, "status": code, "body": data})
        time.sleep(2)


def google_cse(cx, key, urls, errors):
    if not cx or not key:
        return
    for domain in DOMAINS:
        for start in (1, 11, 21):
            qs = urlencode({"key": key, "cx": cx, "q": f"site:{domain}", "num": 10, "start": start})
            code, _, data = request_json(f"https://www.googleapis.com/customsearch/v1?{qs}")
            write_json(OUTDIR / "raw" / f"google-{domain}-{start}.json", {"status": code, "body": data})
            if code == 200:
                for item in data.get("items", []):
                    add_urls(urls, item.get("link", ""))
            else:
                errors.append({"source": "google", "domain": domain, "status": code, "body": data})
                break
            time.sleep(1)


def fofa(key, urls, services, errors):
    if not key:
        return
    for domain in DOMAINS:
        q = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        qs = urlencode({"key": key, "qbase64": q, "size": 100, "fields": "host,ip,port,protocol,title"})
        code, _, data = request_json(f"https://fofa.info/api/v1/search/all?{qs}")
        write_json(OUTDIR / "raw" / f"fofa-{domain}.json", {"status": code, "body": data})
        if code == 200 and not data.get("error"):
            for row in data.get("results", []):
                if row:
                    host = row[0]
                    proto = row[3] if len(row) > 3 else ""
                    if host.startswith("http"):
                        add_urls(urls, host)
                    elif proto in ("http", "https"):
                        add_urls(urls, f"{proto}://{host}")
                    services.append({"source": "fofa", "domain": domain, "row": row})
        else:
            errors.append({"source": "fofa", "domain": domain, "status": code, "body": data})
        time.sleep(2)


def github_code(token, urls, errors):
    if not token:
        return
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "passive-recon",
    }
    for domain in DOMAINS:
        qs = urlencode({"q": f'"{domain}"', "per_page": 30})
        code, _, data = request_json(f"https://api.github.com/search/code?{qs}", headers)
        write_json(OUTDIR / "raw" / f"github-code-{domain}.json", {"status": code, "body": data})
        if code == 200:
            for item in data.get("items", [])[:20]:
                file_url = item.get("url")
                if not file_url:
                    continue
                f_code, _, f_data = request_json(file_url, headers)
                if f_code != 200:
                    continue
                content = f_data.get("content", "")
                if f_data.get("encoding") == "base64" and content:
                    try:
                        decoded = base64.b64decode(content).decode("utf-8", "replace")
                    except Exception:
                        decoded = ""
                    add_urls(urls, decoded)
                time.sleep(0.5)
        else:
            errors.append({"source": "github-code", "domain": domain, "status": code, "body": data})
        time.sleep(2)


def main():
    if "--stdin-json" in sys.argv:
        secret_blob = sys.stdin.read()
        if secret_blob.strip():
            for key, value in json.loads(secret_blob).items():
                if value:
                    os.environ[key] = value

    OUTDIR.mkdir(parents=True, exist_ok=True)
    hosts = set()
    urls = set()
    services = []
    errors = []

    securitytrails(os.getenv("SECURITYTRAILS_KEY"), hosts, errors)
    chaos(os.getenv("CHAOS_KEY"), hosts, errors)
    binaryedge(os.getenv("BINARYEDGE_KEY"), hosts, errors)
    certspotter(os.getenv("CERTSPOTTER_KEY"), hosts, errors)
    whoisxmlapi(os.getenv("WHOISXMLAPI_KEY"), hosts, errors)
    shodan(os.getenv("SHODAN_KEY"), hosts, services, errors)
    google_cse(os.getenv("GOOGLE_CX"), os.getenv("GOOGLE_KEY"), urls, errors)
    fofa(os.getenv("FOFA_KEY"), urls, services, errors)
    github_code(os.getenv("GITHUB_TOKEN"), urls, errors)

    (OUTDIR / "external-subdomains.txt").write_text("\n".join(sorted(hosts)) + ("\n" if hosts else ""), encoding="utf-8")
    (OUTDIR / "external-urls.txt").write_text("\n".join(sorted(urls)) + ("\n" if urls else ""), encoding="utf-8")
    with (OUTDIR / "external-services.jsonl").open("w", encoding="utf-8") as handle:
        for item in services:
            handle.write(json.dumps(item, sort_keys=True) + "\n")
    with (OUTDIR / "errors.jsonl").open("w", encoding="utf-8") as handle:
        for item in errors:
            handle.write(json.dumps(item, sort_keys=True) + "\n")
    summary = {"subdomains": len(hosts), "urls": len(urls), "services": len(services), "errors": len(errors)}
    write_json(OUTDIR / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
