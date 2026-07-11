# Internal IP / DB-host disclosure in public DNS (`omanpostsql*.docswallet.com`)

**Program:** VFS Global (YesWeHack)
**Asset:** `omanpostsql.docswallet.com`, `omanpostsql-uat.docswallet.com` (in scope: `*.docswallet.com`)
**Class:** Sensitive information disclosure (CWE-200)
**Severity (proposed):** Informational / Low

> **Scope check first:** internal-IP disclosure is frequently *out of scope / auto-N/A* on bug
> bounty programs, and `*.vfsglobal.com` is a heavily-farmed scope with high duplicate probability.
> Confirm the VFS YWH policy treats this as in-scope before submitting; otherwise hold it.

---

## 1. Executive Summary

Two `docswallet.com` hostnames publish **direct `A` records to internal (RFC1918) database hosts**
in public DNS: `omanpostsql.docswallet.com → 10.165.170.70` and `omanpostsql-uat.docswallet.com →
10.165.170.102`. The naming advertises function and environment ("Oman Post SQL", prod + UAT). This
leaks the existence, naming, and internal addressing of database servers. The hosts are not
internet-reachable, so this is reconnaissance value only — Informational/Low.

## 2. Proof of Concept

```bash
$ dig +short CNAME omanpostsql.docswallet.com        # (none — direct A record, not a CDN/ELB alias)
$ dig +short A     omanpostsql.docswallet.com
10.165.170.70
$ dig +short A     omanpostsql-uat.docswallet.com
10.165.170.102
```

> **Attach to submission:** screenshot of the `dig` output for both hosts.

## 3. Honest Assessment / Root-Cause Note

This was originally drafted alongside the `bolt2-ffdc-*-prod.vfsglobal.com` hosts (which also surface
`172.22.5.x` addresses). **Those are excluded here, deliberately:** the `bolt2-ffdc-*` hosts are not
manual A records — they `CNAME` to **AWS internal-scheme Elastic Load Balancers**
(`internal-*-api-*.eu-central-1.elb.amazonaws.com`), and AWS *publishes the VPC-private IPs of
internal-scheme ELBs in public DNS by design*. There is nothing for VFS to "remove" there — the IPs
are inherited from the ELB alias — and the records reveal AWS `eu-central-1` (Frankfurt) plus a
handful of shared internal ALBs, not a private datacenter. Reporting that set would be a
false-positive on root cause.

The `omanpostsql*` records are different: they are **manually-created direct `A` records** to
internal DB hosts, which is a genuine (if low-impact) DNS-hygiene mistake. That distinction is the
whole point of this report.

What this is: disclosure of internal DB host naming + addressing.
What this is not: any demonstrated access to those hosts — `10.165.170.x` is not internet-routable.

## 4. Remediation

- Move `omanpostsql*.docswallet.com` to a **split-horizon / internal-only** DNS zone so the records
  resolve only on the internal resolver; remove them from the public zone.
- Audit `*.docswallet.com` for other internally-named direct A records (the `*sql*`, `*db*` naming
  pattern in particular).

## 5. Suggestions for Next Iteration

A zone-wide pattern sweep (`*sql*`, `*db*`, `*-internal*`, RFC1918 direct-A) across all program
domains would catch any siblings; the AWS-ELB-inherited IPs should be filtered out of that sweep to
avoid false positives.
