# Dangling CNAME → deleted Azure App Service on `insights.vfsglobal.com` / `insightsuat.vfsglobal.com`

**Program:** VFS Global (YesWeHack)
**Asset:** `insights.vfsglobal.com`, `insightsuat.vfsglobal.com` (in scope: `*.vfsglobal.com`)
**Class:** Dangling DNS record / potential subdomain takeover (CWE-16: Configuration)
**Severity (proposed):** Low — *dangling DNS record confirmed; full takeover NOT proven (see Honest Assessment)*

---

## 1. Executive Summary

Two in-scope hostnames, `insights.vfsglobal.com` and `insightsuat.vfsglobal.com`, contain
`CNAME` records pointing to Azure App Service instances that **no longer exist** — both backend
names return `NXDOMAIN`. This is a dangling DNS reference to a de-provisioned cloud resource. It is
reported as a DNS-hygiene / cloud-resource-management issue. A full subdomain takeover (serving
attacker content on a `vfsglobal.com` host) is **plausible but unconfirmed**, because Microsoft's
`asuid` domain-verification TXT records are still present and act as an anti-takeover control.

## 2. Key Findings

| Host | CNAME target | Backend status | `asuid` TXT present |
|------|--------------|----------------|---------------------|
| `insights.vfsglobal.com` | `insightshubprodwebapp1.azurewebsites.net` | **NXDOMAIN** | Yes |
| `insightsuat.vfsglobal.com` | `insightshubuatwebapp1.azurewebsites.net` | **NXDOMAIN** | Yes |

## 3. Proof of Concept

```bash
# in-scope host still points at the Azure App Service
$ dig +short CNAME insights.vfsglobal.com
insightshubprodwebapp1.azurewebsites.net.

# the App Service backend is gone (verified on two independent resolvers)
$ dig +short A insightshubprodwebapp1.azurewebsites.net @8.8.8.8     # -> (empty)
$ dig +noall +comments insightshubprodwebapp1.azurewebsites.net @8.8.8.8 | grep status
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: ...
$ dig +short A insightshubprodwebapp1.azurewebsites.net @1.1.1.1     # -> (empty), NXDOMAIN

# anti-takeover verification record still present (orphaned, points at the old subscription)
$ dig +short TXT asuid.insights.vfsglobal.com
"13409881BB6CB1123EFFF61FBD70E56C06FDC74ECEC6C63B4A3C113F9FC6A889"

# no live origin
$ curl -sk -m15 -o /dev/null -w "%{http_code}\n" https://insights.vfsglobal.com/
000

# Identical situation for the UAT host:
$ dig +short CNAME insightsuat.vfsglobal.com   # -> insightshubuatwebapp1.azurewebsites.net.
$ dig +short A insightshubuatwebapp1.azurewebsites.net @8.8.8.8   # -> NXDOMAIN
$ dig +short TXT asuid.insightsuat.vfsglobal.com
"C8681766506E26240AB07A45AC371860600411E0FAF2FAAB3B0059A2EF23286B"
```

> **Attach to submission:** terminal screenshot/recording of the `dig` commands above showing
> `NXDOMAIN` for both backends alongside the live `CNAME`. (Per submission policy, never text-only.)

## 4. Honest Assessment

This is **what it is:** a confirmed dangling CNAME to a deleted Azure App Service.

This is **what it is not (yet):** a confirmed subdomain takeover. Per Microsoft's documented App
Service custom-domain flow, adding a custom hostname requires the binding subscription to prove
ownership — either the CNAME points at the attacker's app *and* the domain's **Custom Domain
Verification ID** (`asuid.<host>` TXT) matches the attacker's subscription. The `asuid` value here
belongs to the *original* (now-deleted) subscription; an attacker's subscription has a different
verification ID and cannot write to `vfsglobal.com` DNS to change it, so the binding is expected to
fail while this TXT stands. To actually prove exploitability one would have to (a) register an App
Service named `insightshubprodwebapp1` in an attacker subscription and (b) attempt to bind
`insights.vfsglobal.com` — which was **not done** (no demonstrative claim performed). Until that PoC
exists, this is a dangling-record hygiene issue, not a working takeover.

**Expected triage outcome:** programs routinely close non-exploitable dangling records as
**Informational** with no bounty. This is submitted as hygiene/defense-in-depth, not as a paid
takeover — set expectations accordingly.

## 5. Impact & Risk

- **If the takeover proves viable:** an attacker serves arbitrary content on a trusted
  `*.vfsglobal.com` host — phishing of visa applicants, cookie/CSP scoping abuse (`Domain=.vfsglobal.com`
  cookies), OAuth/redirect allow-list abuse. That would be High.
- **As confirmed today:** internal/operational hygiene issue; reveals a decommissioned analytics
  ("insights hub") component. Low.

## 6. Remediation

> **Order matters — do NOT delete the `asuid` TXT first.** The `CNAME` is the hazard; the `asuid`
> TXT is currently the protection blocking takeover. Removing `asuid` while the `CNAME` still
> dangles would *open* the very takeover that is presently blocked.

- **Immediate:** delete the dangling **`CNAME`** records for `insights.vfsglobal.com` and
  `insightsuat.vfsglobal.com`. Removing the `CNAME` alone fully closes the issue (the host stops
  resolving to Azure). The `asuid.*` TXT records become harmless once the `CNAME` is gone and can be
  cleaned up afterward — but only *after*, never before.
- **Short-term:** if the analytics hub is still needed, re-provision the App Service under VFS's own
  subscription and re-point DNS, rather than leaving a stale `CNAME`.
- **Long-term:** add a DNS-hygiene CI check that flags any `*.vfsglobal.com` CNAME whose backend
  target no longer resolves to a live endpoint (covers CloudFront / App Service / Traffic Manager
  dangling classes).

## 7. Suggestions for Next Iteration

The full `*.vfsglobal.com` / `*.vfsevisa.com` CNAME set was subsequently swept — see the companion
report **`03_dangling_cloudfront.md`** (consolidated DNS-hygiene report). That sweep concluded the
CloudFront takeover angle is **dry**: 23 hosts dangle at dead distributions, and the live-edge hosts
are all **claimed** (no `Bad request.` CNAMEError anywhere), so there is no takeover candidate to
prove.

For this Azure pair specifically, **no claim-PoC is warranted.** The `asuid` Custom Domain
Verification ID still binds the original (deleted) subscription, so an attacker subscription's
binding is expected to **fail**; registering the App Service name `insightshubprodwebapp1` in an
attacker account is not authorized and would, at best, confirm a negative. Treat this as **hygiene
only — blocked by `asuid`** — and resolve it by removing the dangling `CNAME` (per §6), not by
attempting a takeover demonstration.
