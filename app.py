"""CyberRakshak - passive website security assessment platform (FastAPI + SQLite)."""
import os, re, ssl, socket, ipaddress, sqlite3, hashlib, secrets, time, html, logging
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
import requests, dns.resolver
from fastapi import FastAPI, Depends, Header, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

DB = os.getenv("DATABASE_PATH", "cyberrakshak.db"); RPT = os.getenv("REPORT_STORAGE_PATH", "reports")
RATE = int(os.getenv("RATE_LIMIT", "5")); MAXR = int(os.getenv("MAX_REDIRECTS", "5"))
TO = int(os.getenv("SCAN_TIMEOUT", "8")); MAXB = int(os.getenv("MAX_RESPONSE_SIZE", "262144"))
os.makedirs(RPT, exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cyberrakshak")
app = FastAPI(title="CyberRakshak API", description="Passive website security assessment API")

class E(Exception):
    def __init__(s, status, code, msg): s.status, s.code, s.msg = status, code, msg
@app.exception_handler(E)
async def eh(r, e): return JSONResponse({"success": False, "data": None, "error": {"code": e.code, "message": e.msg}}, e.status)
@app.exception_handler(Exception)
async def eh2(r, e):
    log.error("unhandled: %s", type(e).__name__)
    return JSONResponse({"success": False, "data": None, "error": {"code": "SERVER_ERROR", "message": "Something went wrong. Please try again."}}, 500)
def ok(d=None): return {"success": True, "data": d, "error": None}
now = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")

# ---------- database ----------
SCHEMA = """
create table if not exists users(id integer primary key, email text unique not null, password_hash text not null, full_name text, created_at text, updated_at text, last_login text, is_active integer default 1);
create table if not exists sessions(token text primary key, user_id integer references users(id) on delete cascade, expires real);
create table if not exists targets(id integer primary key, user_id integer references users(id) on delete cascade, domain text, created_at text, unique(user_id,domain));
create table if not exists scans(id integer primary key, target_id integer references targets(id) on delete cascade, user_id integer references users(id) on delete cascade, status text, progress integer default 0, current_check text, started_at text, completed_at text, authorization_confirmed integer, authorization_timestamp text, overall_score integer, risk_level text, total_checks integer, passed_checks integer, warning_checks integer, failed_checks integer, critical_count integer default 0, high_count integer default 0, error_message text, created_at text);
create table if not exists checks(id integer primary key, scan_id integer references scans(id) on delete cascade, category text, name text, status text, severity text, summary text, description text, evidence text, recommendation text, reference_url text, duration_ms integer);
create table if not exists reports(id integer primary key, scan_id integer references scans(id) on delete cascade, user_id integer, file_path text, generated_at text, report_type text);
create table if not exists audit_logs(id integer primary key, user_id integer, action text, ip_address text, user_agent text, created_at text);
"""
def db():
    c = sqlite3.connect(DB, timeout=15); c.row_factory = sqlite3.Row; c.execute("pragma foreign_keys=on"); return c
def q(sql, a=(), one=False):
    c = db()
    try:
        r = c.execute(sql, a); r = r.fetchone() if one else r.fetchall(); c.commit()
    finally: c.close()
    return (dict(r) if r else None) if one else [dict(x) for x in r]
def ex(sql, a=()):
    c = db()
    try: i = c.execute(sql, a).lastrowid; c.commit()
    finally: c.close()
    return i
c0 = db(); c0.executescript(SCHEMA); c0.close()
def audit(uid, action): ex("insert into audit_logs(user_id,action,created_at) values(?,?,?)", (uid, action, now()))

# ---------- auth ----------
def hp(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 240000).hex()
def vp(pw, h): return secrets.compare_digest(hp(pw, h.split("$")[0]), h)
def me(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "): raise E(401, "UNAUTHORIZED", "Please sign in to continue.")
    t = hashlib.sha256(authorization[7:].encode()).hexdigest()
    u = q("select u.* from sessions s join users u on u.id=s.user_id where s.token=? and s.expires>? and u.is_active=1", (t, time.time()), True)
    if not u: raise E(401, "UNAUTHORIZED", "Your session has expired. Please sign in again.")
    u["token"] = t; return u
pub = lambda u: {"id": u["id"], "email": u["email"], "full_name": u["full_name"], "created_at": u["created_at"], "last_login": u["last_login"]}
class Reg(BaseModel): email: str; password: str; full_name: str
class Log(BaseModel): email: str; password: str
tries = {}
@app.post("/api/auth/register")
def register(b: Reg):
    em = b.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", em): raise E(400, "INVALID_EMAIL", "Enter a valid email address.")
    if len(b.password) < 8: raise E(400, "WEAK_PASSWORD", "Password must be at least 8 characters.")
    if not b.full_name.strip(): raise E(400, "INVALID_NAME", "Enter your full name.")
    if q("select 1 from users where email=?", (em,), True): raise E(409, "EMAIL_EXISTS", "An account with this email already exists.")
    uid = ex("insert into users(email,password_hash,full_name,created_at,updated_at) values(?,?,?,?,?)", (em, hp(b.password), b.full_name.strip()[:80], now(), now()))
    audit(uid, "REGISTER"); return ok({"id": uid})
@app.post("/api/auth/login")
def login(b: Log):
    em = b.email.strip().lower(); t = [x for x in tries.get(em, []) if x > time.time() - 900]
    if len(t) >= 10: raise E(429, "TOO_MANY_ATTEMPTS", "Too many failed sign-ins. Try again in 15 minutes.")
    u = q("select * from users where email=? and is_active=1", (em,), True)
    if not u or not vp(b.password, u["password_hash"]):
        tries[em] = t + [time.time()]; raise E(401, "INVALID_CREDENTIALS", "Incorrect email or password.")
    tok = secrets.token_urlsafe(32)
    ex("insert into sessions values(?,?,?)", (hashlib.sha256(tok.encode()).hexdigest(), u["id"], time.time() + 43200))
    ex("update users set last_login=? where id=?", (now(), u["id"])); audit(u["id"], "LOGIN")
    return ok({"token": tok, "user": pub(u)})
@app.post("/api/auth/logout")
def logout(u=Depends(me)): ex("delete from sessions where token=?", (u["token"],)); audit(u["id"], "LOGOUT"); return ok()
@app.get("/api/me")
def profile(u=Depends(me)): return ok(pub(u))
class Name(BaseModel): full_name: str
@app.put("/api/me")
def upd(b: Name, u=Depends(me)):
    if not b.full_name.strip(): raise E(400, "INVALID_NAME", "Name cannot be empty.")
    ex("update users set full_name=?,updated_at=? where id=?", (b.full_name.strip()[:80], now(), u["id"])); return ok()
class Pw(BaseModel): current: str; new: str
@app.post("/api/me/password")
def chpw(b: Pw, u=Depends(me)):
    if not vp(b.current, u["password_hash"]): raise E(400, "INVALID_CREDENTIALS", "Current password is incorrect.")
    if len(b.new) < 8: raise E(400, "WEAK_PASSWORD", "New password must be at least 8 characters.")
    ex("update users set password_hash=? where id=?", (hp(b.new), u["id"])); return ok()

# ---------- target validation / SSRF protection ----------
def bad(): raise E(400, "INVALID_DOMAIN", "Enter a valid public domain such as example.com.")
def norm(raw):
    s = raw.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        if re.match(r"^(javascript|file|data):", s, re.I): bad()
        s = "http://" + s
    p = urlparse(s)
    if p.scheme not in ("http", "https") or not p.hostname: bad()
    h = p.hostname.lower().rstrip(".")
    try: h = h.encode("idna").decode()
    except Exception: bad()
    if h == "localhost" or re.fullmatch(r"[\d.]+|[0-9a-f:]+", h) or not re.fullmatch(r"([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}", h): bad()
    return h
def guard(h):
    """Resolve host server-side and reject any non-public address (loopback, private, link-local, metadata, ULA...)."""
    try: infos = socket.getaddrinfo(h, None)
    except socket.gaierror: raise E(400, "DNS_FAILURE", "CyberRakshak couldn't reach this domain. Please verify that the domain is publicly accessible.")
    for i in infos:
        if not ipaddress.ip_address(i[4][0].split("%")[0]).is_global:
            raise E(400, "BLOCKED_TARGET", "This address resolves to a private or internal network and cannot be assessed.")
    return sorted({i[4][0] for i in infos})

# ---------- scanner ----------
UA = {"User-Agent": "CyberRakshak/1.0 (authorized security assessment)"}
def fetch(url, method="GET"):
    chain = []
    for _ in range(MAXR + 1):
        guard(urlparse(url).hostname)
        r = requests.request(method, url, headers=UA, timeout=(5, TO), allow_redirects=False, stream=True)
        body = r.raw.read(MAXB, decode_content=True) if method == "GET" else b""
        r.close(); chain.append((url, r.status_code))
        if r.is_redirect and r.headers.get("Location"): url = urljoin(url, r.headers["Location"]); continue
        return r, chain, body
    raise RuntimeError("Too many redirects (limit %d)" % MAXR)
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP = "https://owasp.org/www-project-secure-headers/"
TS, HD, CK, DN, IN, WC, SH = "Transport Security", "HTTP Security Headers", "Cookies", "DNS & Domain", "Information Disclosure", "Web Configuration", "Security Hygiene"

def s_resolve(x, add):
    x["ips"] = guard(x["host"])
    add(DN, "Domain resolution", "PASS", "HIGH", f"Domain resolves to {len(x['ips'])} public address(es)", "The domain must resolve to a public IP for visitors to reach it.", ", ".join(x["ips"][:6]), ref="https://owasp.org/www-project-web-security-testing-guide/")
def s_https(x, add):
    h = x["host"]; x["https"] = False; x["ssl_err"] = None; chain_s = lambda c: " -> ".join(f"{u} [{s}]" for u, s in c)
    try:
        r, ch, b = fetch(f"https://{h}/"); x.update(https=True, resp=r, body=b, chain=ch)
    except requests.exceptions.SSLError as e: x["ssl_err"] = str(e)[:200]
    except requests.RequestException as e: x["https_err"] = type(e).__name__
    why = "HTTPS encrypts traffic between visitors and the website, protecting logins and personal data."
    if x["https"]:
        fin = urlparse(x["chain"][-1][0]).scheme
        add(TS, "HTTPS availability", "PASS" if fin == "https" else "FAIL", "HIGH", "HTTPS is enabled" if fin == "https" else "Final destination does not use HTTPS", why, chain_s(x["chain"]), "Serve all pages over HTTPS.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security")
    else:
        add(TS, "HTTPS availability", "FAIL", "CRITICAL", "HTTPS is not working", why, x["ssl_err"] or x.get("https_err", "Connection failed"), "Install a valid TLS certificate (e.g. free Let's Encrypt) and enable HTTPS on port 443.", "https://letsencrypt.org/getting-started/")
    try:
        r, ch, b = fetch(f"http://{h}/")
        if not x["https"]: x.update(resp=r, body=b, chain=ch)
        good = urlparse(ch[-1][0]).scheme == "https" and len(ch) > 1
        add(TS, "HTTP to HTTPS redirect", "PASS" if good else "FAIL", "HIGH", "HTTP redirects to HTTPS" if good else "The website is accessible over HTTP without enforcing HTTPS",
            "Visitors who type http:// should be sent to the secure version automatically.", chain_s(ch), "Add a permanent (301) redirect from HTTP to HTTPS on the web server.", MDN + "Strict-Transport-Security")
    except requests.RequestException:
        add(TS, "HTTP to HTTPS redirect", "PASS", "HIGH", "Plain HTTP is not served", "No insecure HTTP service was reachable.", "Connection on port 80 failed")
    if "resp" not in x: raise RuntimeError("The website could not be reached over HTTP or HTTPS.")
def s_tls(x, add):
    h = x["host"]
    if x.get("ssl_err"):
        add(TS, "Certificate validity", "FAIL", "CRITICAL", "TLS certificate failed validation", "Browsers warn visitors when a certificate is invalid, expired or mismatched.", x["ssl_err"], "Install a valid certificate issued by a trusted CA that matches the domain name.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"); return
    if not x["https"]: add(TS, "Certificate validity", "FAIL", "CRITICAL", "No TLS connection could be established", "Without TLS no certificate can be validated.", "Port 443 unreachable", "Enable HTTPS with a valid certificate."); return
    with socket.create_connection((h, 443), TO) as s, ssl.create_default_context().wrap_socket(s, server_hostname=h) as t:
        cert, ver = t.getpeercert(), t.version()
    iss = dict(i[0] for i in cert.get("issuer", ())).get("organizationName", "unknown")
    add(TS, "Certificate validity & hostname match", "PASS", "CRITICAL", "Certificate is trusted and matches the hostname", "A trusted, matching certificate proves the server's identity.", f"Issuer: {iss}; Subject: {dict(i[0] for i in cert.get('subject', ())).get('commonName', '')}")
    d = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400); x["days"] = d
    st, sev = ("FAIL", "CRITICAL") if d < 0 else ("FAIL", "HIGH") if d <= 7 else ("WARN", "MEDIUM") if d <= 30 else ("PASS", "MEDIUM")
    add(TS, "Certificate expiry", st, sev, f"Certificate expires in {d} days" if d >= 0 else "Certificate has expired", "Expired certificates cause browser warnings and outages.", f"notAfter: {cert['notAfter']} ({d} days remaining)", "Renew the certificate and automate renewal (e.g. certbot).", "https://letsencrypt.org/docs/faq/")
    add(TS, "TLS protocol version", "PASS" if ver in ("TLSv1.2", "TLSv1.3") else "FAIL", "HIGH", f"Negotiated {ver}", "Old TLS versions have known weaknesses.", ver, "Allow only TLS 1.2 and TLS 1.3.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security")
HDR = {
 "content-security-policy": ("Content-Security-Policy", "HIGH", "CSP protects against certain classes of XSS by controlling which resources a browser may load.", "Implement a restrictive CSP appropriate for the application and test it (Report-Only) before enforcing.", "Content-Security-Policy: default-src 'self'"),
 "strict-transport-security": ("Strict-Transport-Security", "HIGH", "HSTS tells browsers to use HTTPS for all future connections.", "Configure Strict-Transport-Security on the HTTPS response after verifying HTTPS works across the domain.", "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
 "x-content-type-options": ("X-Content-Type-Options", "MEDIUM", "Stops browsers from guessing (sniffing) content types, which can enable script injection.", "Send X-Content-Type-Options: nosniff.", "X-Content-Type-Options: nosniff"),
 "x-frame-options": ("X-Frame-Options / frame-ancestors", "MEDIUM", "Prevents other sites from embedding your pages in frames (clickjacking).", "Send X-Frame-Options: DENY or a CSP frame-ancestors directive.", "X-Frame-Options: DENY"),
 "referrer-policy": ("Referrer-Policy", "LOW", "Controls how much URL information is shared with other sites.", "Send Referrer-Policy: strict-origin-when-cross-origin.", "Referrer-Policy: strict-origin-when-cross-origin"),
 "permissions-policy": ("Permissions-Policy", "LOW", "Restricts powerful browser features (camera, microphone, geolocation).", "Send a Permissions-Policy limiting unused features.", "Permissions-Policy: camera=(), microphone=(), geolocation=()"),
 "cross-origin-opener-policy": ("Cross-Origin-Opener-Policy", "LOW", "Isolates your pages from other windows to reduce cross-origin attacks.", "Send Cross-Origin-Opener-Policy: same-origin where compatible.", "Cross-Origin-Opener-Policy: same-origin"),
 "cross-origin-resource-policy": ("Cross-Origin-Resource-Policy", "LOW", "Stops other origins from loading your resources.", "Send Cross-Origin-Resource-Policy: same-origin where compatible.", "Cross-Origin-Resource-Policy: same-origin")}
def s_headers(x, add):
    H = x["resp"].headers; csp = H.get("content-security-policy", "")
    for k, (nm, sev, why, rec, ex_) in HDR.items():
        v = H.get(k); ref = OWASP if k == "x-frame-options" else MDN + k; ev = f"{k}: {v}" if v else f"{nm} header was not observed."; st, sm = "PASS", f"{nm} is present"
        if k == "x-frame-options" and "frame-ancestors" in csp: v = csp; ev = "CSP frame-ancestors directive observed."
        if not v: st, sm = ("FAIL" if sev != "LOW" else "WARN"), f"Missing {nm}"
        elif k == "content-security-policy" and re.search(r"unsafe-(inline|eval)", v): st, sm = "WARN", "CSP allows unsafe-inline/unsafe-eval"
        elif k == "strict-transport-security":
            m = re.search(r"max-age=(\d+)", v)
            if not m or int(m.group(1)) < 15552000: st, sm = "WARN", "HSTS max-age is shorter than 180 days"
        elif k == "x-content-type-options" and v.lower().strip() != "nosniff": st, sm = "FAIL", "X-Content-Type-Options has an unexpected value"
        add(HD, nm, st, sev, sm, why, ev, f"{rec} Example: {ex_}" if st != "PASS" else "", ref)
def s_cookies(x, add):
    cs = x["resp"].raw.headers.getlist("Set-Cookie") if hasattr(x["resp"].raw.headers, "getlist") else []
    if not cs: add(CK, "Cookie security", "PASS", "MEDIUM", "No cookies were set on the initial response", "Cookie attributes can only be assessed when cookies are observable.", "No Set-Cookie header observed"); return
    for c in cs[:5]:
        nm = c.split("=")[0].strip(); low = c.lower(); miss = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in low]
        sens = bool(re.search(r"sess|sid|token|auth|jwt|login", nm, re.I))
        add(CK, f"Cookie '{nm}'", "PASS" if not miss else ("FAIL" if sens else "WARN"), "MEDIUM" if sens else "LOW", "Cookie has Secure, HttpOnly and SameSite" if not miss else f"Cookie is missing: {', '.join(miss)}",
            "Secure keeps cookies off plain HTTP, HttpOnly hides them from scripts, SameSite limits cross-site sending.", f"Cookie name: {nm}; attributes observed: {low.split(';',1)[1].strip() if ';' in low else 'none'}", "Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies." if miss else "", MDN + "Set-Cookie")
def s_server(x, add):
    H = x["resp"].headers; ex_ = {k: H[k] for k in ("server", "x-powered-by") if k in H}; ver = {k: v for k, v in ex_.items() if re.search(r"\d", v)}
    add(IN, "Server information disclosure", "WARN" if ver else "PASS", "LOW", "Server technology information is exposed" if ver else "No detailed server version information exposed",
        "Version details help attackers look for known flaws. Disclosure alone does not mean the site is vulnerable.", "; ".join(f"{k}: {v}" for k, v in ex_.items()) or "Server/X-Powered-By not detailed", "Hide version numbers (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx)." if ver else "", OWASP)
def look(name, t):
    try: return [r.to_text() for r in dns.resolver.Resolver().resolve(name, t, lifetime=5)]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN): return []
def s_dns(x, add):
    h = x["host"]; base = h if look(h, "TXT") else ".".join(h.split(".")[-2:]); ns, caa = look(base, "NS") or look(".".join(h.split(".")[-2:]), "NS"), look(base, "CAA") or look(".".join(h.split(".")[-2:]), "CAA"); txt = look(base, "TXT"); spf = [t for t in txt if "v=spf1" in t]; dm = [t for t in look("_dmarc." + base, "TXT") if "v=DMARC1" in t]
    add(DN, "DNS address records", "PASS", "LOW", "A/AAAA records found" + (" (IPv6 available)" if look(h, "AAAA") else ""), "Address records map the domain to servers.", ", ".join(x["ips"][:6]))
    add(DN, "Name servers", "PASS" if len(ns) >= 2 else "WARN", "LOW", f"{len(ns)} name server(s) found" if ns else "NS records not found at this name", "Two or more name servers keep the domain reachable if one fails.", ", ".join(ns[:4]) or "None observed", "Use at least two name servers." if len(ns) < 2 else "", "https://www.icann.org/resources/pages/dns-2017-06-02-en")
    add(DN, "SPF record", "PASS" if spf else "WARN", "MEDIUM", "SPF record detected" if spf else "SPF record was not detected", "SPF lists servers allowed to send email for the domain, reducing spoofing.", spf[0][:160] if spf else f"No v=spf1 TXT at {base}", "" if spf else "Publish an SPF TXT record, e.g. v=spf1 include:_spf.yourmailprovider.com -all", "https://www.rfc-editor.org/rfc/rfc7208")
    add(DN, "DMARC record", "PASS" if dm else "WARN", "MEDIUM", "DMARC record detected" if dm else "DMARC record was not detected", "DMARC tells receivers how to handle email that fails SPF/DKIM checks.", dm[0][:160] if dm else f"No DMARC TXT at _dmarc.{base}", "" if dm else "Publish a DMARC record, e.g. _dmarc TXT: v=DMARC1; p=quarantine; rua=mailto:you@yourdomain", "https://www.rfc-editor.org/rfc/rfc7489")
    add(DN, "CAA record", "PASS" if caa else "WARN", "LOW", "CAA record detected" if caa else "CAA record was not detected", "CAA limits which certificate authorities may issue certificates for the domain.", ", ".join(caa[:3]) or "None observed", "" if caa else "Add a CAA record naming your CA, e.g. 0 issue \"letsencrypt.org\"", "https://www.rfc-editor.org/rfc/rfc8659")
def s_config(x, add):
    r = x["resp"]; code = r.status_code
    add(WC, "HTTP response status", "PASS" if code < 400 else "WARN", "LOW", f"Final response status {code}", "A healthy site normally answers with 2xx/3xx.", f"Status {code}; redirect chain length {len(x['chain'])}")
    try:
        o, _, _ = fetch(x["chain"][-1][0], "OPTIONS"); al = o.headers.get("Allow", ""); risky = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT") if m in al.upper()]
        add(WC, "HTTP methods", "WARN" if risky else "PASS", "MEDIUM", f"Risky methods advertised: {', '.join(risky)}" if risky else "No risky HTTP methods advertised", "Unneeded methods increase the attack surface.", f"Allow: {al}" if al else "No Allow header returned (safe OPTIONS probe)", "Disable TRACE/PUT/DELETE unless required." if risky else "", MDN + "Allow")
    except requests.RequestException as e: add(WC, "HTTP methods", "ERROR", "INFO", "The check could not be completed.", evidence=type(e).__name__)
def s_files(x, add):
    base = x["chain"][-1][0]; base = f"{urlparse(base).scheme}://{x['host']}"
    for path, nm, absent_st, sev, why, rec, ref in (("/robots.txt", "robots.txt", "PASS", "INFO", "robots.txt guides crawlers but is NOT an access-control mechanism; never list secrets in it.", "", MDN.replace("/Headers/", "/") if False else "https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt"),
        ("/.well-known/security.txt", "security.txt", "WARN", "LOW", "security.txt is a standard way to publish vulnerability-reporting contact details.", "Publish /.well-known/security.txt with a Contact field.", "https://www.rfc-editor.org/rfc/rfc9116")):
        r, ch, b = fetch(base + path); found = r.status_code == 200 and not b.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))
        add(SH, nm, "PASS" if found else absent_st, sev, f"{nm} is present" if found else f"{nm} was not found", why, f"GET {path} -> {r.status_code}", "" if found else rec, ref)
def s_tech(x, add):
    H, b, t = x["resp"].headers, x["body"].decode("utf-8", "ignore"), set()
    for k in ("server", "x-powered-by", "x-generator"):
        if H.get(k): t.add(H[k].split()[0])
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', b, re.I)
    if m: t.add(m.group(1)[:40])
    if "cf-ray" in H: t.add("Cloudflare")
    if "/_next/" in b: t.add("Next.js (possible)")
    if "wp-content" in b: t.add("WordPress (possible)")
    add(IN, "Detected technology", "PASS", "INFO", ("Possible technology detected: " + ", ".join(sorted(t))) if t else "No technology clues observed", "Technology hints are passive guesses from headers and HTML and may be inaccurate.", ", ".join(sorted(t)) or "None", ref="https://owasp.org/www-project-web-security-testing-guide/")
STEPS = [("Resolving domain", DN, s_resolve), ("Checking HTTPS and redirects", TS, s_https), ("Checking TLS certificate", TS, s_tls), ("Analyzing security headers", HD, s_headers), ("Checking cookies", CK, s_cookies),
         ("Checking server information", IN, s_server), ("Checking DNS and email records", DN, s_dns), ("Checking web configuration", WC, s_config), ("Checking robots.txt and security.txt", SH, s_files), ("Detecting technology", IN, s_tech)]

# ---------- risk engine ----------
# Each applicable check has a weight by the severity it carries if it fails. FAIL costs the full weight, WARN half, PASS none.
# ERROR (check could not run) is excluded from both penalty and total. Score = 100 * (1 - penalty / total_possible).
W = {"INFO": 0, "LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 20}
TH = [(int(os.getenv("T_LOW", 85)), "LOW"), (int(os.getenv("T_MOD", 65)), "MODERATE"), (int(os.getenv("T_HIGH", 45)), "HIGH")]
def pct(cs):
    tot = sum(W[c["severity"]] for c in cs if c["status"] != "ERROR"); pen = sum(W[c["severity"]] * (1 if c["status"] == "FAIL" else .5 if c["status"] == "WARN" else 0) for c in cs)
    return 100 if tot == 0 else round(100 * (1 - pen / tot))
def label(s): return "Excellent" if s >= 90 else "Good" if s >= 75 else "Needs Attention" if s >= 60 else "Poor" if s >= 40 else "Critical"
def summ(cs):
    s = pct(cs); risk = next((r for t, r in TH if s >= t), "CRITICAL"); n = lambda st: sum(c["status"] == st for c in cs)
    return dict(overall_score=s, risk_level=risk, total_checks=len(cs), passed_checks=n("PASS"), warning_checks=n("WARN"), failed_checks=n("FAIL"),
                critical_count=sum(c["status"] == "FAIL" and c["severity"] == "CRITICAL" for c in cs), high_count=sum(c["status"] == "FAIL" and c["severity"] == "HIGH" for c in cs))
def cats(cs):
    o = {}
    for c in cs: o.setdefault(c["category"], []).append(c)
    return [dict(category=k, score=pct(v), passed=sum(c["status"] == "PASS" for c in v), warnings=sum(c["status"] == "WARN" for c in v), failed=sum(c["status"] == "FAIL" for c in v)) for k, v in o.items()]

def run_scan(sid, host):
    q("update scans set status='RUNNING',started_at=? where id=?", (now(), sid)); out = []; x = {"host": host}; cur = {"cat": "", "t": time.time()}
    def add(cat, name, st, sev, sm, why="", ev="", rec="", ref=""):
        out.append(dict(category=cat, name=name, status=st, severity=sev, summary=sm, description=why, evidence=ev, recommendation=rec, reference_url=ref, duration_ms=int((time.time() - cur["t"]) * 1000))); cur["t"] = time.time()
    try:
        for i, (lab, cat, fn) in enumerate(STEPS):
            q("update scans set current_check=?,progress=? where id=?", (lab, int(i / len(STEPS) * 100), sid)); cur["t"] = time.time()
            try: fn(x, add)
            except Exception as e:
                if i < 2 and "resp" not in x: raise
                add(cat, lab, "ERROR", "INFO", "The check could not be completed.", evidence=(e.msg if isinstance(e, E) else type(e).__name__ + ": " + str(e))[:200])
        c = db()
        try:
            for k in out: c.execute("insert into checks(scan_id,category,name,status,severity,summary,description,evidence,recommendation,reference_url,duration_ms) values(?,?,?,?,?,?,?,?,?,?,?)", (sid, *[k[f] for f in ("category", "name", "status", "severity", "summary", "description", "evidence", "recommendation", "reference_url", "duration_ms")]))
            s = summ(out); c.execute("update scans set status='COMPLETED',progress=100,current_check='Done',completed_at=?,overall_score=?,risk_level=?,total_checks=?,passed_checks=?,warning_checks=?,failed_checks=?,critical_count=?,high_count=? where id=?", (now(), *s.values(), sid)); c.commit()
        finally: c.close()
        uid = q("select user_id from scans where id=?", (sid,), True)["user_id"]; audit(uid, "SCAN_COMPLETED"); make_report(sid, uid); log.info("scan %s completed", sid)
    except Exception as e:
        msg = e.msg if isinstance(e, E) else "CyberRakshak couldn't reach this website. Please verify that the domain is publicly accessible."
        q("update scans set status='FAILED',error_message=?,completed_at=? where id=?", (msg, now(), sid)); log.warning("scan %s failed: %s", sid, type(e).__name__)

# ---------- scans API ----------
class ScanIn(BaseModel): domain: str; authorized: bool = False
def own(sid, u):
    s = q("select s.*,t.domain from scans s join targets t on t.id=s.target_id where s.id=? and s.user_id=?", (sid, u["id"]), True)
    if not s: raise E(404, "NOT_FOUND", "Assessment not found.")
    return s
@app.post("/api/scans")
def new_scan(b: ScanIn, bg: BackgroundTasks, u=Depends(me)):
    if not b.authorized: raise E(400, "AUTHORIZATION_REQUIRED", "Confirm that you own or are authorized to assess this domain.")
    host = norm(b.domain); guard(host)
    if q("select count(*) n from scans where user_id=? and created_at>?", (u["id"], datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat(timespec="seconds")), True)["n"] >= RATE:
        raise E(429, "RATE_LIMITED", f"Limit of {RATE} assessments per hour reached. Try again later.")
    t = q("select id from targets where user_id=? and domain=?", (u["id"], host), True); tid = t["id"] if t else ex("insert into targets(user_id,domain,created_at) values(?,?,?)", (u["id"], host, now()))
    sid = ex("insert into scans(target_id,user_id,status,authorization_confirmed,authorization_timestamp,created_at) values(?,?,'QUEUED',1,?,?)", (tid, u["id"], now(), now()))
    audit(u["id"], "SCAN_STARTED"); log.info("scan %s started", sid); bg.add_task(run_scan, sid, host); return ok({"id": sid})
@app.get("/api/scans")
def scans(domain: str = None, u=Depends(me)):
    return ok(q("select s.id,t.domain,s.status,s.overall_score,s.risk_level,s.created_at,s.completed_at from scans s join targets t on t.id=s.target_id where s.user_id=?" + (" and t.domain=?" if domain else "") + " order by s.id desc limit 200", (u["id"],) + ((domain,) if domain else ())))
@app.get("/api/scans/{sid}/status")
def sstatus(sid: int, u=Depends(me)): s = own(sid, u); return ok({k: s[k] for k in ("status", "progress", "current_check", "error_message")})
@app.get("/api/scans/{sid}")
def scan(sid: int, u=Depends(me)):
    s = own(sid, u); cs = q("select * from checks where scan_id=? order by id", (sid,)); prev = q("select overall_score from scans where target_id=? and status='COMPLETED' and id<? order by id desc limit 1", (s["target_id"], sid), True)
    s.update(checks=cs, categories=cats(cs), previous_score=prev["overall_score"] if prev else None, label=label(s["overall_score"]) if s["overall_score"] is not None else None); return ok(s)
@app.delete("/api/scans/{sid}")
def dscan(sid: int, u=Depends(me)):
    own(sid, u)
    for r in q("select file_path from reports where scan_id=?", (sid,)):
        try: os.remove(r["file_path"])
        except OSError: pass
    ex("delete from scans where id=?", (sid,)); return ok()
@app.get("/api/targets")
def targets(u=Depends(me)):
    return ok(q("select t.id,t.domain,t.created_at,(select max(created_at) from scans where target_id=t.id) last_scanned,(select overall_score from scans where target_id=t.id and status='COMPLETED' order by id desc limit 1) score,(select count(*) from scans where target_id=t.id) scan_count from targets t where t.user_id=? order by t.id desc", (u["id"],)))
@app.delete("/api/targets/{tid}")
def dtarget(tid: int, u=Depends(me)):
    if not q("select 1 from targets where id=? and user_id=?", (tid, u["id"]), True): raise E(404, "NOT_FOUND", "Target not found.")
    for r in q("select file_path from reports where scan_id in (select id from scans where target_id=?)", (tid,)):
        try: os.remove(r["file_path"])
        except OSError: pass
    ex("delete from targets where id=?", (tid,)); return ok()
@app.get("/api/dashboard")
def dash(u=Depends(me)):
    done = q("select s.id,t.domain,s.overall_score,s.risk_level,s.created_at,s.status,s.critical_count,s.high_count from scans s join targets t on t.id=s.target_id where s.user_id=? order by s.id desc", (u["id"],))
    comp = [d for d in done if d["status"] == "COMPLETED"]; last = comp[0] if comp else None
    cat = cats(q("select * from checks where scan_id=?", (last["id"],))) if last else []
    return ok({"total_scans": len(done), "latest": last, "previous_score": comp[1]["overall_score"] if len(comp) > 1 and comp[1]["domain"] == last["domain"] else None, "recent": done[:6], "trend": [{"date": d["created_at"], "score": d["overall_score"], "domain": d["domain"]} for d in reversed(comp[:20])], "categories": cat})

# ---------- PDF reports ----------
def make_report(sid, uid):
    from reportlab.lib.pagesizes import A4; from reportlab.lib import colors; from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    s = q("select s.*,t.domain from scans s join targets t on t.id=s.target_id where s.id=?", (sid,), True); cs = q("select * from checks where scan_id=? order by id", (sid,))
    rid = secrets.token_hex(8); path = os.path.join(RPT, f"{rid}.pdf"); ss = getSampleStyleSheet(); e = html.escape
    H1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#0b1b34")); B = ParagraphStyle("b", parent=ss["BodyText"], leading=14); SM = ParagraphStyle("sm", parent=B, fontSize=8.5, leading=11, textColor=colors.HexColor("#334155"))
    col = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#b45309", "LOW": "#1d4ed8", "INFO": "#475569"}; P = lambda t, st=B: Paragraph(t, st)
    f = [Spacer(1, 120), P("CYBERRAKSHAK", ParagraphStyle("c", parent=H1, fontSize=34)), P("Security Assessment Report", ss["Heading2"]), Spacer(1, 30),
         P(f"<b>Target:</b> {e(s['domain'])}"), P(f"<b>Assessment date:</b> {e(s['completed_at'][:10])}"), P(f"<b>Overall score:</b> {s['overall_score']}/100 ({label(s['overall_score'])})"), P(f"<b>Risk level:</b> {s['risk_level']}"), PageBreak()]
    bad_ = [c for c in cs if c["status"] in ("FAIL", "WARN")]
    f += [P("Executive Summary", H1), P(f"CyberRakshak assessed the public configuration of <b>{e(s['domain'])}</b> using {s['total_checks']} passive, non-intrusive checks. {s['passed_checks']} passed, {s['warning_checks']} produced warnings and {s['failed_checks']} failed. " + (f"{len(bad_)} area(s) need attention, led by: {e(', '.join(c['name'] for c in sorted(bad_, key=lambda c: -W[c['severity']])[:3]))}." if bad_ else "No critical issues were detected by the checks performed.")),
          Spacer(1, 8), P("Assessment Scope", H1), P(f"Target domain: {e(s['domain'])}<br/>Assessment type: Website Security Assessment (passive)<br/>Authorization confirmed: {'Yes' if s['authorization_confirmed'] else 'No'}<br/>Authorization timestamp: {e(s['authorization_timestamp'])}<br/>Scan started: {e(s['started_at'])}"),
          Spacer(1, 8), P("Score Summary", H1)]
    t = Table([["Overall score", "Risk", "Passed", "Warnings", "Failed"], [f"{s['overall_score']}/100", s["risk_level"], s["passed_checks"], s["warning_checks"], s["failed_checks"]]], hAlign="LEFT"); t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1b34")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .5, colors.grey), ("PADDING", (0, 0), (-1, -1), 6)])); f += [t, Spacer(1, 8), P("Category Summary", H1)]
    t = Table([["Category", "Score", "Passed", "Warnings", "Failed"]] + [[c["category"], f"{c['score']}%", c["passed"], c["warnings"], c["failed"]] for c in cats(cs)], hAlign="LEFT"); t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1b34")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .5, colors.grey), ("PADDING", (0, 0), (-1, -1), 5)])); f += [t, PageBreak(), P("Findings", H1)]
    for c in sorted(cs, key=lambda c: ({"FAIL": 0, "WARN": 1, "ERROR": 2, "PASS": 3}[c["status"]], -W[c["severity"]])):
        f += [P(f"<font color='{col[c['severity']]}'><b>[{c['status']} / {c['severity']}]</b></font> <b>{e(c['name'])}</b> - {e(c['summary'])}"), P(f"<b>Why it matters:</b> {e(c['description'] or '-')}<br/><b>Evidence:</b> {e(c['evidence'] or '-')}" + (f"<br/><b>Recommendation:</b> {e(c['recommendation'])}" if c["recommendation"] else "") + (f"<br/><b>Reference:</b> {e(c['reference_url'])}" if c["reference_url"] else ""), SM), Spacer(1, 7)]
    f += [P("Remediation Priority", H1)]
    for i, c in enumerate(sorted(bad_, key=lambda c: -W[c["severity"]])[:9], 1): f.append(P(f"Priority {1 if i <= 3 else 2 if i <= 6 else 3}: {e(c['name'])} ({c['severity']})"))
    if not bad_: f.append(P("No remediation required for the checks performed."))
    f += [PageBreak(), P("Technical Appendix", H1)] + [P(f"{e(c['category'])} / {e(c['name'])}: {c['status']} ({c['duration_ms']} ms)<br/>{e(c['evidence'] or '-')}", SM) for c in cs]
    f += [Spacer(1, 14), P("<b>Disclaimer:</b> This automated assessment evaluates only the checks performed by CyberRakshak during the stated assessment period. A clean result does not guarantee that the target is completely secure. Only authorized systems should be assessed.", SM)]
    def foot(cv, d): cv.setFont("Helvetica", 8); cv.drawString(40, 25, f"CyberRakshak - {s['domain']} - Page {d.page}")
    SimpleDocTemplate(path, pagesize=A4, leftMargin=40, rightMargin=40, topMargin=45, bottomMargin=45, title=f"CyberRakshak report {s['domain']}").build(f, onFirstPage=foot, onLaterPages=foot)
    for r in q("select file_path from reports where scan_id=?", (sid,)):
        try: os.remove(r["file_path"])
        except OSError: pass
    ex("delete from reports where scan_id=?", (sid,)); audit(uid, "REPORT_GENERATED")
    return ex("insert into reports(scan_id,user_id,file_path,generated_at,report_type) values(?,?,?,?,'PDF')", (sid, uid, path, now()))
@app.post("/api/scans/{sid}/report")
def regen(sid: int, u=Depends(me)):
    s = own(sid, u)
    if s["status"] != "COMPLETED": raise E(400, "NOT_READY", "The assessment has not completed yet.")
    return ok({"id": make_report(sid, u["id"])})
@app.get("/api/reports")
def reports(u=Depends(me)):
    return ok(q("select r.id,r.scan_id,r.generated_at,t.domain,s.overall_score,s.risk_level,s.status from reports r join scans s on s.id=r.scan_id join targets t on t.id=s.target_id where r.user_id=? order by r.id desc", (u["id"],)))
def myrep(rid, u):
    r = q("select r.*,t.domain,s.completed_at from reports r join scans s on s.id=r.scan_id join targets t on t.id=s.target_id where r.id=? and r.user_id=?", (rid, u["id"]), True)
    if not r: raise E(404, "NOT_FOUND", "Report not found.")
    return r
@app.get("/api/reports/{rid}")
def rep(rid: int, u=Depends(me)): r = myrep(rid, u); r.pop("file_path"); return ok(r)
@app.get("/api/reports/{rid}/download")
def dl(rid: int, u=Depends(me)):
    r = myrep(rid, u)
    if not os.path.exists(r["file_path"]): raise E(404, "FILE_MISSING", "The report file is missing. Use Generate Report on the assessment page.")
    audit(u["id"], "REPORT_DOWNLOADED"); return FileResponse(r["file_path"], media_type="application/pdf", filename=f"CyberRakshak-{r['domain'].replace('.', '-')}-{r['completed_at'][:10]}.pdf")
@app.delete("/api/reports/{rid}")
def drep(rid: int, u=Depends(me)):
    r = myrep(rid, u)
    try: os.remove(r["file_path"])
    except OSError: pass
    ex("delete from reports where id=?", (rid,)); return ok()

# ---------- demo mode (clearly labelled sample data, never stored) ----------
@app.get("/api/demo")
def demo():
    d = lambda c, n, st, sv, sm, why="", ev="", rec="": dict(category=c, name=n, status=st, severity=sv, summary=sm, description=why, evidence=ev, recommendation=rec, reference_url=OWASP, duration_ms=40)
    cs = [d(TS, "HTTPS availability", "PASS", "HIGH", "HTTPS is enabled", "HTTPS encrypts traffic.", "https://demo.example/ [200]"), d(TS, "Certificate expiry", "PASS", "MEDIUM", "Certificate expires in 61 days", "Expired certificates cause outages.", "notAfter: demo"),
          d(HD, "Content-Security-Policy", "FAIL", "HIGH", "Missing Content-Security-Policy", "CSP controls which resources a browser may load.", "Header was not observed.", "Implement a restrictive CSP and test before enforcing."),
          d(HD, "Strict-Transport-Security", "WARN", "HIGH", "HSTS max-age is shorter than 180 days", "HSTS tells browsers to use HTTPS.", "max-age=3600", "Increase max-age to 31536000."),
          d(HD, "X-Content-Type-Options", "PASS", "MEDIUM", "X-Content-Type-Options is present", "Stops MIME sniffing.", "nosniff"), d(CK, "Cookie 'session'", "FAIL", "MEDIUM", "Cookie is missing: HttpOnly", "HttpOnly hides cookies from scripts.", "session=...; Secure", "Add HttpOnly."),
          d(DN, "DMARC record", "WARN", "MEDIUM", "DMARC record was not detected", "DMARC protects against email spoofing.", "No DMARC TXT", "Publish a DMARC record."), d(DN, "Domain resolution", "PASS", "HIGH", "Domain resolves", "", "203.0.113.10"),
          d(IN, "Server information disclosure", "WARN", "LOW", "Server technology information is exposed", "Version details help attackers.", "Server: nginx/1.18.0", "Hide version numbers."), d(SH, "security.txt", "WARN", "LOW", "security.txt was not found", "", "GET /.well-known/security.txt -> 404", "Publish security.txt.")]
    s = summ(cs); s.update(id=0, demo=True, domain="demo.example (DEMO DATA)", status="COMPLETED", created_at=now(), completed_at=now(), checks=cs, categories=cats(cs), previous_score=None, label=label(s["overall_score"])); return ok(s)

@app.get("/")
def index(): return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))
