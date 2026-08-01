import re
import os
import sys
import whois
from urllib.parse import urlparse
from datetime import datetime
import django

try:
    from pyzbar.pyzbar import decode
    PYZBAR_AVAILABLE = True
except Exception:
    decode = None
    PYZBAR_AVAILABLE = False

try:
    import cv2
    OPENCV_AVAILABLE = True
except Exception:
    cv2 = None
    OPENCV_AVAILABLE = False

from PIL import Image
import piexif

# ══════════════════════════════════════════════════════════════════
#  Constants for Social Media Scanner
# ══════════════════════════════════════════════════════════════════

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

ALWAYS_200  = {"Facebook", "LinkedIn"}
BLOCKS_BOTS = {"Instagram", "TikTok", "Twitter", "X", "Snapchat"}

SOCIAL_PLATFORMS = {
    "GitHub":    "https://github.com/{}",
    "Reddit":    "https://www.reddit.com/user/{}",
    "YouTube":   "https://www.youtube.com/@{}",
    "Telegram":  "https://t.me/{}",
    "Twitch":    "https://www.twitch.tv/{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Medium":    "https://medium.com/@{}",
    "Tumblr":    "https://{}.tumblr.com",
    "Patreon":   "https://www.patreon.com/{}",
    "Linktree":  "https://linktr.ee/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter":   "https://twitter.com/{}",
    "X":         "https://x.com/{}",
    "TikTok":    "https://www.tiktok.com/@{}",
    "Snapchat":  "https://www.snapchat.com/add/{}",
    "Facebook":  "https://www.facebook.com/{}",
    "LinkedIn":  "https://www.linkedin.com/in/{}",
}


# ══════════════════════════════════════════════════════════════════
#  Result builder  ─  carries structured sections for rich display
# ══════════════════════════════════════════════════════════════════

def _build_result(score, reasons, sections=None, metadata=None):
    """
    score    : int 0-100
    reasons  : flat list of strings (legacy / sub-scanner use)
    sections : list of {"title": str, "items": [str], "severity": str}
               severity ∈ "critical" | "warning" | "info" | "ok"
    metadata : dict of extra key-value info to show in the header block
    """
    score = min(score, 100)
    if score >= 70:
        risk = "HIGH"
    elif score >= 40:
        risk = "MEDIUM"
    elif score >= 15:
        risk = "LOW"
    else:
        risk = "SAFE"
    return {
        "risk":     risk,
        "score":    score,
        "reasons":  reasons,
        "sections": sections or [],
        "metadata": metadata or {},
    }


# ══════════════════════════════════════════════════════════════════
#  URL Scanner
# ══════════════════════════════════════════════════════════════════

def scan_url(url):
    score    = 0
    reasons  = []
    sections = []
    metadata = {}

    if not url:
        return _build_result(0, ["No URL provided"])

    # ── Section 1 : Protocol & structure ──────────────────────────
    proto_items = []
    if not url.startswith("https://"):
        score += 15
        proto_items.append("❌  No HTTPS — data transmitted over this link is NOT encrypted. "
                           "Any credentials or payment details you enter can be intercepted "
                           "by a third party (man-in-the-middle attack).")
    else:
        proto_items.append("✅  HTTPS present — connection is encrypted.")

    if len(url) > 75:
        score += 10
        proto_items.append(f"⚠️   Unusually long URL ({len(url)} characters). Fraudsters often "
                           "pad URLs to hide the real destination or obfuscate phishing domains.")

    ip_pattern = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
    if ip_pattern.match(url):
        score += 20
        proto_items.append("🚨  URL uses a raw IP address instead of a domain name. "
                           "Legitimate services almost never do this — it is a strong "
                           "indicator of a phishing or malware distribution site.")

    try:
        domain = urlparse(url).netloc
        parts  = domain.split(".")
        metadata["Domain"] = domain
        if len(parts) > 4:
            score += 10
            proto_items.append(f"⚠️   Excessive subdomain depth ({len(parts)} levels: {domain}). "
                               "Scammers add fake brand names as subdomains to trick users "
                               "(e.g. secure.paypal.login.evil.com).")
    except Exception:
        pass

    sections.append({"title": "Protocol & URL Structure", "items": proto_items, "severity": "info"})

    # ── Section 2 : Keyword analysis ──────────────────────────────
    suspicious_words = [
        "login", "verify", "bank", "wallet", "secure",
        "otp", "gift", "reward", "free", "lucky", "prize",
        "click", "confirm", "update", "account", "password"
    ]
    kw_hits = [w for w in suspicious_words if w in url.lower()]
    kw_items = []
    if kw_hits:
        for w in kw_hits:
            score += 5
        kw_items.append(f"⚠️   {len(kw_hits)} suspicious keyword(s) found in URL: "
                        f"{', '.join(repr(w) for w in kw_hits)}.")
        kw_items.append("     These words are commonly used in phishing URLs to create "
                        "urgency or mimic legitimate banking / e-commerce pages.")
    else:
        kw_items.append("✅  No suspicious keywords found in URL path.")
    sections.append({"title": "Keyword Analysis", "items": kw_items, "severity": "warning" if kw_hits else "ok"})

    # ── Section 3 : Domain age (WHOIS) ────────────────────────────
    whois_items = []
    try:
        domain = urlparse(url).netloc
        info   = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            age_str  = f"{age_days} days ({age_days // 30} months)"
            metadata["Domain Age"] = age_str
            metadata["Registered"] = str(creation)[:10]
            if info.registrar:
                metadata["Registrar"] = info.registrar
            if age_days < 30:
                score += 35
                whois_items.append(f"🚨  Domain registered only {age_days} day(s) ago. "
                                   "Scam domains are almost always brand-new. "
                                   "This is an extremely high-risk signal.")
            elif age_days < 180:
                score += 25
                whois_items.append(f"⚠️   Domain is only {age_str} old. "
                                   "Fraudulent sites are typically created days or weeks "
                                   "before a scam campaign. Treat with caution.")
            else:
                whois_items.append(f"✅  Domain age is {age_str} — established domain, lower risk.")
        else:
            whois_items.append("⚠️   WHOIS returned no creation date — domain age unverifiable.")
    except Exception:
        whois_items.append("ℹ️   Could not perform WHOIS lookup (network issue or private registration). "
                           "Domain age could not be verified.")
    sections.append({"title": "Domain Age & WHOIS", "items": whois_items, "severity": "info"})

    reasons = [item for s in sections for item in s["items"]]
    return _build_result(score, reasons, sections, metadata)


# ══════════════════════════════════════════════════════════════════
#  Phone Number Scanner
# ══════════════════════════════════════════════════════════════════

def scan_phone(number):
    score    = 0
    reasons  = []
    sections = []
    metadata = {}

    if not number:
        return _build_result(0, ["No phone number provided"])

    cleaned     = re.sub(r"[\s\-\.\(\)]", "", number)
    digits_only = cleaned.lstrip("+")
    metadata["Input"]          = number
    metadata["Cleaned"]        = cleaned
    metadata["Digit Count"]    = str(len(digits_only))

    # ── Section 1 : Format validation ─────────────────────────────
    fmt_items = []
    if not re.match(r"^\+?\d+$", cleaned):
        score += 30
        fmt_items.append("🚨  Number contains non-numeric characters after cleaning. "
                         "This may indicate spoofing, copy-paste errors, or a fabricated number.")
    else:
        fmt_items.append("✅  Number contains only valid numeric characters.")

    if not (7 <= len(digits_only) <= 15):
        score += 25
        fmt_items.append(f"🚨  Digit count ({len(digits_only)}) is outside the valid ITU-T E.164 "
                         f"range of 7–15 digits. Real phone numbers cannot have this length.")
    else:
        fmt_items.append(f"✅  Digit count ({len(digits_only)}) is within the valid E.164 range (7–15).")

    sections.append({"title": "Format Validation", "items": fmt_items, "severity": "info"})

    # ── Section 2 : Prefix / country code analysis ────────────────
    prefix_items = []
    scam_prefixes = {
        "+92":  "Pakistan — frequently used in impersonation and lottery scams",
        "+237": "Cameroon — associated with advance-fee fraud",
        "+234": "Nigeria — well-known origin of 419 advance-fee scams",
        "+216": "Tunisia — used in various phone fraud campaigns",
        "+256": "Uganda — linked to international phone scams",
        "140":  "Indian premium-rate or service number",
        "141":  "Indian caller-ID spoofing prefix",
        "160":  "Indian bulk-SMS gateway prefix",
    }
    hit_prefix = None
    for prefix, explanation in scam_prefixes.items():
        if cleaned.startswith(prefix):
            score += 30
            hit_prefix = prefix
            prefix_items.append(f"🚨  Number begins with '{prefix}' ({explanation}). "
                                 "While not conclusive, this prefix has a disproportionate "
                                 "association with scam calls in fraud databases.")
            break
    if not hit_prefix:
        prefix_items.append("✅  Number prefix does not match any known high-risk country code or service prefix.")

    sections.append({"title": "Prefix & Country Code", "items": prefix_items, "severity": "warning" if hit_prefix else "ok"})

    # ── Section 3 : Pattern analysis ──────────────────────────────
    pattern_items = []
    if re.match(r"^(\d)\1{6,}$", digits_only):
        score += 20
        pattern_items.append(f"🚨  Number is composed of a single repeated digit (e.g. 9999999999). "
                              "Real telephone numbers never look like this — almost certainly fake.")
    elif digits_only in "01234567890123456789" or digits_only in "98765432109876543210":
        score += 15
        pattern_items.append("⚠️   Number follows a sequential digit pattern (e.g. 1234567890). "
                              "This is a strong indicator of a placeholder or fabricated number.")
    else:
        pattern_items.append("✅  No suspicious repeating or sequential digit pattern detected.")

    sections.append({"title": "Pattern Analysis", "items": pattern_items, "severity": "info"})

    reasons = [item for s in sections for item in s["items"]]
    return _build_result(score, reasons, sections, metadata)


# ══════════════════════════════════════════════════════════════════
#  Email Scanner
# ══════════════════════════════════════════════════════════════════

def scan_email(email):
    score    = 0
    reasons  = []
    sections = []
    metadata = {}

    if not email:
        return _build_result(0, ["No email provided"])

    email = email.strip().lower()
    metadata["Input"] = email

    # ── Section 1 : Format validation ─────────────────────────────
    fmt_items = []
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        score += 40
        fmt_items.append("🚨  The string does not conform to a valid email format (local@domain.tld). "
                         "It cannot be a genuine email address.")
        sections.append({"title": "Format Validation", "items": fmt_items, "severity": "critical"})
        return _build_result(score, fmt_items, sections, metadata)

    local, domain = email.rsplit("@", 1)
    metadata["Local Part"] = local
    metadata["Domain"]     = domain
    fmt_items.append(f"✅  Valid email format detected — local part: '{local}', domain: '{domain}'.")
    sections.append({"title": "Format Validation", "items": fmt_items, "severity": "ok"})

    # ── Section 2 : Domain reputation ─────────────────────────────
    domain_items = []
    disposable_domains = [
        "mailinator.com", "guerrillamail.com", "tempmail.com",
        "throwaway.email", "yopmail.com", "sharklasers.com",
        "trashmail.com", "fakeinbox.com", "maildrop.cc",
        "dispostable.com", "getairmail.com", "spam4.me"
    ]
    if domain in disposable_domains:
        score += 40
        domain_items.append(f"🚨  '{domain}' is a known disposable / temporary email service. "
                            "These inboxes are created anonymously and deleted after use — "
                            "they are almost exclusively used to bypass verification systems "
                            "and avoid accountability in fraud.")
    else:
        domain_items.append(f"✅  '{domain}' is not on the known disposable-domain blacklist.")

    lookalike_pattern = re.compile(r"(g[o0]{2}gle|paypa[l1]|arnazon|micros[o0]ft|y[a@]hoo|app[l1]e)")
    if lookalike_pattern.search(domain):
        score += 35
        domain_items.append(f"🚨  Domain '{domain}' appears to impersonate a well-known brand using "
                            "lookalike characters (e.g. 'paypa1' instead of 'paypal'). "
                            "This is a textbook phishing technique.")
    sections.append({"title": "Domain Reputation", "items": domain_items,
                     "severity": "critical" if score >= 40 else "ok"})

    # ── Section 3 : Local-part analysis ───────────────────────────
    local_items = []
    suspicious_local = [
        "verify", "secure", "login", "bank", "otp", "reward",
        "prize", "winner", "free", "gift", "admin", "support",
        "noreply", "no-reply", "helpdesk", "service", "team"
    ]
    kw_hits = [w for w in suspicious_local if w in local]
    if kw_hits:
        for _ in kw_hits:
            score += 10
        local_items.append(f"⚠️   Suspicious keyword(s) in local part: {', '.join(repr(w) for w in kw_hits)}. "
                           "Scammers craft addresses like 'support@...' or 'verify@...' to appear "
                           "as official notifications from banks or services.")

    num_count = len(re.findall(r"\d", local))
    metadata["Digits in Local"] = str(num_count)
    if num_count >= 6:
        score += 10
        local_items.append(f"⚠️   Local part contains {num_count} digits. Auto-generated scam addresses "
                           "commonly contain long random digit strings (e.g. support48392017@...).")

    if len(local) <= 2:
        score += 10
        local_items.append(f"⚠️   Local part is very short ({len(local)} character(s)). "
                           "Extremely short local parts are unusual for legitimate accounts.")

    if not local_items:
        local_items.append("✅  No suspicious patterns detected in the local part of the address.")

    sections.append({"title": "Local-Part Analysis", "items": local_items, "severity": "warning" if kw_hits else "ok"})

    reasons = [item for s in sections for item in s["items"]]
    return _build_result(score, reasons, sections, metadata)


# ══════════════════════════════════════════════════════════════════
#  UPI ID Scanner
# ══════════════════════════════════════════════════════════════════

def scan_upi(upi_id):
    score    = 0
    reasons  = []
    sections = []
    metadata = {}

    if not upi_id:
        return _build_result(0, ["No UPI ID provided"])

    upi_id = upi_id.strip().lower()
    metadata["Input"] = upi_id

    # ── Section 1 : Format validation ─────────────────────────────
    fmt_items = []
    if not re.match(r"^[a-zA-Z0-9.\-_]+@[a-zA-Z0-9]+$", upi_id):
        score += 40
        fmt_items.append("🚨  Input does not match UPI ID format (localpart@handle). "
                         "A valid UPI ID looks like: name@okaxis or mobilenumber@ybl.")
        sections.append({"title": "Format Validation", "items": fmt_items, "severity": "critical"})
        return _build_result(score, fmt_items, sections, metadata)

    local, handle = upi_id.rsplit("@", 1)
    metadata["Local Part"] = local
    metadata["Handle"]     = f"@{handle}"
    fmt_items.append(f"✅  Valid UPI ID format — local: '{local}', handle: '@{handle}'.")
    sections.append({"title": "Format Validation", "items": fmt_items, "severity": "ok"})

    # ── Section 2 : Handle verification ───────────────────────────
    handle_items = []
    known_handles = {
        "okaxis", "okhdfcbank", "okicici", "oksbi",
        "ybl", "ibl", "axl", "upi", "paytm", "apl",
        "fbl", "ikwik", "rajgovhdfcbank", "barodampay",
        "cnrb", "kotak", "indus", "unionbank", "pnb",
        "mahb", "sib", "kvb", "dbs", "allbank", "andb", "aubank"
    }
    if handle not in known_handles:
        score += 20
        handle_items.append(f"⚠️   '@{handle}' is not in the list of NPCI-recognised UPI handles. "
                            "This does not mean it is fraudulent — banks sometimes use custom "
                            "handles — but you should verify it directly with your bank before "
                            "making any payment.")
    else:
        handle_items.append(f"✅  '@{handle}' is a recognised UPI banking handle.")
    sections.append({"title": "Handle Verification", "items": handle_items, "severity": "warning" if handle not in known_handles else "ok"})

    # ── Section 3 : Keyword analysis ──────────────────────────────
    kw_items = []
    suspicious_upi = [
        "free", "gift", "reward", "prize", "lucky", "win",
        "lottery", "refund", "cashback", "bonus", "offer",
        "tax", "income", "govt", "gov", "pm", "police",
        "cbi", "uidai", "paytm", "helpdesk", "support"
    ]
    kw_hits = [w for w in suspicious_upi if w in local]
    if kw_hits:
        for _ in kw_hits:
            score += 15
        kw_items.append(f"🚨  Suspicious keyword(s) in local part: {', '.join(repr(w) for w in kw_hits)}. "
                        "UPI IDs containing words like 'refund', 'govt', 'prize', or 'cbi' are "
                        "almost certainly fraudulent. Government agencies and banks do NOT collect "
                        "payments via UPI IDs with such names.")
    else:
        kw_items.append("✅  No suspicious keywords found in the UPI local part.")

    digit_count = len(re.findall(r"\d", local))
    if digit_count >= 8:
        score += 10
        kw_items.append(f"⚠️   Local part contains {digit_count} digits — unusual for a genuine UPI ID. "
                        "Fake IDs often use long random numbers to appear as mobile-linked accounts.")

    if len(local) <= 2:
        score += 15
        kw_items.append(f"⚠️   Local part is very short ({len(local)} character(s)). "
                        "Genuine UPI IDs typically have longer, meaningful local parts.")

    sections.append({"title": "Local-Part & Keyword Analysis", "items": kw_items, "severity": "critical" if kw_hits else "ok"})

    reasons = [item for s in sections for item in s["items"]]
    return _build_result(score, reasons, sections, metadata)


# ══════════════════════════════════════════════════════════════════
#  QR Code Scanner
# ══════════════════════════════════════════════════════════════════

def scan_qr(image_path):
    score    = 0
    reasons  = []
    sections = []
    metadata = {}

    if not image_path or not os.path.exists(image_path):
        return _build_result(0, ["Image file not found"])

    # ── Decode QR ─────────────────────────────────────────────────
    decoded_text = None
    decode_method = None

    try:
        if OPENCV_AVAILABLE:
            img = cv2.imread(image_path)
            if img is not None:
                detector = cv2.QRCodeDetector()
                data, points, _ = detector.detectAndDecode(img)
                if points is not None and data:
                    decoded_text  = data.strip()
                    decode_method = "OpenCV"
    except Exception:
        pass

    if not decoded_text:
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            img   = Image.open(image_path)
            codes = pyzbar_decode(img)
            if codes:
                decoded_text  = codes[0].data.decode("utf-8", errors="replace").strip()
                decode_method = "pyzbar"
        except Exception:
            pass

    if not decoded_text:
        return _build_result(0, ["No QR code could be detected in the provided image. "
                                  "Ensure the image is clear, well-lit, and contains a valid QR code."])

    metadata["Decoded Via"]    = decode_method or "Unknown"
    metadata["Content Length"] = f"{len(decoded_text)} characters"
    metadata["Content Preview"] = decoded_text[:100] + ("..." if len(decoded_text) > 100 else "")

    # ── Section 1 : Content identification ────────────────────────
    id_items = [f"✅  QR code successfully decoded using {decode_method}."]
    text_lower = decoded_text.lower()

    content_type = "plain text"
    sub_result   = None

    if decoded_text.startswith("http://") or decoded_text.startswith("https://") or decoded_text.startswith("www."):
        content_type = "URL"
        id_items.append(f"ℹ️   QR code encodes a URL: {decoded_text[:80]}{'...' if len(decoded_text)>80 else ''}")
        id_items.append("     A nested URL scan has been performed — see sections below.")
        sub_result = scan_url(decoded_text)

    elif decoded_text.startswith("upi://"):
        content_type = "UPI Payment Link"
        id_items.append("ℹ️   QR code encodes a UPI payment deep-link.")
        pa_match = re.search(r"pa=([^&]+)", decoded_text)
        if pa_match:
            upi_id = pa_match.group(1)
            metadata["UPI ID"] = upi_id
            id_items.append(f"     Payee UPI ID extracted: {upi_id}")
            sub_result = scan_upi(upi_id)
        am_match = re.search(r"am=([^&]+)", decoded_text)
        if am_match:
            try:
                amount = float(am_match.group(1))
                metadata["Pre-filled Amount"] = f"₹{amount:,.2f}"
                if amount > 50000:
                    score += 20
                    id_items.append(f"🚨  Pre-filled payment amount is ₹{amount:,.0f} — unusually large. "
                                    "Legitimate QR codes rarely pre-fill amounts above ₹50,000.")
                else:
                    id_items.append(f"ℹ️   Pre-filled amount: ₹{amount:,.2f}")
            except ValueError:
                pass
        pn_match = re.search(r"pn=([^&]+)", decoded_text)
        if pn_match:
            metadata["Payee Name"] = pn_match.group(1)

    elif re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", decoded_text):
        content_type = "Email Address"
        id_items.append(f"ℹ️   QR code encodes an email address: {decoded_text}")
        sub_result = scan_email(decoded_text)

    elif re.match(r"^\+?\d[\d\s\-]{5,}$", decoded_text):
        content_type = "Phone Number"
        id_items.append(f"ℹ️   QR code encodes a phone number: {decoded_text}")
        sub_result = scan_phone(decoded_text)

    else:
        id_items.append(f"ℹ️   QR code contains plain text: {decoded_text[:80]}{'...' if len(decoded_text)>80 else ''}")

    metadata["Content Type"] = content_type
    sections.append({"title": "QR Code Content Identification", "items": id_items, "severity": "info"})

    # ── Merge sub-scanner result ───────────────────────────────────
    if sub_result:
        score += sub_result["score"]
        for sub_sec in sub_result.get("sections", []):
            sub_sec["title"] = f"[{content_type} Check] {sub_sec['title']}"
            sections.append(sub_sec)
        metadata.update({f"  {k}": v for k, v in sub_result.get("metadata", {}).items()})

    # ── Section 2 : Content red flags ─────────────────────────────
    flag_items = []
    qr_red_flags = [
        "free", "prize", "winner", "reward", "lottery",
        "click here", "limited time", "act now",
        "verify", "otp", "password", "bank", "login", "confirm"
    ]
    hits = [f for f in qr_red_flags if f in text_lower]
    if hits:
        for _ in hits:
            score += 10
        flag_items.append(f"⚠️   {len(hits)} high-risk phrase(s) found in QR content: "
                          f"{', '.join(repr(h) for h in hits)}.")
        flag_items.append("     Phrases like 'free', 'prize', 'verify', 'otp', or 'bank' in a QR "
                          "code strongly suggest a phishing or scam payload.")
    else:
        flag_items.append("✅  No high-risk phrases detected in the QR content.")

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "shorturl.at"]
    for s in shorteners:
        if s in text_lower:
            score += 15
            flag_items.append(f"⚠️   URL shortener detected: '{s}'. Shorteners hide the true destination "
                               "of a link, making it impossible to verify safety before visiting. "
                               "This is a common tactic in QR-phishing ('quishing') attacks.")
            break

    sections.append({"title": "Content Red-Flag Analysis", "items": flag_items, "severity": "warning" if hits else "ok"})

    reasons = [item for s in sections for item in s["items"]]
    return _build_result(score, reasons, sections, metadata)


# ══════════════════════════════════════════════════════════════════
#  Social Media Scanner
# ══════════════════════════════════════════════════════════════════

def _check_platform(platform, url_template, username):
    import requests
    url = url_template.format(username)
    if platform in ALWAYS_200:
        return None, url, "login-wall"
    if platform in BLOCKS_BOTS:
        return None, url, "bot-protected"
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        if r.status_code == 200:
            final = r.url.rstrip("/").lower()
            home_urls = ["tiktok.com/foryou", "reddit.com/?", "pinterest.com/login"]
            if any(h in final for h in home_urls):
                return False, url, "redirected to homepage"
            return True, url, ""
        elif r.status_code == 404:
            return False, url, "not found"
        elif r.status_code == 403:
            return None, url, "bot-protected"
        else:
            return None, url, f"HTTP {r.status_code}"
    except Exception as e:
        return None, url, f"error: {e}"


def scan_social(handle_or_url):
    score    = 0
    reasons  = []
    sections = []
    metadata = {}

    if not handle_or_url:
        return _build_result(0, ["No profile provided"])

    original = handle_or_url.strip()
    lower    = original.lower()

    # ── Extract username ───────────────────────────────────────────
    username = original
    url_path_match = re.search(
        r"(?:instagram|twitter|x|facebook|fb|youtube|tiktok|"
        r"github|reddit|telegram|t|linkedin|twitch|pinterest|"
        r"snapchat|medium|tumblr|patreon|linktree|replit|devto|hashnode)"
        r"\.(?:com|me|tv|to)/(?:@|user/|c/|in/)?([A-Za-z0-9_.'\-]+)",
        lower
    )
    if url_path_match:
        username = url_path_match.group(1).strip("@").strip(".")
    elif original.startswith("@"):
        username = original.lstrip("@")
    elif not re.search(r"[\s/\\]", original):
        username = original
    username = username.split("?")[0].split("#")[0]

    metadata["Username"]      = f"@{username}"
    metadata["Username Length"] = str(len(username))

    print(f"\n  🔍 Scanning username: @{username}")
    print(f"  Checking {len(SOCIAL_PLATFORMS)} platforms — please wait...\n")

    # ── Section 1 : Platform existence ────────────────────────────
    found_on  = []
    not_found = []
    skipped   = []

    for platform, url_tpl in SOCIAL_PLATFORMS.items():
        found, url, note = _check_platform(platform, url_tpl, username)
        if found is True:
            found_on.append((platform, url))
        elif found is False:
            not_found.append(platform)
        else:
            skipped.append((platform, url_tpl.format(username), note))

    exist_items = []
    if found_on:
        exist_items.append(f"✅  '@{username}' was CONFIRMED active on {len(found_on)} platform(s):")
        for plat, url in found_on:
            exist_items.append(f"     [{plat:12s}]  {url}")
    else:
        exist_items.append(f"❌  '@{username}' was not confirmed on any automatically-checkable platform.")

    if not_found:
        exist_items.append(f"\n  ✗  Account NOT found on: {', '.join(not_found)}.")

    if skipped:
        exist_items.append(f"\n  🔗  {len(skipped)} platform(s) could not be checked automatically "
                           "(bot-protected or login-wall). Verify manually by clicking the links:")
        for plat_name, url, note in skipped:
            exist_items.append(f"     [{plat_name:12s}]  {url}  ← {note}")

    metadata["Confirmed On"]  = str(len(found_on)) + " platform(s)"
    metadata["Not Found On"]  = str(len(not_found)) + " platform(s)"
    metadata["Manual Check"]  = str(len(skipped)) + " platform(s)"
    sections.append({"title": "Platform Existence Check", "items": exist_items, "severity": "info"})

    # ── Section 2 : Username pattern analysis ─────────────────────
    pattern_items = []

    if len(username) <= 3:
        score += 10
        pattern_items.append(f"⚠️   Very short username ({len(username)} chars). Genuine personal or brand "
                             "accounts rarely use names shorter than 4 characters.")
    elif len(username) > 25:
        score += 10
        pattern_items.append(f"⚠️   Very long username ({len(username)} chars). Auto-generated bot accounts "
                             "often have long, random-looking usernames.")
    else:
        pattern_items.append(f"✅  Username length ({len(username)} chars) is within a normal range.")

    digit_count = len(re.findall(r"\d", username))
    metadata["Digits in Username"] = str(digit_count)
    if digit_count >= 6:
        score += 15
        pattern_items.append(f"⚠️   Username contains {digit_count} digits. Accounts with 6+ digit characters "
                             "are statistically far more likely to be bots or auto-registered fake accounts.")
    elif digit_count >= 4:
        score += 5
        pattern_items.append(f"ℹ️   Username contains {digit_count} digits — slightly above average, "
                             "worth noting but not conclusive.")
    else:
        pattern_items.append(f"✅  Low digit count ({digit_count}) — consistent with a human-chosen username.")

    if re.search(r"[a-zA-Z]{3,}\d{4,}$", username):
        score += 10
        pattern_items.append("⚠️   Username ends with a long trailing digit sequence (e.g. 'john48291'). "
                             "This pattern is common in bulk-registered fake accounts where a real name "
                             "is appended with a random number to create a unique handle.")

    letters = re.sub(r"[^a-zA-Z]", "", username)
    if len(letters) >= 6:
        vowels = len(re.findall(r"[aeiouAEIOU]", letters))
        ratio  = round(vowels / len(letters), 2)
        metadata["Vowel Ratio"] = f"{vowels}/{len(letters)} = {ratio}"
        if ratio < 0.15:
            score += 20
            pattern_items.append(f"🚨  Very low vowel ratio ({vowels} vowels in {len(letters)} letters = {ratio:.0%}). "
                                 "Human-chosen usernames almost always have a natural vowel distribution. "
                                 "A near-zero ratio strongly suggests a randomly generated string.")
        elif ratio < 0.25:
            score += 8
            pattern_items.append(f"⚠️   Below-average vowel ratio ({ratio:.0%}) — username may be auto-generated.")
        else:
            pattern_items.append(f"✅  Vowel ratio ({ratio:.0%}) looks natural.")

    sep_count = username.count("_") + username.count(".")
    if sep_count >= 4:
        score += 10
        pattern_items.append(f"⚠️   Username contains {sep_count} separator characters (underscores/dots). "
                             "Excessive separators are unusual and sometimes used to create variations "
                             "of a name that mimics another account.")

    sections.append({"title": "Username Pattern Analysis", "items": pattern_items, "severity": "info"})

    # ── Section 3 : Impersonation detection ───────────────────────
    imp_items = []
    impersonation_keywords = [
        "official", "real", "verified", "original", "genuine",
        "support", "help", "helpdesk", "service", "care",
        "admin", "staff", "team", "mod", "moderator",
        "india", "gov", "govt", "government", "pm", "modi",
        "rbi", "sebi", "irdai", "uidai", "npci", "cbi", "cid",
        "police", "cyber", "income", "tax", "gst",
        "paytm", "phonepe", "googlepay", "gpay", "bhim",
        "google", "amazon", "microsoft", "apple", "meta",
        "flipkart", "meesho", "snapdeal", "myntra",
        "jio", "airtel", "vodafone", "bsnl",
        "hdfc", "sbi", "icici", "axis", "kotak", "pnb",
    ]
    flagged_kw = [kw for kw in impersonation_keywords if kw in username.lower()]
    for _ in flagged_kw:
        score += 20

    if flagged_kw:
        imp_items.append(f"🚨  Impersonation keyword(s) detected in username: {', '.join(flagged_kw)}.")
        imp_items.append("     Authentic brand, bank, and government accounts NEVER embed their name "
                        "in a username like this — their handles are verified by the platform and do "
                        "not need to self-identify. Accounts that do are almost always scammers.")
    else:
        imp_items.append("✅  No brand, government, or authority impersonation keywords found in username.")

    # Homoglyph / lookalike check
    lookalike_map = {
        "0": "o", "1": "l", "3": "e", "4": "a",
        "5": "s", "6": "g", "8": "b",
        "rn": "m", "vv": "w", "cl": "d",
    }
    found_lookalikes = []
    for fake, real_char in lookalike_map.items():
        if fake in username.lower():
            found_lookalikes.append(f"'{fake}' → '{real_char}'")
            score += 12

    if found_lookalikes:
        imp_items.append(f"⚠️   Lookalike / homoglyph character substitution(s) detected: "
                        f"{', '.join(found_lookalikes)}. "
                        "Replacing letters with visually similar numbers (e.g. 'l' → '1', "
                        "'o' → '0') is a classic brand-impersonation technique.")
    else:
        imp_items.append("✅  No homoglyph or lookalike character substitutions detected.")

    sections.append({"title": "Impersonation & Homoglyph Detection",
                     "items": imp_items,
                     "severity": "critical" if flagged_kw else ("warning" if found_lookalikes else "ok")})

    reasons = [item for s in sections for item in s["items"]]
    return _build_result(score, reasons, sections, metadata)


# ══════════════════════════════════════════════════════════════════
#  Photo / Image Scanner
# ══════════════════════════════════════════════════════════════════

def scan_photo(image_path):
    score    = 0
    reasons  = []
    sections = []
    metadata = {}

    if not image_path or not os.path.exists(image_path):
        return _build_result(0, ["Image file not found"])

    try:
        img          = Image.open(image_path)
        fmt          = img.format
        width, height = img.size
        file_size_kb  = os.path.getsize(image_path) // 1024

        metadata["File"]       = os.path.basename(image_path)
        metadata["Format"]     = fmt or "Unknown"
        metadata["Dimensions"] = f"{width} × {height} px"
        metadata["File Size"]  = f"{file_size_kb} KB"

        # ── Section 1 : EXIF Metadata ─────────────────────────────
        exif_items = []
        exif_data  = {}
        try:
            raw = img.info.get("exif")
            if raw:
                exif_data = piexif.load(raw)
        except Exception:
            pass

        if exif_data:
            exif_items.append("✅  EXIF metadata block is present in the image.")

            gps = exif_data.get("GPS", {})
            if gps:
                score += 20
                lat_ref = gps.get(1, b"").decode("utf-8", errors="ignore") if isinstance(gps.get(1), bytes) else "?"
                lon_ref = gps.get(3, b"").decode("utf-8", errors="ignore") if isinstance(gps.get(3), bytes) else "?"
                metadata["GPS Latitude Ref"]  = lat_ref
                metadata["GPS Longitude Ref"] = lon_ref
                exif_items.append(f"🚨  GPS location data is embedded in this image "
                                  f"(Lat ref: {lat_ref}, Lon ref: {lon_ref}). "
                                  "Sharing this image online will expose the physical location "
                                  "where it was taken. Strip EXIF data before sharing.")
            else:
                exif_items.append("✅  No GPS coordinates embedded — location privacy is intact.")

            zeroth = exif_data.get("0th", {})
            make   = zeroth.get(271, b"").decode("utf-8", errors="ignore").strip() if isinstance(zeroth.get(271), bytes) else ""
            model  = zeroth.get(272, b"").decode("utf-8", errors="ignore").strip() if isinstance(zeroth.get(272), bytes) else ""
            soft   = zeroth.get(305, b"").decode("utf-8", errors="ignore").strip() if isinstance(zeroth.get(305), bytes) else ""

            if make or model:
                device_str = f"{make} {model}".strip()
                metadata["Camera / Device"] = device_str
                exif_items.append(f"ℹ️   Device info embedded: {device_str}. "
                                  "This identifies the physical device that captured the image.")
            if soft:
                metadata["Software"] = soft
                exif_items.append(f"ℹ️   Software tag: '{soft}'.")
                ai_tools = [
                    "stable diffusion", "midjourney", "dall-e", "firefly",
                    "runwayml", "deepfake", "faceswap", "reface", "wombo",
                    "this person does not exist"
                ]
                for tool in ai_tools:
                    if tool in soft.lower():
                        score += 40
                        exif_items.append(f"🚨  AI image generation tool identified in EXIF software tag: '{soft}'. "
                                          "This image was generated or heavily manipulated by artificial intelligence, "
                                          "not captured by a real camera.")
                        break

            dt_orig     = zeroth.get(36867)
            dt_modified = zeroth.get(306)
            if dt_orig:
                metadata["Date Taken"]    = dt_orig if isinstance(dt_orig, str) else dt_orig.decode("utf-8", errors="ignore")
            if dt_modified:
                metadata["Date Modified"] = dt_modified if isinstance(dt_modified, str) else dt_modified.decode("utf-8", errors="ignore")
            if dt_orig and dt_modified and dt_orig != dt_modified:
                score += 15
                exif_items.append("⚠️   Timestamp mismatch: the original capture timestamp differs from "
                                  "the last-modified timestamp. This strongly suggests the image was "
                                  "edited after being taken (e.g. via Photoshop or a deepfake tool).")
            elif dt_orig and dt_modified:
                exif_items.append("✅  Original and modified timestamps match — no post-capture editing detected.")
        else:
            score += 10
            exif_items.append("⚠️   No EXIF metadata found. Metadata is typically stripped from "
                              "screenshots, heavily edited images, and images processed by "
                              "AI-generation pipelines. Its absence is mildly suspicious.")

        sections.append({"title": "EXIF Metadata Analysis", "items": exif_items, "severity": "info"})

        # ── Section 2 : Pixel-level AI/manipulation signals ───────
        import numpy as np
        pixel_items = []
        arr = np.array(img.convert("RGB"))

        channel_stds  = [arr[:, :, c].std() for c in range(3)]
        avg_std        = round(sum(channel_stds) / 3, 2)
        channel_means = [arr[:, :, c].mean() for c in range(3)]
        mean_diff      = round(max(channel_means) - min(channel_means), 1)

        metadata["Pixel Noise (std)"]        = str(avg_std)
        metadata["Channel Imbalance (diff)"] = str(mean_diff)

        if avg_std < 8:
            score += 15
            pixel_items.append(f"⚠️   Very low pixel noise standard deviation ({avg_std}). "
                               "Real camera photos have natural sensor noise; AI-generated images "
                               "are often unnaturally smooth. This may indicate AI generation "
                               "or heavy post-processing.")
        else:
            pixel_items.append(f"✅  Pixel noise level ({avg_std}) is within the normal range for a real photo.")

        if mean_diff > 80:
            score += 10
            pixel_items.append(f"⚠️   High colour channel imbalance (diff = {mean_diff}). "
                               "A large gap between colour channel averages can indicate heavy "
                               "colour grading, compositing, or AI synthesis artefacts.")
        else:
            pixel_items.append(f"✅  Colour channel balance ({mean_diff}) looks natural.")

        if width < 100 or height < 100:
            score += 10
            pixel_items.append(f"⚠️   Image is very small ({width}×{height}px). "
                               "Tiny images are often placeholders, icons, or thumbnails — "
                               "not genuine photographs.")
        elif width == height and width in [512, 768, 1024, 1280, 2048]:
            score += 15
            pixel_items.append(f"⚠️   Resolution is {width}×{height}px (perfectly square). "
                               "AI image generators (Stable Diffusion, DALL-E, Midjourney) "
                               "commonly output images at exactly these square dimensions.")
        else:
            pixel_items.append(f"✅  Resolution ({width}×{height}px) does not match known AI output dimensions.")

        sections.append({"title": "Pixel-Level & AI-Generation Signals", "items": pixel_items, "severity": "info"})

        # ── Section 3 : Watermark / overlay detection ─────────────
        wm_items    = []
        top_band    = arr[:30, :, :]
        bottom_band = arr[-30:, :, :]
        wm_found    = False
        for band, pos in [(top_band, "top"), (bottom_band, "bottom")]:
            if band.std() < 5:
                score += 10
                wm_found = True
                wm_items.append(f"⚠️   Uniform (near-solid) pixel band detected at the {pos} of the image. "
                                "This pattern is characteristic of a watermark bar, burned-in text overlay, "
                                "or black letterbox — sometimes used to crop out identifying information.")
        if not wm_found:
            wm_items.append("✅  No uniform edge bands detected — no obvious watermark or overlay.")

        try:
            ratio = round(width / height, 2)
            stock_ratios = {1.33: "4:3", 1.50: "3:2", 1.78: "16:9", 0.67: "2:3 (portrait)", 0.75: "3:4 (portrait)"}
            matched = next((name for r, name in stock_ratios.items() if abs(ratio - r) < 0.02), None)
            if matched:
                wm_items.append(f"ℹ️   Aspect ratio {ratio} ({matched}) matches standard stock/professional "
                                "photo formats. Not a red flag on its own, but worth noting.")
        except ZeroDivisionError:
            pass

        sections.append({"title": "Watermark & Overlay Detection", "items": wm_items, "severity": "info"})

    except ImportError as e:
        sections.append({"title": "Error", "items": [f"Missing required library: {e}. "
                                                       "Run: pip install pillow piexif numpy"], "severity": "critical"})
    except Exception as e:
        sections.append({"title": "Error", "items": [f"Image analysis failed: {e}"], "severity": "critical"})

    reasons = [item for s in sections for item in s["items"]]
    return _build_result(score, reasons, sections, metadata)


# ══════════════════════════════════════════════════════════════════
#  Shared helpers
# ══════════════════════════════════════════════════════════════════

def detect_input_type(value):
    value = value.strip()
    if value.startswith("http://") or value.startswith("https://") or value.startswith("www."):
        return "url"
    if re.match(r"^[a-zA-Z0-9.\-_]+@[a-zA-Z0-9]+$", value) and "." not in value.split("@")[-1]:
        return "upi"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        return "email"
    if re.match(r"^\+?\d[\d\s\-\.\(\)]{5,}$", value):
        return "phone"
    return "unknown"


# ══════════════════════════════════════════════════════════════════
#  Professional display engine
# ══════════════════════════════════════════════════════════════════

W = 72   # total report width

RISK_STYLE = {
    "HIGH":    ("🔴", "HIGH RISK",    "═"),
    "MEDIUM":  ("🟡", "MEDIUM RISK",  "─"),
    "LOW":     ("🟢", "LOW RISK",     "─"),
    "SAFE":    ("✅", "SAFE",         "─"),
    "UNKNOWN": ("⚪", "UNKNOWN",      "─"),
}

SEVERITY_PREFIX = {
    "critical": "  ▶ ",
    "warning":  "  ▷ ",
    "info":     "  · ",
    "ok":       "  · ",
}


def _hr(char="─", width=W):
    return char * width


def _center(text, width=W):
    return text.center(width)


def _wrap(text, indent=6, width=W):
    """Simple word-wrap that respects leading emoji / bullet characters."""
    import textwrap
    # preserve existing leading spaces/bullets on first line
    lead  = len(text) - len(text.lstrip())
    first = text[:lead]
    rest  = text[lead:]
    lines = textwrap.wrap(rest, width=width - indent)
    if not lines:
        return text
    out = [first + lines[0]]
    for l in lines[1:]:
        out.append(" " * (indent + lead) + l)
    return "\n".join(out)


def print_result(label, result):
    icon, risk_label, hr_char = RISK_STYLE.get(result["risk"], RISK_STYLE["UNKNOWN"])
    score = result["score"]

    # ── Score bar ──────────────────────────────────────────────────
    bar_fill  = int(score / 100 * (W - 14))
    bar_empty = (W - 14) - bar_fill
    bar       = f"[{'█' * bar_fill}{'░' * bar_empty}]"

    # ── Recommendation ─────────────────────────────────────────────
    recommendations = {
        "HIGH":   "⛔  DO NOT interact with this. Report it to cybercrime.gov.in or 1930.",
        "MEDIUM": "⚠️   Exercise caution. Verify through official channels before proceeding.",
        "LOW":    "ℹ️   Minor concerns noted. Cross-check before sharing personal information.",
        "SAFE":   "✅  No significant threats detected. Remain generally cautious online.",
    }
    advice = recommendations.get(result["risk"], "")

    print()
    print(_hr("═"))
    print(_center(f"  SCANOSHIELD  —  FRAUD ANALYSIS REPORT  "))
    print(_hr("═"))
    print(f"  Target Type  :  {label}")
    print(f"  Scan Time    :  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")

    # Metadata block
    meta = result.get("metadata", {})
    if meta:
        print(_hr("─"))
        print("  TARGET DETAILS")
        print(_hr("─"))
        for k, v in meta.items():
            k_display = str(k).lstrip()
            indent    = "    " if k.startswith("  ") else "  "
            print(f"{indent}{k_display:<26}  {v}")

    print(_hr("═"))
    print(f"  {icon}  VERDICT  :  {risk_label}")
    print(f"  RISK SCORE   :  {score} / 100    {bar}")
    print(_hr("═"))
    print(f"\n  RECOMMENDATION")
    print(f"  {advice}")
    print()

    # Sections
    sections = result.get("sections", [])
    if sections:
        for sec in sections:
            title    = sec.get("title", "Details")
            items    = sec.get("items", [])
            severity = sec.get("severity", "info")
            prefix   = SEVERITY_PREFIX.get(severity, "  · ")

            print(_hr("─"))
            print(f"  ◈  {title.upper()}")
            print(_hr("─"))
            for item in items:
                # split item into lines for wrapping
                for line in item.split("\n"):
                    # preserve indented continuation lines
                    if line.startswith("     "):
                        print(f"       {line.lstrip()}")
                    else:
                        wrapped = _wrap(line, indent=4, width=W - 2)
                        for wl in wrapped.split("\n"):
                            if wl.strip():
                                print(f"{prefix}{wl}")
                            else:
                                print()
            print()
    else:
        # Fallback to flat reasons list
        print(_hr("─"))
        print("  FINDINGS")
        print(_hr("─"))
        for r in result.get("reasons", []):
            print(f"  ·  {r}")
        print()

    print(_hr("═"))
    print()


# ══════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════

MENU = {
    "1": ("URL",                  scan_url,    "Enter URL (e.g. https://example.com): ",         False),
    "2": ("Phone Number",         scan_phone,  "Enter phone number (e.g. +919876543210): ",       False),
    "3": ("Email Address",        scan_email,  "Enter email address: ",                           False),
    "4": ("UPI ID",               scan_upi,    "Enter UPI ID (e.g. name@okaxis): ",               False),
    "5": ("QR Code (image file)", scan_qr,     "Enter path to QR code image (e.g. qr.png): ",    False),
    "6": ("Social Media Profile", scan_social, "Enter username or profile URL (e.g. @user): ",   False),
    "7": ("Photo / Image",        scan_photo,  "Enter path to image file (e.g. photo.jpg): ",    False),
    "8": ("Auto-detect",          None,        "Enter any value (URL / phone / email / UPI): ",  False),
}

if __name__ == "__main__":
    print()
    print("═" * W)
    print(_center("  ▐  SCANOSHIELD  —  Digital Fraud Detector  ▌  "))
    print(_center("  Protecting India from Online Scams & Fraud  "))
    print("═" * W)
    print()
    print("  What would you like to scan?\n")
    for key, (label, _, _, _) in MENU.items():
        print(f"    [{key}]  {label}")
    print()

    choice = input("  Choose an option (1–8): ").strip()

    if choice not in MENU:
        print("\n  Invalid choice. Exiting.\n")
        sys.exit(1)

    label, scanner, prompt, _ = MENU[choice]
    value = input(f"\n  {prompt}").strip()

    if choice == "8":
        detected = detect_input_type(value)
        scanners_map = {
            "url":   scan_url,
            "phone": scan_phone,
            "email": scan_email,
            "upi":   scan_upi,
        }
        if detected == "unknown":
            print("\n  Could not determine input type. Please choose a specific option.\n")
            sys.exit(1)
        print(f"\n  Auto-detected input type: {detected.upper()}")
        result = scanners_map[detected](value)
    else:
        result = scanner(value)

    print_result(label, result)