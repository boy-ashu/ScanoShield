# scanner/utils.py
import re
import json
import socket
import urllib.request
import phonenumbers
from phonenumbers import geocoder, carrier

def detect_input_type(value: str) -> str:
    """Detects whether input is an IP, Phone, Email, Domain, or Unknown."""
    value = value.strip()
    
    # Simple regex rules
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    email_pattern = r"^[\w\.-]+@([\w\.-]+\.\w+)$"
    phone_pattern = r"^\+?[0-9]{7,15}$"
    domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    if re.match(ip_pattern, value):
        return "ip"
    elif re.match(email_pattern, value):
        return "email"
    elif re.match(phone_pattern, value):
        return "phone"
    elif re.match(domain_pattern, value):
        return "domain"
    return "unknown"


def lookup_ip(ip_str: str) -> dict:
    """Fetches approximate geographical details using ipapi.co API."""
    ip_str = ip_str.strip()
    url = f"https://ipapi.co/{ip_str}/json/" if ip_str else "https://ipapi.co/json/"
    req = urllib.request.Request(url, headers={'User-Agent': 'ScanoShield-Locator/1.0'})
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            if "error" in data:
                return {"error": data.get('reason', 'Invalid IP or rate limit reached')}
            
            return {
                "type": "IP Address",
                "ip": data.get('ip'),
                "city": data.get('city'),
                "region": data.get('region'),
                "country": data.get('country_name'),
                "postal": data.get('postal'),
                "isp": data.get('org'),
                "coordinates": f"{data.get('latitude')}, {data.get('longitude')}",
                "note": "IP locations represent ISP routing points, not exact physical addresses."
            }
    except Exception as e:
        return {"error": f"Network error: {str(e)}"}


def lookup_phone(phone_str: str) -> dict:
    """Parses international phone numbers for country and carrier information."""
    try:
        parsed_num = phonenumbers.parse(phone_str.strip())
        if not phonenumbers.is_valid_number(parsed_num):
            return {"error": "Invalid phone format. Please include country code (e.g. +14155552671)."}
        
        return {
            "type": "Phone Number",
            "formatted": phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country": geocoder.description_for_number(parsed_num, "en") or "Unknown",
            "carrier": carrier.name_for_number(parsed_num, "en") or "Unknown/Ported",
            "note": "Live GPS location requires device-level permissions or carrier authorization."
        }
    except Exception as e:
        return {"error": f"Phone parsing error: {str(e)}"}


def lookup_email(email_str: str) -> dict:
    """Validates email format and checks domain MX/A record status."""
    email_str = email_str.strip()
    match = re.match(r"^[\w\.-]+@([\w\.-]+\.\w+)$", email_str)
    
    if not match:
        return {"error": "Invalid email address format."}
    
    domain = match.group(1)
    status = "Unreachable domain"
    try:
        socket.gethostbyname(domain)
        status = "Active (Domain resolves)"
    except socket.gaierror:
        pass

    return {
        "type": "Email Address",
        "email": email_str,
        "domain": domain,
        "status": status,
        "note": "Email addresses do not broadcast real-time physical GPS location."
    }


def lookup_domain(domain_str: str) -> dict:
    """Resolves a domain name to its primary IP address."""
    domain_str = domain_str.strip()
    try:
        resolved_ip = socket.gethostbyname(domain_str)
        return {
            "type": "Domain Name",
            "domain": domain_str,
            "resolved_ip": resolved_ip
        }
    except socket.gaierror:
        return {"error": f"Could not resolve IP for domain {domain_str}"}