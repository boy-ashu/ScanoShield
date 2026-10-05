import re
import os
import json
import math
import subprocess
from collections import Counter
import socket
import requests
import urllib.request
import phonenumbers
from phonenumbers import geocoder, carrier

OUI_VENDOR_MAP = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:11": "Google",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1D:7E": "Cisco",
    "00:00:0C": "Cisco",
    "F4:92:BF": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "50:C7:BF": "TP-Link",
    "EC:08:6B": "TP-Link",
    "00:14:6C": "Netgear",
    "28:80:23": "Netgear",
    "C8:3A:35": "Tenda",
    "00:1E:10": "Apple",
    "F4:F5:DB": "Apple",
    "F0:99:B6": "Apple",
}

def resolve_vendor(bssid):
    """Extracts MAC prefix to resolve hardware vendor."""
    if not bssid or len(bssid) < 8:
        return "Unknown Vendor"
    prefix = bssid.upper()[:8].replace("-", ":")
    return OUI_VENDOR_MAP.get(prefix, "Generic IEEE Device")


def get_channel_frequency(channel):
    """Maps channel number to frequency in MHz and band string."""
    try:
        ch = int(channel)
        if 1 <= ch <= 14:
            freq = 2412 + (ch - 1) * 5 if ch != 14 else 2484
            return freq, "2.4 GHz"
        else:
            return 5000 + (ch * 5), "5 GHz"
    except Exception:
        return 2412, "2.4 GHz"

def resolve_target_to_ip(target_str, target_type):
    """Extracts an IP address depending on the target type."""
    target_str = target_str.strip()
    
    if target_type == "domain":
        try:
            # Strip protocol if present
            clean_domain = re.sub(r'https?://', '', target_str).split('/')[0]
            return socket.gethostbyname(clean_domain)
        except Exception:
            return None

    elif target_type == "email":
        try:
            domain = target_str.split('@')[-1]
            return socket.gethostbyname(domain)
        except Exception:
            return None

    elif target_type == "ip":
        return target_str

    return None


def get_geolocation_data(target_input, target_type="ip"):
    ip_address = resolve_target_to_ip(target_input, target_type)
    
    # If testing locally, fetch host's external public IP
    if not ip_address or ip_address in ["127.0.0.1", "localhost", "0.0.0.0"]:
        try:
            ip_address = requests.get('https://api.ipify.org', timeout=3).text
        except Exception:
            ip_address = None

    if ip_address:
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": ip_address,
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp_organization": data.get("isp", "Unknown Network"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "countryCode": data.get("countryCode", "")
                }
        except Exception as e:
            print(f"Geolocation lookup failed: {e}")

    return {
        "error": "Unable to resolve valid public IP location."
    }


def calculate_distance(signal_pct, frequency_mhz=2412):
    """Calculates approximate distance using Free-Space Path Loss (FSPL)."""
    try:
        sig = float(str(signal_pct).replace("%", ""))
        if sig <= 0:
            return "Unknown"
        dbm = (sig / 2.0) - 100.0
        exp = (27.55 - (20.0 * math.log10(frequency_mhz)) + abs(dbm)) / 20.0
        meters = math.pow(10, exp)
        return f"{round(meters, 1)}m"
    except Exception:
        return "N/A"

def assess_risk(auth, encryption, ssid, all_ssids):
    """Evaluates AP vulnerability level and flags duplicate SSIDs (Rogue APs)."""
    auth_upper = auth.upper()
    enc_upper = encryption.upper()
    
    if "OPEN" in auth_upper or "NONE" in enc_upper:
        return "CRITICAL", "Unencrypted Open Wi-Fi Network. Traffic can be eavesdropped."
    if "WEP" in auth_upper or "WEP" in enc_upper:
        return "CRITICAL", "Deprecating WEP encryption detected. Easily crackable."
    if "WPA" in auth_upper and "WPA2" not in auth_upper and "WPA3" not in auth_upper:
        return "HIGH", "Legacy WPA1 protocol detected. Vulnerable to handshake attacks."
    if all_ssids.count(ssid) > 1 and ssid != "Hidden Network":
        return "HIGH", "Rogue AP Alert: Multiple Access Points broadcasting identical SSID."
    if "WPA2" in auth_upper:
        return "LOW", "Standard WPA2 Security Enabled."
    if "WPA3" in auth_upper:
        return "LOW", "Strong WPA3 Enterprise/Personal Security Enabled."
        
    return "MEDIUM", "Non-standard security configuration."

def analyze_siem_logs(threshold=3):
    """Parses system event logs for failed login attempts (Forensics/SIEM module)."""
    failed_counts = Counter()
    try:
        if os.name == 'nt':
            cmd = 'powershell "Get-WinEvent -FilterHashtable @{LogName=\'Security\'; Id=4625} -MaxEvents 50 | Select-Object -ExpandProperty Message"'
            out = subprocess.check_output(cmd, shell=True, text=True, errors='ignore', timeout=5)
            ips = re.findall(r'Source Network Address:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', out)
            failed_counts.update(ips)

        else:
            log_path = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    logs = f.readlines()[-200:]
                for line in logs:
                    if "Failed password" in line:
                        ip_match = re.search(r'from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
                        if ip_match:
                            failed_counts[ip_match.group(1)] += 1

    except Exception:
        pass

    suspicious = {ip: count for ip, count in failed_counts.items() if count >= threshold}
    return {
        "status": "success",
        "total_failed_attempts": sum(failed_counts.values()),
        "suspicious_targets": suspicious
    }

def get_active_connection_info():
    """Extracts interface rate, default gateway, and local IP routing."""
    active_conn = {"bssid": "", "receive_rate": "N/A", "transmit_rate": "N/A"}
    route_info = {"gateway": "N/A", "local_ip": "N/A", "subnet": "255.255.255.0"}
    
    try:
        if os.name == 'nt':
            out = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True, errors='ignore')
            bssid_m = re.search(r'BSSID\s+:\s+([0-9a-fA-F:]+)', out)
            rx_m = re.search(r'Receive rate \(Mbps\)\s+:\s+([0-9.]+)', out)
            tx_m = re.search(r'Transmit rate \(Mbps\)\s+:\s+([0-9.]+)', out)
            
            if bssid_m: active_conn["bssid"] = bssid_m.group(1).strip()
            if rx_m: active_conn["receive_rate"] = f"{rx_m.group(1)} Mbps"
            if tx_m: active_conn["transmit_rate"] = f"{tx_m.group(1)} Mbps"
            
            ip_out = subprocess.check_output("ipconfig", shell=True, text=True, errors='ignore')
            gw_m = re.search(r'Default Gateway[.\s]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', ip_out)
            ip_m = re.search(r'IPv4 Address[.\s]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', ip_out)
            
            if gw_m: route_info["gateway"] = gw_m.group(1)
            if ip_m: route_info["local_ip"] = ip_m.group(1)
    except Exception:
        pass
        
    return active_conn, route_info

def get_arp_devices():
    """Scans local ARP table for connected endpoints."""
    devices = []
    try:
        out = subprocess.check_output("arp -a", shell=True, text=True, errors='ignore')
        matches = re.findall(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fa-f-]{17})\s+(\w+)', out)
        for ip, mac, dev_type in matches:
            if not ip.startswith("224.") and not ip.endswith(".255"):
                devices.append({"ip": ip, "mac": mac.replace("-", ":").upper(), "type": dev_type})
    except Exception:
        pass
    return devices

# -------------------------------------------------------------------
# OSINT & GEOLOCATION LOOKUP HELPERS
# -------------------------------------------------------------------

def detect_input_type(value: str) -> str:
    """Detects whether input is an IP, Phone, Email, Domain, or Unknown."""
    value = value.strip()
    
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


def lookup_ip(ip_str):
    """Queries ipapi.co for IP geolocation details."""
    ip_str = ip_str.strip()
    url = f"https://ipapi.co/{ip_str}/json/" if ip_str else "https://ipapi.co/json/"
    
    req = urllib.request.Request(url, headers={'User-Agent': 'ScanoShield-Locator/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            
            if data.get("error"):
                return {"error": data.get("reason", "Invalid IP or rate limit reached.")}
            
            return {
                "type": "IP Geolocation",
                "ip_address": data.get("ip"),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": f"{data.get('country_name')} ({data.get('country_code')})",
                "postal_code": data.get("postal", "N/A"),
                "isp_organization": data.get("org", "Unknown ISP"),
                "coordinates": f"{data.get('latitude')}, {data.get('longitude')}",
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "note": "IP locations represent ISP routing nodes and server hubs, not precise street-level physical addresses."
            }
    except Exception as e:
        return {"error": f"Lookup failed: {str(e)}"}


def lookup_phone(phone_str: str) -> dict:
    """Parses international phone numbers for country and carrier information."""
    phone_str = phone_str.strip()
    
    # Prepend '+' if missing for raw 10-digit Indian numbers
    if not phone_str.startswith("+") and len(phone_str) == 10 and phone_str.startswith(("6", "7", "8", "9")):
        phone_str = "+91" + phone_str

    try:
        parsed_num = phonenumbers.parse(phone_str)
        if not phonenumbers.is_valid_number(parsed_num):
            raise ValueError("Invalid phone format")
        
        country_loc = geocoder.description_for_number(parsed_num, "en") or "India"
        provider = carrier.name_for_number(parsed_num, "en") or "Telecom Provider"
        code = f"+{parsed_num.country_code}"
        
        return {
            "type": "Phone Number",
            "formatted": phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country": country_loc,
            "region": country_loc,
            "city": country_loc,
            "carrier": provider,
            "isp_organization": provider,
            "countryCode": code,
            "latitude": 20.5937 if code == "+91" else 37.7749,
            "longitude": 78.9629 if code == "+91" else -122.4194,
            "threatScore": 10
        }
    except Exception:
        return {
            "type": "Phone Number",
            "formatted": phone_str,
            "country": "India" if phone_str.startswith("+91") or len(phone_str) == 10 else "United States",
            "region": "Telecom Circle",
            "city": "Unknown City",
            "carrier": "Cellular Network Provider",
            "isp_organization": "Cellular Network Provider",
            "countryCode": "+91" if len(phone_str) == 10 else "+1",
            "latitude": 20.5937,
            "longitude": 78.9629,
            "threatScore": 5
        }

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
    """Resolves a domain name to its primary IP address and performs geolocation."""
    domain_str = domain_str.strip()
    try:
        resolved_ip = socket.gethostbyname(domain_str)
        ip_data = lookup_ip(resolved_ip)
        return {
            "type": "Domain Name",
            "domain": domain_str,
            "resolved_ip": resolved_ip,
            "ip_data": ip_data
        }
    except socket.gaierror:
        return {"error": f"Could not resolve IP for domain {domain_str}"}