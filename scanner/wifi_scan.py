import os
import re
import subprocess
from collections import Counter
from .utils import (
    resolve_vendor,
    get_channel_frequency,
    calculate_distance,
    assess_risk,
    analyze_siem_logs,
    get_active_connection_info,
    get_arp_devices
)

MAC_VENDORS = {
    "00:1A:2B": "Cisco Systems",
    "00:14:22": "Dell Inc.",
    "00:0C:29": "VMware",
    "F8:D1:11": "TP-Link",
    "18:E8:29": "Ubiquiti Networks",
    "C4:6E:1F": "Netgear",
    "2A:76:C8": "Xiaomi / Redmi",
    "00:25:9C": "Linksys",
    "B4:2E:99": "TP-Link",
    "DC:A6:32": "Raspberry Pi",
    "3C:84:6A": "Google",
    "AC:37:43": "Apple Inc.",
    "70:3A:C8": "Apple Inc.",
    "00:11:22": "TP-Link",
    "54:E4:3A": "Netgear",
    "A4:C3:F0": "Cisco Systems",
}

PHONE_VENDORS = [
    "apple", "samsung", "google", "oneplus", "xiaomi", "redmi", 
    "oppo", "vivo", "realme", "huawei", "motorola", "lg electronics",
    "poco", "iqoo", "nothing", "infinix", "tecno", "asus", "nokia"
]


def is_locally_administered_mac(bssid):
    """
    Checks if MAC address is randomized/locally administered.
    Mobile hotspots almost always use randomized MACs (x2, x6, xA, xE in 1st octet).
    """
    if not bssid or bssid == "N/A":
        return False
    try:
        first_octet = int(bssid.split(":")[0], 16)
        # Check bit 1 (2's bit)
        return bool(first_octet & 2)
    except Exception:
        return False


def classify_device_type(ssid, vendor, bssid=""):
    """
    Classifies whether a device is a Mobile Phone Hotspot ('phone') 
    or a Standard Wi-Fi Router/AP ('router').
    """
    ssid_lower = (ssid or "").lower()
    vendor_lower = (vendor or "").lower()

    phone_keywords = [
        "iphone", "galaxy", "pixel", "oneplus", "android", 
        "hotspot", "mobile", "redmi", "realme", "vivo", "oppo",
        "poco", "xiaomi", "iqoo", "infinix", "tecno", "nothing",
        "samsung", "huawei", "honor", "motorola", "asus", "nokia"
    ]
    
    # 1. Check SSID keywords (e.g. POCO C50, Galaxy S21, John's iPhone)
    if any(keyword in ssid_lower for keyword in phone_keywords):
        return "phone"

    # 2. Check vendor string
    if any(p_vendor in vendor_lower for p_vendor in PHONE_VENDORS):
        return "phone"

    # 3. Fallback: If MAC is randomized (common on mobile hotspots) and vendor is unknown
    if is_locally_administered_mac(bssid) and vendor == "Unknown Vendor":
        # Additional check: standard routers rarely use default phone model naming style
        if re.search(r"^[a-zA-Z0-9\s]+$", ssid_lower) and not any(r_kw in ssid_lower for r_kw in ["wifi", "router", "net", "broadband", "fiber"]):
            return "phone"

    return "router"


def classify_security(auth, encryption):
    """Classifies authentication and encryption types into standard tags."""
    auth = (auth or "").upper()
    encryption = (encryption or "").upper()

    if "OPEN" in auth or encryption in ("NONE", "N/A", ""):
        return "OPEN"
    if "WEP" in auth or "WEP" in encryption:
        return "WEP"
    if "WPA3" in auth:
        return "WPA3"
    if "WPA2" in auth:
        return "WPA2"
    if "WPA" in auth:
        return "WPA"

    return "UNKNOWN"


def calculate_risk(auth, encryption, is_duplicate):
    """Calculates risk level and provides human-readable vulnerability details."""
    security = classify_security(auth, encryption)

    if security == "WEP":
        return (
            "CRITICAL",
            "Obsolete WEP cipher key easily cracked using standard tools."
        )

    if security == "OPEN":
        return (
            "HIGH",
            "Open network advertising no encryption. Wireless traffic is unencrypted."
        )

    if is_duplicate:
        return (
            "HIGH" if security in ("OPEN", "WEP") else "MEDIUM",
            "Mismatched security or duplicate SSID parameters. Investigate for Evil Twin."
        )

    if security in ("WPA3", "WPA2"):
        return ("LOW", "None")

    return ("MEDIUM", "Legacy security configuration detected.")


def detect_band(channel, radio_type):
    """Identifies frequency band (2.4 GHz vs 5 GHz)."""
    radio_type = (radio_type or "").lower()

    if "802.11a" in radio_type or "802.11ac" in radio_type:
        return "5 GHz"
    if "802.11ax" in radio_type:
        return "2.4/5 GHz"

    try:
        channel_number = int(channel)
        if 1 <= channel_number <= 14:
            return "2.4 GHz"
        if 32 <= channel_number <= 177:
            return "5 GHz"
    except (ValueError, TypeError):
        pass

    return "2.4 GHz"


def analyze_channels(networks):
    """Calculates channel usage for congestion analysis."""
    channel_counts = Counter()
    for net in networks:
        channel = str(net.get("channel", "N/A"))
        if channel != "N/A":
            channel_counts[channel] += 1

    standard_channels = ["1", "6", "11"]
    best_channel = min(standard_channels, key=lambda ch: channel_counts[ch])

    return dict(channel_counts), best_channel


def get_arp_ip_map():
    """Maps BSSID/MAC addresses to local IP addresses using Windows ARP table."""
    ip_map = {}
    try:
        output = subprocess.check_output(["arp", "-a"], encoding="utf-8", errors="ignore")
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parts[0]):
                ip = parts[0]
                mac = parts[1].replace("-", ":").upper()
                ip_map[mac] = ip
    except Exception:
        pass
    return ip_map


def get_vendor(bssid):
    """Identifies vendor from first 3 octets or detects randomized MAC."""
    if not bssid or bssid == "N/A":
        return "Unknown Vendor"

    prefix = bssid.upper().replace("-", ":")[:8]
    vendor = MAC_VENDORS.get(prefix)
    if vendor:
        return vendor

    if is_locally_administered_mac(bssid):
        return "Randomized / Private MAC"

    return "Unknown Vendor"


def get_active_connection_info():
    """Extracts Link Speed, State, Signal, and SSID from Windows WLAN interface."""
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            encoding="utf-8",
            errors="ignore"
        )
        info = {
            "ssid": "Not Connected",
            "receive_rate": "N/A",
            "transmit_rate": "N/A",
            "signal": "N/A",
            "state": "disconnected"
        }
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("State"):
                info["state"] = line.split(":", 1)[1].strip()
            elif line.startswith("SSID") and not line.startswith("BSSID"):
                info["ssid"] = line.split(":", 1)[1].strip()
            elif "Receive rate (Mbps)" in line:
                info["receive_rate"] = f"{line.split(':', 1)[1].strip()} Mbps"
            elif "Transmit rate (Mbps)" in line:
                info["transmit_rate"] = f"{line.split(':', 1)[1].strip()} Mbps"
            elif line.startswith("Signal"):
                info["signal"] = line.split(":", 1)[1].strip()
        return info
    except Exception:
        return {}


def get_network_route():
    """Extracts Default Gateway IP, Local IP, and Subnet Mask via ipconfig."""
    try:
        output = subprocess.check_output(
            ["ipconfig"],
            encoding="utf-8",
            errors="ignore"
        )
        route_info = {"local_ip": "N/A", "gateway": "N/A", "subnet": "N/A"}
        
        ip_match = re.search(r"IPv4 Address[^\:]*:\s*([0-9\.]+)", output)
        gw_match = re.search(r"Default Gateway[^\:]*:\s*([0-9\.]+)", output)
        mask_match = re.search(r"Subnet Mask[^\:]*:\s*([0-9\.]+)", output)

        if ip_match:
            route_info["local_ip"] = ip_match.group(1)
        if gw_match:
            route_info["gateway"] = gw_match.group(1)
        if mask_match:
            route_info["subnet"] = mask_match.group(1)

        return route_info
    except Exception:
        return {"local_ip": "N/A", "gateway": "N/A", "subnet": "N/A"}


def get_connected_devices_count():
    """Parses Windows ARP table to count active IP endpoints on local subnet."""
    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            encoding="utf-8",
            errors="ignore"
        )
        devices = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parts[0]):
                ip, mac, ip_type = parts[0], parts[1], parts[2]
                if ip_type.lower() == "dynamic" and not ip.startswith("224."):
                    devices.append({"ip": ip, "mac": mac})
        return len(devices), devices
    except Exception:
        return 0, []


def scan_wifi_networks_advanced():
    """Runs Windows netsh wlan command and outputs formatted network telemetry."""
    try:
        raw_output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            encoding="utf-8",
            errors="ignore"
        )

        raw_networks = []
        current_net = {}

        for line in raw_output.splitlines():
            line = line.strip()

            if line.startswith("SSID"):
                if current_net and "ssid" in current_net:
                    raw_networks.append(current_net)
                    current_net = {}

                parts = line.split(":", 1)
                ssid = parts[1].strip() if len(parts) > 1 else ""
                current_net["ssid"] = ssid if ssid else "Hidden Network"

            elif line.startswith("Radio type"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_net["radio_type"] = parts[1].strip()

            elif line.startswith("Authentication"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_net["auth"] = parts[1].strip()

            elif line.startswith("Encryption"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_net["encryption"] = parts[1].strip()

            elif line.startswith("BSSID"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_net["bssid"] = parts[1].strip().upper()

            elif line.startswith("Signal"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_net["signal"] = parts[1].strip()

            elif line.startswith("Channel"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_net["channel"] = parts[1].strip()

        if current_net and "ssid" in current_net:
            raw_networks.append(current_net)

        ssid_counter = Counter(
            net["ssid"] for net in raw_networks if net.get("ssid") != "Hidden Network"
        )

        arp_map = get_arp_ip_map()
        alerts = []
        processed_networks = []

        for net in raw_networks:
            ssid = net.get("ssid", "Hidden Network")
            bssid = net.get("bssid", "N/A")
            auth = net.get("auth", "Open")
            encryption = net.get("encryption", "None")
            radio_type = net.get("radio_type", "Unknown")
            channel = net.get("channel", "N/A")

            security = classify_security(auth, encryption)
            is_duplicate = (ssid != "Hidden Network" and ssid_counter[ssid] > 1)
            vendor = get_vendor(bssid)
            band = detect_band(channel, radio_type)
            risk_score, risk_reason = calculate_risk(auth, encryption, is_duplicate)
            device_type = classify_device_type(ssid, vendor, bssid)
            assigned_ip = arp_map.get(bssid, "N/A")

            net_obj = {
                "ssid": ssid,
                "bssid": bssid,
                "ip": assigned_ip,
                "vendor": vendor,
                "type": device_type,
                "channel": channel,
                "band": band,
                "security": security,
                "encryption": encryption,
                "signal": net.get("signal", "0%"),
                "is_unsecured": (security in ["OPEN", "WEP"]),
                "risk_score": risk_score,
                "vulnerability": risk_reason,
                "is_suspicious": is_duplicate
            }

            if security == "OPEN":
                alerts.append(f"OPEN NETWORK DETECTED: '{ssid}' ({bssid}) has no encryption enabled.")
            elif security == "WEP":
                alerts.append(f"WEAK SECURITY DETECTED: '{ssid}' ({bssid}) uses vulnerable WEP encryption.")

            if is_duplicate:
                alerts.append(f"SUSPECTED EVIL TWIN: Duplicate SSID '{ssid}' detected across multiple APs.")

            processed_networks.append(net_obj)

        # Dashboard Summary Aggregations
        channel_stats, recommended_channel = analyze_channels(processed_networks)
        security_summary = Counter(net["security"] for net in processed_networks)
        risk_summary = Counter(net["risk_score"] for net in processed_networks)

        # Network Telemetry
        active_info = get_active_connection_info()
        route_info = get_network_route()
        device_count, device_list = get_connected_devices_count()

        return {
            "status": "success",
            "count": len(processed_networks),
            "networks": processed_networks,
            "alerts": list(dict.fromkeys(alerts)),
            "recommended_channel": recommended_channel,
            "channel_stats": channel_stats,
            "security_summary": dict(security_summary),
            "risk_summary": dict(risk_summary),
            "active_connection": active_info,
            "network_route": route_info,
            "connected_devices_count": device_count,
            "connected_devices": device_list
        }

    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "message": f"Windows Wi-Fi scan failed: {str(e)}",
            "networks": [],
            "alerts": []
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "networks": [],
            "alerts": []
        }