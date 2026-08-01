import os
import hashlib
import math
import json
import struct
import requests
from datetime import datetime
import zipfile
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

ANDROID_PERMISSION_INFO = {
    "android.permission.INTERNET":
        "Allows internet access",

    "android.permission.CAMERA":
        "Allows camera access",

    "android.permission.RECORD_AUDIO":
        "Allows microphone access",

    "android.permission.ACCESS_FINE_LOCATION":
        "Allows GPS access",
}

SUSPICIOUS_PATTERNS = {
    # Tumhare existing patterns
    "eval("      : "Dynamically generated code execute karta hai — malicious instructions chupayi ja sakti hain.",
    "exec("      : "Runtime pe arbitrary code run kar sakta hai.",
    "subprocess" : "External programs aur processes launch kar sakta hai.",
    "os.system"  : "OS commands execute kar sakta hai.",
    "powershell" : "PowerShell scripts run ya payload download kar sakta hai.",
    "cmd.exe"    : "Windows shell commands run kar sakta hai.",
    "socket"     : "Network connections bana sakta hai.",
    "base64"     : "Code aur payloads chupaane ke liye use hota hai.",
    "wget"       : "Remote servers se files download kar sakta hai.",
    "curl"       : "Remote systems se data transfer kar sakta hai.",

    # Naye — Ransomware patterns
    "cryptolocker"      : "Famous ransomware ka naam — highly suspicious.",
    "your files have been encrypted" : "Ransomware message pattern.",
    ".locked"           : "Ransomware file extension pattern.",
    "bitcoin"           : "Ransom payment pattern — suspicious context mein.",

    # Naye — Backdoor / RAT patterns
    "reverse_shell"     : "Reverse shell connection attempt.",
    "bind_shell"        : "Bind shell — attacker connection accept karta hai.",
    "meterpreter"       : "Metasploit payload — common in attacks.",
    "nc -e"             : "Netcat reverse shell command.",
    "bash -i"           : "Interactive bash shell spawn — suspicious.",

    # Naye — Webshell patterns
    "system($_get"      : "PHP webshell — GET se command execute karta hai.",
    "system($_post"     : "PHP webshell — POST se command execute karta hai.",
    "passthru("         : "PHP function jo OS commands chalata hai.",
    "shell_exec("       : "PHP shell execution function.",
    "eval(base64_decode": "Obfuscated PHP code — common webshell pattern.",

    # Naye — Keylogger patterns
    "getasynckeystate"  : "Windows keylogger API — keystroke capture.",
    "setwindowshookex"  : "Windows hook — keyboard/mouse monitoring.",
    "keylogger"         : "Direct keylogger reference.",

    # Naye — Network threats
    "urllib.request"    : "Python HTTP requests — payload download ho sakta hai.",
    "http.get("         : "HTTP request — data exfiltration possible.",
    "ftp.connect"       : "FTP connection — suspicious file transfer.",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe" : "Windows executable — directly code run kar sakta hai.",
    ".bat" : "Windows batch script — shell commands run karta hai.",
    ".cmd" : "Windows command file — batch script jaisa.",
    ".vbs" : "VBScript — Windows automation abuse hota hai.",
    ".ps1" : "PowerShell script — powerful system access.",
    ".scr" : "Screen saver file — executable disguise.",
    ".dll" : "Dynamic library — inject ho sakti hai doosre programs mein.",
    ".sys" : "System driver — kernel level access.",
    ".jar" : "Java archive — cross platform code run karta hai.",
    ".apk" : "Android package — mobile malware.",
    ".hta" : "HTML Application — browser se system access.",
    ".lnk" : "Windows shortcut — malicious paths chupaata hai.",
    ".reg" : "Registry file — system settings badal sakta hai.",
}

LANGUAGE_PATTERNS = {
    "Python": ["import ", "def ", "if __name__ =="],
    "Java": ["public class", "System.out.println"],
    "JavaScript": ["function ", "console.log("],
    "PHP": ["<?php", "$_GET", "$_POST"],
    "C": ["#include <stdio.h>", "printf("],
    "C++": ["#include <iostream>", "std::", "cout <<"],
    "C#": ["using System;", "Console.WriteLine("],
    "Go": ["package main", "func main()"],
    "Rust": ["fn main()", "println!"],
}


MAGIC_SIGNATURES = {
    b'\x4D\x5A'            : '.exe / .dll  (Windows Executable)',
    b'\x7fELF'             : '.elf          (Linux Executable)',
    b'\xca\xfe\xba\xbe'   : '.class        (Java Bytecode)',
    b'PK\x03\x04'          : '.zip / .jar  (ZIP Archive)',
    b'\x50\x4b\x03\x04'   : '.docx / .xlsx (Office Document)',
    b'\xd0\xcf\x11\xe0'   : '.doc / .xls  (Old Office Format)',
    b'%PDF'                : '.pdf          (PDF Document)',
    b'\xff\xd8\xff'        : '.jpg          (JPEG Image)',
    b'\x89PNG'             : '.png          (PNG Image)',
    b'GIF8'                : '.gif          (GIF Image)',
    b'\x1f\x8b'            : '.gz           (GZIP Compressed)',
    b'Rar!'                : '.rar          (RAR Archive)',
    b'#!/'                 : 'Shell Script  (Unix/Linux)',
    b'<?php'               : 'PHP Script    (Web Script)',
}


def calculate_hash(file_path):
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5"    : md5.hexdigest(),
        "sha1"   : sha1.hexdigest(),
        "sha256" : sha256.hexdigest(),
    }


def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def check_magic_bytes(file_path):
    """
    File ke pehle bytes padhkar asli type detect karo.
    Agar extension aur magic bytes alag hain — suspicious!
    """
    with open(file_path, "rb") as f:
        header = f.read(8)

    detected = None
    for magic, file_type in MAGIC_SIGNATURES.items():
        if header.startswith(magic):
            detected = file_type
            break

    return detected

def detect_file_type(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    result = {
        "category": "Unknown",
        "type": "Unknown"
    }

    try:
        if zipfile.is_zipfile(file_path):

            with zipfile.ZipFile(file_path, "r") as z:
                names = [n.lower() for n in z.namelist()]

                if "androidmanifest.xml" in names:
                    return {
                        "category": "Mobile Application",
                        "type": "Android APK"
                    }
                if "meta-inf/manifest.mf" in names:
                    return {
                        "category": "Java Applications",
                        "type": "JAR Archive"
                    }
                
                if any(n.startswith("word/") for n in names):
                    return {
                        "category": "Document",
                        "type": "Microsoft Word"
                    }
                
                if any(n.startswith("xl/") for n in names):
                    return {
                        "category": "Spreadsheet",
                        "type": "Microsoft Excel"
                    }
                
                if any(n.startswith("ppt/") for n in names):
                    return {
                        "category": "Presentation",
                        "type": "Microsoft PowerPoint"   
                    }
        mapping = {
            ".exe": ("Executable", "Windows Executable"),
            ".dll": ("Library", "Windows DLL"),
            ".pdf": ("Document", "PDF Document"),
            ".jpg": ("Image", "JPEG Image"),
            ".jpeg": ("Image", "JPEG Image"),
            ".png": ("Image", "PNG Image"),
            ".gif": ("Image", "GIF Image"),
            ".py": ("Source Code", "Python Script"),
            ".java": ("Source Code", "Java Source"),
            ".js": ("Source Code", "JavaScript"),
            ".php": ("Source Code", "PHP Script"),
        }  
        
        if ext in mapping:
            result["category"] = mapping[ext][0]
            result["type"] = mapping[ext][1]

    except Exception:
        pass

    return result

def check_extension_mismatch(file_path, magic_type):
    ext = os.path.splitext(file_path)[1].lower()
    if not magic_type:
        return False

    dangerous_mismatch = {
        ".jpg"  : ["exe", "elf"],    # list use karo
        ".jpeg" : ["exe"],
        ".png"  : ["exe", "php"],
        ".gif"  : ["exe"],
        ".pdf"  : ["exe"],
        ".txt"  : ["exe"],
    }

    for safe_ext, dangerous_list in dangerous_mismatch.items():
        if ext == safe_ext:
            for dangerous in dangerous_list:
                if dangerous in magic_type.lower():
                    return True

    return False

def scan_content(file_path):
    findings = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()

        for pattern, reason in SUSPICIOUS_PATTERNS.items():
            if pattern.lower() in content:
                findings.append({
                    "pattern" : pattern,
                    "reason"  : reason,
                })
    except Exception:
        pass
    return findings


def check_virustotal(sha256: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "reason": "API key not found."}

    try:
        headers  = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=10,
        )

        if response.status_code == 404:
            return {
                "status"  : "not_found",
                "reason": "The file hash was not found in the VirusTotal database. This may indicate that the file is new or has not been previously analyzed."
            }

        if response.status_code == 200:
            data  = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "status"     : "found",
                "malicious"  : stats.get("malicious",  0),
                "suspicious" : stats.get("suspicious", 0),
                "undetected" : stats.get("undetected", 0),
                "harmless"   : stats.get("harmless",   0),
                "total"      : sum(stats.values()),
                "link"       : f"https://www.virustotal.com/gui/file/{sha256}",
            }

    except requests.exceptions.ConnectionError:
        return {"status": "error", "reason": "No Internet Connection available"}
    except Exception as e:
        return {"status": "error", "reason": str(e)}

    return {"status": "error", "reason": "Unknown error."}


def calculate_risk_score(ext, entropy, findings, magic_mismatch, vt_result):
    score = 0

    # Extension (tumhara existing)
    if ext in SUSPICIOUS_EXTENSIONS:
        score += 40

    # Entropy (tumhara existing)
    if entropy > 7:
        score += 30
    elif entropy > 6:
        score += 15

    # Patterns (tumhara existing — per pattern)
    score += len(findings) * 10

    # Magic bytes mismatch — NAYA
    if magic_mismatch:
        score += 35   # .jpg ke andar .exe — bahut dangerous

    # VirusTotal — NAYA
    if vt_result.get("status") == "found":
        malicious = vt_result.get("malicious", 0)
        if malicious > 10 : score += 50
        elif malicious > 5: score += 35
        elif malicious > 0: score += 20

    return min(score, 100)


def get_threat_level(score):
    if score == 0    : return "CLEAN"
    if score <= 20   : return "LOW"
    if score <= 50   : return "MEDIUM"
    if score <= 80   : return "HIGH"
    return "CRITICAL"

def scan_file(file_path, orginal_filename=None):
    display_name = orginal_filename if orginal_filename else os.path.basename(file_path)
    ext = os.path.splitext(display_name)[1].lower()

    report = {
        "file"         : file_path,
        "filename"     : display_name,
        "size"         : os.path.getsize(file_path),
        "scan_time"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "extension"    : ext,
        "magic_type"   : None,
        "magic_mismatch": False,
        "hashes"       : {},
        "entropy"      : 0,
        "warnings"     : [],
        "findings"     : [],
        "virustotal"   : {},
        "risk_score"   : 0,
        "threat_level" : "CLEAN",
        "file_category": "",
        "real_type": "",
        "programming_language": "",
        "content_summary": "",
        "permissions": [],
        "capabilities": [],
    }

    ext = os.path.splitext(file_path)[1].lower()
    report["extension"] = ext

    try:
        file_info = detect_file_type(file_path)

        report["file_category"] = file_info.get(
            "category",
            "Unknown"
        )

        report["real_type"] = file_info.get(
            "type",
            "Unknown"
        )
    except Exception:
        report["file_category"] = "Unknown"
        report["real_type"] = "Unknown"

    try:
        report["programming_language"] = (
            detect_programming_language(file_path)
        )
    except Exception:
        report["programming_language"] = "Unknown"

    
    try:
        report["content_summary"] = (
            summarize_content(file_path)
        )
    except Exception:
        report["content_summary"] = (
            "Content summary unavailable."
        )

    try:
        report["permissions"] = (
            extract_permissions(file_path)
        )
    
    except Exception:
        report["permissions"] = []

    try:
        report["capabilities"] = (
            detect_capabilities(file_path)
        )
    except Exception:
        report["capabilities"] = []

    # Extension check
    if ext in SUSPICIOUS_EXTENSIONS:
        report["warnings"].append(
            f"Dangerous extension: {ext} — {SUSPICIOUS_EXTENSIONS[ext]}"
        )

    # Hashes
    report["hashes"] = calculate_hash(file_path)

    # Entropy
    entropy = calculate_entropy(file_path)
    report["entropy"] = round(entropy, 2)
    if entropy > 7:
        report["warnings"].append(
            f"High entropy ({entropy:.2f}/8.00) detected. This may indicate that the file is compressed, encrypted, packed, or intentionally obfuscated."
        )
    elif entropy > 6:

        report["warnings"].append(
            f"Moderately high entropy ({entropy:.2f}/8.00)."
        )

    # Magic bytes — NAYA
    magic_type     = check_magic_bytes(file_path)
    magic_mismatch = check_extension_mismatch(file_path, magic_type)
    report["magic_type"]    = magic_type
    report["magic_mismatch"] = magic_mismatch
    if magic_mismatch:
        report["warnings"].append(
            f"⚠️ EXTENSION MISMATCH DETECTED! The file extension is '{ext}', while the detected file type is '{magic_type}'. This discrepancy may indicate file masquerading or an attempt to conceal the file's true nature."
        )

    # Content scan
    findings = scan_content(file_path)
    report["findings"] = findings
    for f in findings:
        report["warnings"].append(f"Suspicious pattern: {f['pattern']}")


    for capability in report["capabilities"]:

        if capability in [
            "Network Access",
            "Process Creation",
            "Socket Communication"
        ]:

            report["warnings"].append(
                f"Capability Detected: {capability}"
            )

        
    dangerous_permissions = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
    ]

    for permission in report["permissions"]:

        if permission in dangerous_permissions:

            report["warnings"].append(
                f"Dangerous Permission: {permission}"
            )

    # VirusTotal — NAYA
    vt = check_virustotal(report["hashes"]["sha256"])
    report["virustotal"] = vt
    if vt.get("malicious", 0) > 0:
        report["warnings"].append(
            f"VirusTotal: {vt['malicious']}/{vt['total']} security engines detected the file as malicious."
        )

    # Risk score
    score = calculate_risk_score(
        ext, entropy, findings, magic_mismatch, vt
    )

    if any(
        p in dangerous_permissions
        for p in report["permissions"]
    ):
        score += 15


    if any(
        c in [
            "Network Access",
            "Process Creation",
            "Socket Communication"
        ]
        for c in report["capabilities"]
    ):
        score += 10

    report["risk_score"] = min(score, 100)

    report["threat_level"] = get_threat_level(
        report["risk_score"]
    )

    return report

def detect_programming_language(file_path):

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read(50000)
        
        scores = {}

        for lang, patterns in LANGUAGE_PATTERNS.items():
            score = 0

            for p in patterns:
                if p in content:
                    score +=1

            scores[lang] = score

        best = max(scores, key=score.get)

        if scores[best] > 0:
            return best
        
    except Exception:
        pass

    return "Unknown"

def check_virustotal(sha256: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "reason": "API key not found. Please check your .env file."}

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        # The v3 API endpoint you used is correct
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=10,
        )

        if response.status_code == 401:
            return {"status": "error", "reason": "Invalid VirusTotal API Key."}

        if response.status_code == 429:
            return {"status": "error", "reason": "VirusTotal API quota limit exceeded."}

        if response.status_code == 404:
            return {
                "status"  : "not_found",
                "reason": "The file hash was not found in the VirusTotal database. This may indicate that the file is new or has not been previously analyzed."
            }

        if response.status_code == 200:
            data  = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "status"     : "found",
                "malicious"  : stats.get("malicious",  0),
                "suspicious" : stats.get("suspicious", 0),
                "undetected" : stats.get("undetected", 0),
                "harmless"   : stats.get("harmless",   0),
                "total"      : sum(stats.values()),
                "link"       : f"https://www.virustotal.com/gui/file/{sha256}",
            }

    except requests.exceptions.ConnectionError:
        return {"status": "error", "reason": "No Internet Connection available"}
    except Exception as e:
        return {"status": "error", "reason": str(e)}

    return {"status": "error", "reason": "Unknown error."}

def summarize_content(file_path):

    try:

        ext = os.path.splitext(file_path)[1].lower()

        if ext in [".py", ".js", ".php", ".java", "c", ".cpp"]:

            with open(file_path, "r", errors="ignore") as f:
                content = f.read(20000)

            lines = len(content.splitlines())

            return (
                f"Source code file containing"
                f"{lines} lines of code."
            )
        
        elif ext == ".txt":

            with open(file_path, "r", errors="ignore") as f:
                text = f.read(1000)

            return text[:300]
        
        elif ext == ".pdf":
            return "PDF document detected."
        
        elif ext == ".apk":
            return "Android application package."
        
        elif ext in [".jpg", ".jpeg", ".png"]:
            return "Image file."
        
    except Exception:
        pass

    return "Content summary unavailable."


def print_report(report):

    status = "SAFE ✓" if not report["warnings"] else "WARNING ⚠"

    print("\n" + "=" * 75)
    print("                    E-RAKSHAK FILE SECURITY REPORT")
    print("=" * 75)

    print(f"\nScan Time  : {report['scan_time']}")
    print(f"Status     : {status}")

    # =====================================================
    # FILE INFORMATION
    # =====================================================

    print("\n" + "-" * 75)
    print("FILE INFORMATION")
    print("-" * 75)

    print(f"File Name      : {report['filename']}")
    print(f"Path           : {report['file']}")
    print(f"Extension      : {report['extension']}")
    print(f"Size           : {report['size']:,} bytes")

    print(
        f"Category       : "
        f"{report.get('file_category', 'Unknown')}"
    )

    print(
        f"Real Type      : "
        f"{report.get('real_type', 'Unknown')}"
    )

    print(
        f"Language       : "
        f"{report.get('programming_language', 'Unknown')}"
    )

    print(
        f"Magic Type     : "
        f"{report.get('magic_type') or 'Could not detect'}"
    )

    if report.get("magic_mismatch"):
        print("\n⚠️ EXTENSION MISMATCH DETECTED!")

    # =====================================================
    # HASHES
    # =====================================================

    print("\n" + "-" * 75)
    print("HASHES")
    print("-" * 75)

    hashes = report.get("hashes", {})

    print(f"MD5      : {hashes.get('md5', 'N/A')}")
    print(f"SHA1     : {hashes.get('sha1', 'N/A')}")
    print(f"SHA256   : {hashes.get('sha256', 'N/A')}")

    # =====================================================
    # CONTENT SUMMARY
    # =====================================================

    print("\n" + "-" * 75)
    print("CONTENT SUMMARY")
    print("-" * 75)

    summary = report.get(
        "content_summary",
        "No summary available."
    )

    print(summary)

    # =====================================================
    # PERMISSIONS
    # =====================================================

    permissions = report.get("permissions", [])

    print("\n" + "-" * 75)
    print("PERMISSIONS")
    print("-" * 75)

    if permissions:

        for permission in permissions:
            print(f"✓ {permission}")

    else:
        print("No permissions detected.")

    # =====================================================
    # CAPABILITIES
    # =====================================================

    capabilities = report.get("capabilities", [])

    print("\n" + "-" * 75)
    print("CAPABILITIES")
    print("-" * 75)

    if capabilities:

        for capability in capabilities:
            print(f"✓ {capability}")

    else:
        print("No capabilities detected.")

    # =====================================================
    # SECURITY ANALYSIS
    # =====================================================

    print("\n" + "-" * 75)
    print("SECURITY ANALYSIS")
    print("-" * 75)

    print(
        f"Entropy        : "
        f"{report['entropy']:.2f} / 8.00"
    )

    print(
        f"Threat Level   : "
        f"{report['threat_level']}"
    )

    # =====================================================
    # DETECTED PATTERNS
    # =====================================================

    findings = report.get("findings", [])

    print("\n" + "-" * 75)
    print("DETECTED PATTERNS")
    print("-" * 75)

    if findings:

        for finding in findings:

            print(
                f"\n⚠ Pattern : "
                f"{finding['pattern']}"
            )

            print(
                f"  Reason  : "
                f"{finding['reason']}"
            )

    else:
        print("No suspicious patterns detected.")

    # =====================================================
    # VIRUSTOTAL
    # =====================================================

    print("\n" + "-" * 75)
    print("VIRUSTOTAL ANALYSIS")
    print("-" * 75)

    vt = report.get("virustotal", {})

    if vt.get("status") == "found":

        print(
            f"Malicious      : "
            f"{vt['malicious']}"
        )

        print(
            f"Suspicious     : "
            f"{vt['suspicious']}"
        )

        print(
            f"Clean          : "
            f"{vt['undetected']}"
        )

        print(
            f"Total Engines  : "
            f"{vt['total']}"
        )

        print(
            f"Link           : "
            f"{vt['link']}"
        )

    elif vt.get("status") == "not_found":

        print(
    "The file was not found in the VirusTotal database."
     )

    elif vt.get("status") == "skipped":

        print(
            "VirusTotal API key not provided."
        )

    elif vt.get("status") == "error":

        print(
            f"Error : {vt.get('reason')}"
        )

    # =====================================================
    # WARNINGS
    # =====================================================

    print("\n" + "-" * 75)
    print("WARNINGS")
    print("-" * 75)

    warnings = report.get("warnings", [])

    if warnings:

        for warning in warnings:
            print(f"⚠ {warning}")

    else:
        print("No warnings generated.")

    # =====================================================
    # RISK ASSESSMENT
    # =====================================================

    print("\n" + "-" * 75)
    print("RISK ASSESSMENT")
    print("-" * 75)

    print(
        f"Risk Score     : "
        f"{report['risk_score']} / 100"
    )

    print(
        f"Threat Level   : "
        f"{report['threat_level']}"
    )

    # =====================================================
    # RECOMMENDATION
    # =====================================================

    print("\n" + "-" * 75)
    print("RECOMMENDATION")
    print("-" * 75)

    recommendations = {
    "CLEAN":
        "✅ No significant security concerns detected. The file appears safe, but always verify the source before use.",

    "LOW":
        "🟡 Low risk detected. The file appears mostly safe, but it is recommended to verify its origin and purpose before opening or executing it.",

    "MEDIUM":
        "🟠 Medium risk detected. Review the file carefully and ensure it comes from a trusted source before executing it.",

    "HIGH":
        "🔴 High risk detected. Execute this file only in a controlled environment such as a sandbox or virtual machine.",

    "CRITICAL":
        "🚨 Critical risk detected. Do NOT execute this file. Immediate malware analysis and further investigation are strongly recommended."
}

    print(
        recommendations.get(
            report["threat_level"],
            "Unknown risk level."
        )
    )

    print("\n" + "=" * 75)
    print("                         SCAN COMPLETED")
    print("=" * 75)
    
def extract_permissions(file_path):

    permissions = []
    try:
        if file_path.lower().endswith(".apk"):

            with zipfile.ZipFile(file_path, "r") as z:
                for name in z.namelist():
                    lower = name.lower()

                    if "internet" in lower:
                        permissions.append(
                            "android.permission.INTERNET"
                        )
                    
                    if "camera" in lower:
                        permissions.append(
                            "android.permission.CAMERA"
                        )
    except Exception:
        pass 

    return permissions

def detect_capabilities(file_path):

    capabilities = []

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()

        if "requests" in content:
            capabilities.append("Network Access")

        if "socket" in content:
            capabilities.append("Socket Communication")

        if "open(" in content:
            capabilities.append("File Access")
        
        if "sqlite3" in content:
            capabilities.append("Database Acess")
        
        if "subprocess" in content:
            capabilities.append("Process Creation")
    
    except Exception:
        pass

    return capabilities

def save_report_json(report, output_dir="reports"):
   
    os.makedirs(output_dir, exist_ok=True)

    filename = f"report_{report['filename']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path     = os.path.join(output_dir, filename)

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Report saved: {path}")
    return path

# ====================== REPORT GENERATOR (String Return) ======================

def generate_report_text(report):
    """Exact Console Jaisa Content - Professional & Large"""
    lines = []

    status = "SAFE ✓" if not report.get("warnings") else "WARNING ⚠"

    lines.append("\n" + "=" * 75)
    lines.append("                    E-RAKSHAK FILE SECURITY REPORT")
    lines.append("=" * 75)

    lines.append(f"\nScan Time  : {report['scan_time']}")
    lines.append(f"Status     : {status}")

    # FILE INFORMATION
    lines.append("\n" + "-" * 75)
    lines.append("FILE INFORMATION")
    lines.append("-" * 75)
    lines.append(f"File Name      : {report['filename']}")
    lines.append(f"Path           : {report.get('file', 'Uploaded File')}")
    lines.append(f"Extension      : {report['extension']}")
    lines.append(f"Size           : {report['size']:,} bytes")
    lines.append(f"Category       : {report.get('file_category', 'Unknown')}")
    lines.append(f"Real Type      : {report.get('real_type', 'Unknown')}")
    lines.append(f"Language       : {report.get('programming_language', 'Unknown')}")
    lines.append(f"Magic Type     : {report.get('magic_type') or 'Could not detect'}")

    if report.get("magic_mismatch"):
        lines.append("\n⚠️ EXTENSION MISMATCH DETECTED!")

    # HASHES
    lines.append("\n" + "-" * 75)
    lines.append("HASHES")
    lines.append("-" * 75)
    h = report.get("hashes", {})
    lines.append(f"MD5      : {h.get('md5', 'N/A')}")
    lines.append(f"SHA1     : {h.get('sha1', 'N/A')}")
    lines.append(f"SHA256   : {h.get('sha256', 'N/A')}")

    # CONTENT SUMMARY
    lines.append("\n" + "-" * 75)
    lines.append("CONTENT SUMMARY")
    lines.append("-" * 75)
    lines.append(report.get("content_summary", "No summary available."))

    # PERMISSIONS
    lines.append("\n" + "-" * 75)
    lines.append("PERMISSIONS")
    lines.append("-" * 75)
    if report.get("permissions"):
        for p in report["permissions"]:
            lines.append(f"✓ {p}")
    else:
        lines.append("No permissions detected.")

    # CAPABILITIES
    lines.append("\n" + "-" * 75)
    lines.append("CAPABILITIES")
    lines.append("-" * 75)
    if report.get("capabilities"):
        for c in report["capabilities"]:
            lines.append(f"✓ {c}")
    else:
        lines.append("No capabilities detected.")

    # SECURITY ANALYSIS
    lines.append("\n" + "-" * 75)
    lines.append("SECURITY ANALYSIS")
    lines.append("-" * 75)
    lines.append(f"Entropy        : {report['entropy']:.2f} / 8.00")
    lines.append(f"Threat Level   : {report['threat_level']}")

    # DETECTED PATTERNS
    lines.append("\n" + "-" * 75)
    lines.append("DETECTED PATTERNS")
    lines.append("-" * 75)
    findings = report.get("findings", [])
    if findings:
        for f in findings:
            lines.append(f"⚠ Pattern : {f['pattern']}")
            lines.append(f"  Reason  : {f['reason']}")
    else:
        lines.append("No suspicious patterns detected.")

    # VIRUSTOTAL
    lines.append("\n" + "-" * 75)
    lines.append("VIRUSTOTAL ANALYSIS")
    lines.append("-" * 75)
    vt = report.get("virustotal", {})
    if vt.get("status") == "found":
        lines.append(f"Malicious      : {vt.get('malicious', 0)}")
        lines.append(f"Suspicious     : {vt.get('suspicious', 0)}")
        lines.append(f"Clean          : {vt.get('undetected', 0)}")
        lines.append(f"Total Engines  : {vt.get('total', 0)}")
        lines.append(f"Link           : {vt.get('link')}")
    elif vt.get("status") == "not_found":
        lines.append("The file was not found in the VirusTotal database.")
    else:
        lines.append("VirusTotal API key not provided.")

    # WARNINGS
    lines.append("\n" + "-" * 75)
    lines.append("WARNINGS")
    lines.append("-" * 75)
    warnings = report.get("warnings", [])
    if warnings:
        for w in warnings:
            lines.append(f"⚠ {w}")
    else:
        lines.append("No warnings generated.")

    # RISK ASSESSMENT
    lines.append("\n" + "-" * 75)
    lines.append("RISK ASSESSMENT")
    lines.append("-" * 75)
    lines.append(f"Risk Score     : {report['risk_score']} / 100")
    lines.append(f"Threat Level   : {report['threat_level']}")

    # RECOMMENDATION
    lines.append("\n" + "-" * 75)
    lines.append("RECOMMENDATION")
    lines.append("-" * 75)
    recommendations = {
        "CLEAN": "✅ No significant security concerns detected. The file appears safe, but always verify the source before use.",
        "LOW": "🟡 Low risk detected. The file appears mostly safe, but it is recommended to verify its origin and purpose before opening or executing it.",
        "MEDIUM": "🟠 Medium risk detected. Review the file carefully and ensure it comes from a trusted source before executing it.",
        "HIGH": "🔴 High risk detected. Execute this file only in a controlled environment such as a sandbox or virtual machine.",
        "CRITICAL": "🚨 Critical risk detected. Do NOT execute this file. Immediate malware analysis and further investigation are strongly recommended."
    }
    lines.append(recommendations.get(report["threat_level"], "Unknown risk level."))

    lines.append("\n" + "=" * 75)
    lines.append("                         SCAN COMPLETED")
    lines.append("=" * 75)

    return "\n".join(lines)

if __name__ == "__main__":
    target = input("Enter file path to scan: ").strip()
    
    # Quotes hata do — Windows drag-drop se aate hain
    target = target.strip('"').strip("'")
    
    # Path normalize karo
    target = os.path.normpath(target)
    
    print(f"\nDEBUG - Recived Path: {repr(target)}")
    print(f"DEBUG - File Exists: {os.path.exists(target)}")
    
    if not os.path.exists(target):
        print(f"\n❌ File not found: {target}")
        input("Press Enter to exit...")   # window band na ho turant
        exit()

    try:
        print("\n🔍 Scanning...")
        report = scan_file(target)
        print_report(report)

        save_choice = input("\nSave Report in Json? (y/n): ").strip().lower()
        if save_choice == 'y':
            save_report_json(report)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()          
        input("Press Enter to exit...")