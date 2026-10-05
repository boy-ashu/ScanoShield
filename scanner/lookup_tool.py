import tkinter as tk
from tkinter import ttk, messagebox
import urllib.request
import json
import re
import socket
import webbrowser
import phonenumbers
from phonenumbers import geocoder, carrier

# -------------------------------------------------------------------
# Lookup Functions
# -------------------------------------------------------------------

def analyze_ip(ip_str):
    """Queries a public API for IP geolocation details."""
    ip_str = ip_str.strip()
    url = f"https://ipapi.co/{ip_str}/json/" if ip_str else "https://ipapi.co/json/"
    
    req = urllib.request.Request(url, headers={'User-Agent': 'Python-Locator-App/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            
            if "error" in data:
                return f"IP Lookup Error: {data.get('reason', 'Invalid IP or rate limit reached')}", None, None
            
            lat = data.get('latitude')
            lon = data.get('longitude')

            output = [
                "=== IP GEOLOCATION (APPROXIMATE) ===",
                f"IP Address  : {data.get('ip')}",
                f"City        : {data.get('city')}",
                f"Region      : {data.get('region')}",
                f"Country     : {data.get('country_name')}",
                f"Postal Code : {data.get('postal')}",
                f"ISP / Org   : {data.get('org')}",
                f"Coordinates : {lat}, {lon}",
                "\n* Note: IP locations represent internet routing points, not exact physical addresses."
            ]
            return "\n".join(output), lat, lon
    except Exception as e:
        return f"Network or API Error: {str(e)}", None, None

def analyze_phone(phone_str):
    """Parses phone number metadata (Country and Carrier)."""
    try:
        parsed_num = phonenumbers.parse(phone_str.strip())
        if not phonenumbers.is_valid_number(parsed_num):
            return "Invalid phone number format. Please include international country code (e.g., +14155552671)."
        
        country_location = geocoder.description_for_number(parsed_num, "en")
        service_provider = carrier.name_for_number(parsed_num, "en")
        
        output = [
            "=== PHONE NUMBER ANALYSIS ===",
            f"Formatted Number : {phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}",
            f"Country / Region : {country_location or 'Unknown'}",
            f"Carrier / Provider: {service_provider or 'Unknown or Ported'}",
            "\n* Note: Live GPS location requires device-level permissions or carrier access."
        ]
        return "\n".join(output)
    except Exception as e:
        return f"Phone Parsing Error: {str(e)}\nMake sure to include country code (e.g., +1...)"

def analyze_email(email_str):
    """Validates email format and checks domain MX (Mail Exchange) records."""
    email_str = email_str.strip()
    pattern = r"^[\w\.-]+@([\w\.-]+\.\w+)$"
    match = re.match(pattern, email_str)
    
    if not match:
        return "Invalid email address format."
    
    domain = match.group(1)
    
    output = [
        "=== EMAIL DOMAIN ANALYSIS ===",
        f"Email Address : {email_str}",
        f"Domain        : {domain}"
    ]
    
    try:
        socket.gethostbyname(domain)
        output.append("Domain Status : Active (Resolves to IP)")
    except socket.gaierror:
        output.append("Domain Status : Unreachable or invalid domain")
        
    output.append("\n* Note: Email addresses do not broadcast physical location data.")
    return "\n".join(output)

# -------------------------------------------------------------------
# GUI Implementation
# -------------------------------------------------------------------

class LocatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Information & Geolocation Lookup")
        self.root.geometry("600x600")
        
        self.current_lat = None
        self.current_lon = None

        # Main Container Frame
        frame = ttk.Frame(root, padding="15")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Input Section
        ttk.Label(frame, text="Select Data Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.type_var = tk.StringVar(value="IP Address")
        type_dropdown = ttk.Combobox(frame, textvariable=self.type_var, state="readonly", 
                                     values=["IP Address", "Phone Number", "Email Address"])
        type_dropdown.grid(row=0, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(frame, text="Enter Value:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_val = ttk.Entry(frame, width=40)
        self.entry_val.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        # Action Buttons
        search_btn = ttk.Button(frame, text="Execute Lookup", command=self.perform_lookup)
        search_btn.grid(row=2, column=0, columnspan=2, pady=8, sticky=tk.EW)

        self.map_btn = ttk.Button(frame, text="📍 Open Location in Map", command=self.open_map_browser, state=tk.DISABLED)
        self.map_btn.grid(row=3, column=0, columnspan=2, pady=2, sticky=tk.EW)

        # Output Box
        ttk.Label(frame, text="Results:").grid(row=4, column=0, sticky=tk.W, pady=(10, 5))
        self.result_text = tk.Text(frame, height=16, width=65, wrap=tk.WORD)
        self.result_text.grid(row=5, column=0, columnspan=2, sticky=tk.NSEW, pady=5)
        
        # Grid weight configurations
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)

    def perform_lookup(self):
        val = self.entry_val.get().strip()
        category = self.type_var.get()
        
        # Reset state
        self.current_lat = None
        self.current_lon = None
        self.map_btn.config(state=tk.DISABLED)
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Processing query...\n")
        self.root.update()
        
        if category == "IP Address":
            result, lat, lon = analyze_ip(val)
            if lat and lon:
                self.current_lat = lat
                self.current_lon = lon
                self.map_btn.config(state=tk.NORMAL)
        elif category == "Phone Number":
            if not val:
                result = "Please enter a phone number including country code (e.g., +14155552671)."
            else:
                result = analyze_phone(val)
        elif category == "Email Address":
            if not val:
                result = "Please enter an email address."
            else:
                result = analyze_email(val)
        else:
            result = "Unknown category selected."
            
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)

    def open_map_browser(self):
        """Opens coordinates directly in default browser on OpenStreetMap/Google Maps."""
        if self.current_lat and self.current_lon:
            map_url = f"https://www.openstreetmap.org/?mlat={self.current_lat}&mlon={self.current_lon}#map=12/{self.current_lat}/{self.current_lon}"
            webbrowser.open(map_url)
        else:
            messagebox.showwarning("Map Error", "No valid geographic coordinates available for this lookup.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LocatorApp(root)
    root.mainloop()