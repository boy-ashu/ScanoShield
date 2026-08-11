import os
import requests
import feedparser
from bs4 import BeautifulSoup
from datetime import datetime
import tempfile
import json
import ssl
import uuid
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages

from .models import UserProfile, UserSubmissionLog, SearchLog
from . import utils
from .decorators import future_advance_feature_required

# Modular Helpers Import
from .file_scanner import scan_file, generate_report_text
from .password_utils import ProfessionalPasswordToolkit
from .fraud_dectector import (
    scan_url,
    scan_phone,
    scan_email,
    scan_upi,
    scan_qr,
    scan_social,
    _build_result
)


def index(request):
    """Landing page with the search form."""
    recent = SearchLog.objects.all()[:10]
    return render(request, "scanner/index.html", {"recent": recent})


def search(request):
    """Handle the submitted query, detect its type, run the right lookup."""
    query = request.POST.get("query", "").strip() if request.method == "POST" else request.GET.get("query", "").strip()

    if not query:
        return render(request, "scanner/index.html", {
            "error": "Please enter a value to search.",
            "recent": SearchLog.objects.all()[:10],
        })

    input_type = utils.detect_input_type(query)

    context = {
        "query": query,
        "input_type": input_type,
    }

    if input_type == "ip":
        context["result"] = utils.lookup_ip(query)
    elif input_type == "email":
        context["result"] = utils.lookup_email(query)
    elif input_type == "phone":
        context["result"] = utils.lookup_phone(query)
    elif input_type == "domain":
        context["result"] = utils.lookup_domain(query)
    else:
        context["error"] = (
            "Could not detect a valid IP address, email, phone number, "
            "or domain in your input. Please check the format and try again."
        )

    # If it's a domain lookup and we resolved an IP, chain a geolocation lookup too
    if input_type == "domain" and context.get("result", {}).get("resolved_ip"):
        context["ip_result"] = utils.lookup_ip(context["result"]["resolved_ip"])

    SearchLog.objects.create(query=query, input_type=input_type)
    context["recent"] = SearchLog.objects.all()[:10]

    return render(request, "scanner/result.html", context)

# ========================================================
# NETWORK HELPERS
# ========================================================

def get_client_ip(request) -> str:
    """
    Extracts the user's real IP address, accounting for reverse proxies or load balancers.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def locator_page(request):
    return render(request, 'scanner/locator.html')

# ========================================================
# AUTHENTICATION & ACCESS REQUEST VIEWS
# ========================================================

def login_page(request):
    """
    Handles Analyst Login and Access Requests.
    Removed auto-redirect for already authenticated users so the form is visible.
    """
    if request.method == "POST":
        form_type = request.POST.get('form_type')

        # 1. ANALYST LOGIN
        if form_type == "login":
            u = request.POST.get('username', '').strip()
            p = request.POST.get('password', '').strip()
            
            user = authenticate(request, username=u, password=p)
            if user is not None:
                login(request, user)
                profile = getattr(user, 'userprofile', None)
                
                # Verify admin clearance after authenticating
                if user.is_staff or (profile and profile.is_authorized):
                    return redirect('pro_home_page')
                else:
                    messages.warning(request, "Access Denied: Your account is pending Admin clearance.")
                    return redirect('login_page')
            else:
                messages.error(request, "Invalid credentials. Contact system administrator or request access.")

        # 2. ACCESS REQUEST FORM SUBMISSION
        elif form_type == "register":
            full_name = request.POST.get('full_name', '').strip()
            email = request.POST.get('email', '').strip()
            phone = request.POST.get('phone', '').strip()
            company = request.POST.get('company', '').strip()
            designation = request.POST.get('designation', '').strip()

            client_ip = get_client_ip(request)

            UserSubmissionLog.objects.create(
                full_name=f"{full_name} ({company} - {designation})",
                email=email,
                phone_number=phone,
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            messages.success(request, "Access request submitted! Admin will review your details.")
            return redirect('login_page')

    return render(request, 'scanner/login.html')


@login_required(login_url='login_page')
def pro_home_page(request):
    """
    Protected Pro Console.
    Requires user to be staff OR authorized by Admin.
    """
    profile = getattr(request.user, 'userprofile', None)
    
    if request.user.is_staff or (profile and profile.is_authorized):
        return render(request, 'scanner/pro_home.html')
    
    messages.warning(request, "Access Denied: Your account is pending Admin clearance.")
    return redirect('login_page')

@staff_member_required
def admin_approval_panel(request):
    """
    Control panel for Admins to approve/reject access requests and assign Employee Credentials.
    Renders 'scanner/admin_pannal.html'.
    """
    if request.method == "POST":
        action = request.POST.get('action')
        
        # 1. Action: Approve Profile and Assign Credential (Employee ID)
        if action == 'approve':
            profile_id = request.POST.get('profile_id')
            profile = get_object_or_404(UserProfile, id=profile_id)
            
            # Generate/assign credential if missing
            if not profile.emp_id:
                profile.emp_id = f"EMP-{uuid.uuid4().hex[:6].upper()}"
            
            profile.is_authorized = True
            profile.save()
            
            # Ensure the user account itself is activated
            profile.user.is_active = True
            profile.user.save()
            
            messages.success(request, f"Approved user '{profile.user.username}'. Assigned Credential ID: {profile.emp_id}")

        # 2. Action: Reject Profile
        elif action == 'reject':
            profile_id = request.POST.get('profile_id')
            profile = get_object_or_404(UserProfile, id=profile_id)
            profile.is_authorized = False
            profile.role = 'normal'
            profile.save()
            
            messages.warning(request, f"Rejected access request for '{profile.user.username}'.")

        # 3. Action: Clear Submission Log entry
        elif action == 'delete_log':
            log_id = request.POST.get('log_id')
            UserSubmissionLog.objects.filter(id=log_id).delete()
            messages.info(request, "Submission log removed.")

        return redirect('admin_logs')

    # Data queries
    pending_profiles = UserProfile.objects.filter(is_authorized=False, role='professional')
    approved_profiles = UserProfile.objects.filter(is_authorized=True)
    access_logs = UserSubmissionLog.objects.all().order_by('-created_at')[:20]

    context = {
        'pending_profiles': pending_profiles,
        'approved_profiles': approved_profiles,
        'access_logs': access_logs,
    }
    
    # Renders your updated template name: admin_pannal.html
    return render(request, 'scanner/admin_pannal.html', context)

# ========================================================
# 1. CYBER NEWS FETCHING LOGIC
# ========================================================

def fetch_cyber_news():
    feeds = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/"
    ]
    parsed_news = []
    
    # SSL verification bypass
    if not hasattr(ssl, '_create_unverified_context'):
        ssl._create_default_https_context = ssl._create_unverified_context
    else:
        ssl._create_default_https_context = ssl._create_unverified_context

    for url in feeds:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            feed = feedparser.parse(response.content)
            
            for entry in feed.entries[:6]:  # Top 6 entries
                summary_html = entry.get('summary', '') or entry.get('description', '')
                soup = BeautifulSoup(summary_html, 'html.parser')
                
                # Image extraction
                img_tag = soup.find('img')
                image_url = img_tag['src'] if img_tag else None
                
                if not image_url:
                    image_url = "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=500&auto=format&fit=crop"

                # Clean text summary
                clean_text = soup.get_text()[:150] + "..." if len(soup.get_text()) > 150 else soup.get_text()
                
                # Date formatting
                try:
                    date_parsed = entry.published_parsed
                    published_formatted = datetime(*date_parsed[:6]).strftime('%d %b %Y, %H:%M')
                except:
                    published_formatted = entry.get('published', '')

                parsed_news.append({
                    'title': entry.title,
                    'link': entry.link,
                    'summary': clean_text,
                    'image': image_url,
                    'source': 'The Hacker News' if 'hackersnews' in url else 'BleepingComputer',
                    'published': published_formatted
                })
        except Exception as e:
            print(f"Error fetching RSS from {url}: {str(e)}")
            
    return parsed_news

# Add this endpoint in views.py

@csrf_exempt
def lookup_api(request):
    """
    API Endpoint for Geolocation and Metadata Analysis.
    Supports POST with JSON or Form Data containing 'query' and optional 'type'.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            query = data.get('query', '').strip()
            forced_type = data.get('type', None)
        else:
            query = request.POST.get('query', '').strip()
            forced_type = request.POST.get('type', None)

        if not query:
            return JsonResponse({"error": "Empty search query provided."}, status=400)

        input_type = forced_type if forced_type else utils.detect_input_type(query)
        result = {}

        if input_type == "ip":
            result = utils.lookup_ip(query)
        elif input_type == "phone":
            result = utils.lookup_phone(query)
        elif input_type == "email":
            result = utils.lookup_email(query)
        elif input_type == "domain":
            result = utils.lookup_domain(query)
            if "resolved_ip" in result:
                result["ip_data"] = utils.lookup_ip(result["resolved_ip"])
        else:
            return JsonResponse({"error": "Unsupported or unrecognized input format."}, status=400)

        # Log search query
        SearchLog.objects.create(query=query, input_type=input_type)

        return JsonResponse(result)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
# ========================================================
# 2. PAGE RENDERING VIEWS & DATA CAPTURE
# ========================================================

def index_view(request):
    return render(request, 'scanner/index.html')

def file_scanner_page(request):
    return render(request, 'scanner/file_scan.html')

def password_page(request):
    return render(request, 'scanner/pass.html')

def fraud_scanner_page(request):
    return render(request, 'scanner/fraud_scan.html')

def cyber_news_page(request):
    news_data = fetch_cyber_news()
    context = {
        'news_feed': news_data,
        'last_updated': datetime.now().strftime('%H:%M:%S')
    }
    return render(request, 'scanner/cyber_news.html', context)



# ========================================================
# 3. API ENDPOINTS (SCANNERS & AUDITS)
# ========================================================

@csrf_exempt
def fraud_scan_api(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
        
    choice = request.POST.get('choice', '8').strip()
    value = request.POST.get('value', '').strip()
    
    SCAN_MAPPING = {
        "1": scan_url,
        "2": scan_phone,
        "3": scan_email,
        "4": scan_upi,
        "5": scan_qr,
        "6": scan_social,
    }

    if choice == "8":
        from .fraud_dectector import detect_input_type
        detected = detect_input_type(value)
        
        if detected == "url": choice = "1"
        elif detected == "phone": choice = "2"
        elif detected == "email": choice = "3"
        elif detected == "upi": choice = "4"
        else: choice = "1" 

    if choice in ["5", "7"] or request.FILES.get('file'):
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return JsonResponse(_build_result(40, ["Scanning failed: No file uploaded."]), status=400)
        
        suffix = os.path.splitext(uploaded_file.name)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            for chunk in uploaded_file.chunks():
                tmp.write(chunk)
            tmp_path = tmp.name
        
        try:
            if choice == "5":
                result = scan_qr(tmp_path)
            else:
                try:
                    from .fraud_dectector import scan_photo
                    result = scan_photo(tmp_path)
                except ImportError:
                    result = _build_result(0, ["Image analysis simulation"], [{"title": "Photo Scan", "items": ["Successfully received file via API."], "severity": "ok"}])
            
            return JsonResponse(result)
            
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    scanner_func = SCAN_MAPPING.get(choice)
    if not scanner_func:
        return JsonResponse(_build_result(40, ["Invalid analysis profile code selected."]), status=400)
        
    result = scanner_func(value)
    return JsonResponse(result)


@csrf_exempt
def scan_file_api(request):
    if request.method != "POST" or not request.FILES.get("file"):
        return JsonResponse({"error": "No file uploaded"}, status=400)

    uploaded_file = request.FILES['file']
    original_name = uploaded_file.name

    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(original_name)[1]) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    try:
        report = scan_file(tmp_path, orginal_filename=original_name)
        full_report_text = generate_report_text(report)

        return JsonResponse({
            **report,
            "full_report": full_report_text
        })
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@csrf_exempt 
def audit_password_api(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            pwd = data.get("password", "")
            
            if not pwd:
                return JsonResponse({"error": "Empty password input"}, status=400)
            
            strength = ProfessionalPasswordToolkit.check_strength(pwd)
            leak = ProfessionalPasswordToolkit.check_leak(pwd)
            entropy = ProfessionalPasswordToolkit.calculate_entropy(pwd)
            
            return JsonResponse({
                "strength": strength,
                "leak": leak,
                "entropy": entropy
            })
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
            
    return JsonResponse({"error": "Invalid request method"}, status=405)


# ========================================================
# 4. PROFESSIONAL PORTAL & ADMIN APPROVAL MANAGEMENT
# ========================================================

@login_required
def register_professional(request):
    """एक ही पोर्टल से यूजर रजिस्ट्रेशन और पेंडिंग/अप्रूव्ड स्टेटस हैंडल करना"""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == "POST":
        profile.company_name = request.POST.get('company_name')
        profile.designation = request.POST.get('designation')
        profile.phone = request.POST.get('phone')
        
        user_email = request.POST.get('email')
        if user_email:
            request.user.email = user_email
            request.user.save()
            
        profile.role = 'professional'
        profile.is_authorized = False  # एडमिन अप्रूवल पेंडिंग रहेगा
        profile.save()
        
        messages.success(request, "आपकी रिक्वेस्ट दर्ज हो गई है। एडमिन सत्यापन की प्रतीक्षा करें।")
        return redirect('register_professional')
        
    return render(request, 'scanner/professional_portal.html', {'profile': profile})


@staff_member_required
def admin_approval_panel(request):
    """केवल एडमिन/स्टाफ के लिए: प्रोफेशन्स को Approve या Reject करने का कंट्रोल सेंटर"""
    pending_profiles = UserProfile.objects.filter(role='professional', is_authorized=False)
    approved_profiles = UserProfile.objects.filter(role='professional', is_authorized=True)

    if request.method == "POST":
        action = request.POST.get('action')
        profile_id = request.POST.get('profile_id')
        profile = get_object_or_404(UserProfile, id=profile_id)

        if action == 'approve':
            if not profile.emp_id:
                profile.emp_id = f"EMP-{uuid.uuid4().hex[:6].upper()}"
            profile.is_authorized = True
            profile.save()
            messages.success(request, f"{profile.user.username} को Approve कर दिया गया है (Emp ID: {profile.emp_id})।")

        elif action == 'reject':
            profile.role = 'normal'  # Reset role back to normal
            profile.save()
            messages.warning(request, f"{profile.user.username} की रिक्वेस्ट Reject कर दी गई है।")

        return redirect('admin_approval_panel')

    context = {
        'pending_profiles': pending_profiles,
        'approved_profiles': approved_profiles,
    }
    return render(request, 'scanner/admin_approval_panel.html', context)