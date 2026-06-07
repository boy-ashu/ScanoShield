import os
import tempfile
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Library को import कर रहे हैं
from .file_scanner import scan_file, generate_report_text

def index_view(request):
    return render(request, 'scanner/file_scan.html')

@csrf_exempt
def scan_file_api(request):
    if request.method != "POST" or not request.FILES.get("file"):
        return JsonResponse({"error": "No file uploaded"}, status=400)

    uploaded_file = request.FILES['file']
    original_name = uploaded_file.name

    # Temporary file for scanning
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
        # Cleanup
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)