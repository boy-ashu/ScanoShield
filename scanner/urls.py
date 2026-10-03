from django.urls import path
from . import views

urlpatterns = [
    # Dashboard & Pages
    path('', views.index_view, name='home'),
    path('pro-home/', views.pro_home_page, name='pro_home_page'),
    path('file-scanner/', views.file_scanner_page, name='file_scanner_page'),
    path('password/', views.password_page, name='password_check'),
    path('fraud-detector/', views.fraud_scanner_page, name='fraud_scanner_page'),
    path('cyber-news/', views.cyber_news_page, name='cyber_news_page'),
    path('locator/', views.locator_page, name='locator_page'),
    path('login/', views.login_page, name='login_page'),
    path('wifi-scanner/', views.wifi_scanner_page, name='wifi_scanner_page'),
    path('admin-logs/', views.admin_approval_panel, name='admin_logs'),
    path('admin-approval/', views.admin_approval_panel, name='admin_approval_panel'),

    # API Endpoints
    path('api/scan/', views.scan_file_api, name='scan_file'),
    path('api/password-audit/', views.audit_password_api, name='password_audit_api'),
    path('api/fraud-scan/', views.fraud_scan_api, name='fraud_scan_api'),
    path('api/lookup/', views.lookup_api, name='lookup_api'),
    path('api/wifi-scan/', views.wifi_scanner_api, name='wifi_scanner_api'),
    path('api/export-wifi-csv/', views.export_wifi_report_csv, name='export_wifi_csv'),   
]