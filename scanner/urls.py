from django.urls import path
from . import views

urlpatterns = [
    # Dashboard & Pages
    path('', views.index_view, name='home'),
    path('file-scanner/', views.file_scanner_page, name='file_scanner_page'),
    path('password/', views.password_page, name='password_check'),
    path('fraud-detector/', views.fraud_scanner_page, name='fraud_scanner_page'),
    path('cyber-news/', views.cyber_news_page, name='cyber_news_page'),

    # API Endpoints
    path('api/scan/', views.scan_file_api, name='scan_file'),
    path('api/password-audit/', views.audit_password_api, name='password_audit_api'),
    path('api/fraud-scan/', views.fraud_scan_api, name='fraud_scan_api'),
    path('dashboard/', views.cyber_dashboard, name='cyber_dashboard'),
    path('capture/', views.capture_user_info, name='capture_info'),
    
   
]