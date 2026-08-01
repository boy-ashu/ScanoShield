from django.urls import path
from . import views

urlpatterns = [
    path('', views.index_view, name='home'),
    path('api/scan/', views.scan_file_api, name='scan_file'),
]