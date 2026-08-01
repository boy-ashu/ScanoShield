from django.contrib import admin
from .models import UserProfile, UserSubmissionLog


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'company_name', 'designation', 'is_authorized', 'emp_id', 'phone')
    list_filter = ('role', 'is_authorized')
    search_fields = ('user__username', 'user__email', 'company_name', 'emp_id', 'phone')
    ordering = ('-registration_date',)


@admin.register(UserSubmissionLog)
class UserSubmissionLogAdmin(admin.ModelAdmin):
    # Display tracked information clearly in the admin list view
    list_display = ('full_name', 'email', 'phone_number', 'ip_address', 'submitted_at')
    
    # Enable quick search across user details and IP address
    search_fields = ('full_name', 'email', 'phone_number', 'ip_address')
    
    # Filter submissions by date
    list_filter = ('submitted_at',)
    
    # Keep captured metadata read-only to prevent manual alteration
    readonly_fields = ('ip_address', 'user_agent', 'submitted_at')
    
    ordering = ('-submitted_at',)