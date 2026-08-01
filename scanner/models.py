from django.db import models
from django.contrib.auth.models import User

class SearchLog(models.Model):
    INPUT_TYPES = [
        ("ip", "IP Address"),
        ("email", "Email"),
        ("phone", "Phone Number"),
        ("domain", "Domain"),
        ("unknown", "Unknown"),
    ]

    query = models.CharField(max_length=255)
    input_type = models.CharField(max_length=10, choices=INPUT_TYPES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"[{self.input_type}] {self.query} ({self.created_at:%Y-%m-%d %H:%M})"
class UserProfile(models.Model):
    USER_ROLES = (
        ('normal', 'Normal User'),
        ('professional', 'Professional User'),
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=15, choices=USER_ROLES, default='normal')
    
    # प्रोफेशनल यूजर रजिस्ट्रेशन के लिए एडिशनल फील्ड्स
    company_name = models.CharField(max_length=150, blank=True, null=True)
    designation = models.CharField(max_length=100, blank=True, null=True)
    is_authorized = models.BooleanField(default=False)
    emp_id = models.CharField(max_length=50, blank=True, null=True, unique=True)

    phone = models.CharField(max_length=20, blank=True, null=True)
    
    registration_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"

class UserSubmissionLog(models.Model):
    """
    Model to track user submissions, capturing IP address, email, phone, and browser info.
    """
    full_name = models.CharField(max_length=150)
    email = models.EmailField()
    phone_number = models.CharField(max_length=20)
    
    # Automatically tracked metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-submitted_at']

    def __str__(self):
        return f"{self.full_name} ({self.email}) - {self.ip_address}"    