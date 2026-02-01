"""
Documents Models - Core data structures
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
import hashlib

class UserProfile(models.Model):
    """Extended user profile with security clearance"""
    CLEARANCE_LEVELS = [
        (1, 'Public'),
        (2, 'Interne'),
        (3, 'Confidentiel'),
        (4, 'Secret'),
        (5, 'Top Secret'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    clearance_level = models.IntegerField(choices=CLEARANCE_LEVELS, default=1)
    department = models.CharField(max_length=100, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    
    def is_account_locked(self):
        if self.account_locked_until and self.account_locked_until > timezone.now():
            return True
        return False
    
    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save()
    
    def increment_failed_attempts(self):
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        
        if self.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            self.account_locked_until = timezone.now() + timezone.timedelta(
                seconds=settings.LOGIN_ATTEMPT_TIMEOUT
            )
        self.save()
    
    def __str__(self):
        return f"{self.user.username} - Level {self.clearance_level}"


class Document(models.Model):
    """Secure document with encryption and access control"""
    CLASSIFICATION_LEVELS = [
        (1, 'Public'),
        (2, 'Interne'),
        (3, 'Confidentiel'),
        (4, 'Secret'),
        (5, 'Top Secret'),
    ]
    
    STATUS_CHOICES = [
        ('quarantine', 'Quarantaine'),
        ('scanning', 'Analyse en cours'),
        ('approved', 'Approuvé'),
        ('rejected', 'Rejeté'),
    ]
    
    # Metadata (encrypted)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    classification_level = models.IntegerField(choices=CLASSIFICATION_LEVELS, default=1)
    
    # File information
    original_filename = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500)
    file_size = models.BigIntegerField()
    mime_type = models.CharField(max_length=100)
    
    # Security
    file_hash = models.CharField(max_length=64, unique=True)  # SHA-256
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='quarantine')
    is_encrypted = models.BooleanField(default=False)
    
    # Tracking
    uploaded_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='uploaded_documents')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(null=True, blank=True)
    last_modified = models.DateTimeField(auto_now=True)
    
    # Access control
    allowed_users = models.ManyToManyField(User, related_name='accessible_documents', blank=True)
    allowed_departments = models.CharField(max_length=500, blank=True)
    
    class Meta:
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['file_hash']),
            models.Index(fields=['classification_level']),
            models.Index(fields=['status']),
        ]
    
    def can_access(self, user):
        """Check if user has permission to access document"""
        if not user.is_authenticated:
            return False
        
        # Check clearance level
        if user.profile.clearance_level < self.classification_level:
            return False
        
        # Check if user is uploader
        if self.uploaded_by == user:
            return True
        
        # Check explicit permissions
        if self.allowed_users.filter(id=user.id).exists():
            return True
        
        # Check department
        if user.profile.department and user.profile.department in self.allowed_departments:
            return True
        
        return False
    
    def calculate_hash(self, file_content):
        """Calculate SHA-256 hash of file content"""
        return hashlib.sha256(file_content).hexdigest()
    
    def __str__(self):
        return f"{self.title} ({self.get_classification_level_display()})"


class DocumentVersion(models.Model):
    """Track document versions for integrity"""
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='versions')
    version_number = models.IntegerField()
    file_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.PROTECT)
    change_description = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-version_number']
        unique_together = ['document', 'version_number']
    
    def __str__(self):
        return f"{self.document.title} - v{self.version_number}"


class AccessLog(models.Model):
    """Immutable audit log for all document access"""
    ACTION_CHOICES = [
        ('view', 'Consultation'),
        ('download', 'Téléchargement'),
        ('upload', 'Upload'),
        ('modify', 'Modification'),
        ('delete', 'Suppression'),
        ('share', 'Partage'),
    ]
    
    document = models.ForeignKey(Document, on_delete=models.PROTECT)
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=500)
    success = models.BooleanField(default=True)
    details = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['document', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.document.title}"