"""
Audit logging models with hash-chaining for append-only integrity.
Implements WORM (Write Once, Read Many) principles for audit trails.
"""
import hashlib
import logging
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Index, Constraints, Q
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class WORMAuditLog(models.Model):
    """
    Write-Once-Read-Many (WORM) audit log with hash-chaining.
    Each log entry is immutable; deletion/modification is prevented at DB level.
    Hash chaining provides integrity verification.
    """
    
    ACTION_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('view', 'Document View'),
        ('download', 'Document Download'),
        ('upload', 'Document Upload'),
        ('modify', 'Document Modify'),
        ('delete', 'Document Delete'),
        ('share', 'Document Share'),
        ('access_denied', 'Access Denied'),
        ('mfa_verify', 'MFA Verification'),
        ('key_rotation', 'Key Rotation'),
    ]
    
    # Immutable core fields
    entry_id = models.BigAutoField(primary_key=True, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.PROTECT,  # Prevent user deletion if logs exist
        null=True,
        blank=True,
        editable=False
    )
    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        editable=False
    )
    
    # Audit details
    ip_address = models.GenericIPAddressField(editable=False)
    user_agent = models.CharField(max_length=500, editable=False, blank=True)
    success = models.BooleanField(default=True, editable=False)
    details = models.TextField(editable=False, blank=True)
    
    # Document reference (if applicable)
    document_id = models.BigIntegerField(null=True, blank=True, editable=False)
    document_hash = models.CharField(
        max_length=64,
        blank=True,
        editable=False,
        help_text="SHA-256 of document at time of access"
    )
    
    # Hash chaining for integrity
    previous_entry_hash = models.CharField(
        max_length=64,
        blank=True,
        editable=False,
        help_text="Hash of previous log entry (empty for first)"
    )
    entry_hash = models.CharField(
        max_length=64,
        unique=True,
        editable=False,
        help_text="SHA-256 hash of this entry (immutable)"
    )
    
    # Metadata
    classification_level = models.IntegerField(
        null=True,
        blank=True,
        editable=False,
        choices=[
            (1, 'Public'),
            (2, 'Internal'),
            (3, 'Confidential'),
            (4, 'Secret'),
            (5, 'Top Secret'),
        ]
    )
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            Index(fields=['user', 'timestamp']),
            Index(fields=['action', 'timestamp']),
            Index(fields=['ip_address', 'timestamp']),
            Index(fields=['document_id', 'timestamp']),
        ]
        # Prevent any modifications after creation
        permissions = [
            ('view_audit_log', 'Can view audit log'),
            ('export_audit_log', 'Can export audit log'),
        ]
    
    def save(self, *args, **kwargs):
        """Override save to compute hash and prevent updates."""
        if self.pk is not None:
            # Entry already exists; prevent modification
            raise ValidationError("Audit log entries are immutable (WORM principle)")
        
        # Compute hash on creation
        self.entry_hash = self._compute_hash()
        
        # Get previous entry's hash (for chaining)
        last_entry = WORMAuditLog.objects.order_by('-entry_id').first()
        if last_entry:
            self.previous_entry_hash = last_entry.entry_hash
        
        super().save(*args, **kwargs)
        logger.info(f"Audit log entry created: {self.entry_id} ({self.action} by {self.user})")
    
    def delete(self, *args, **kwargs):
        """Prevent deletion (WORM principle)."""
        raise ValidationError("Audit log entries cannot be deleted (WORM principle)")
    
    def _compute_hash(self):
        """
        Compute SHA-256 hash of log entry.
        Hash includes: timestamp, user, action, details, document info.
        Excludes: entry_id (not yet assigned), entry_hash (recursive).
        """
        data_to_hash = (
            f"{self.timestamp}|"
            f"{self.user_id}|"
            f"{self.action}|"
            f"{self.ip_address}|"
            f"{self.user_agent}|"
            f"{self.success}|"
            f"{self.details}|"
            f"{self.document_id}|"
            f"{self.document_hash}|"
            f"{self.previous_entry_hash}"
        )
        
        return hashlib.sha256(data_to_hash.encode()).hexdigest()
    
    def verify_integrity(self, previous_entry=None):
        """
        Verify integrity of this log entry.
        Returns: {'valid': bool, 'reason': str}
        """
        # Recompute hash and verify
        computed_hash = self._compute_hash()
        if computed_hash != self.entry_hash:
            return {
                'valid': False,
                'reason': f'Hash mismatch: expected {computed_hash}, got {self.entry_hash}'
            }
        
        # Verify chain linkage
        if previous_entry:
            if self.previous_entry_hash != previous_entry.entry_hash:
                return {
                    'valid': False,
                    'reason': f'Hash chain broken: entry {self.entry_id} does not link to {previous_entry.entry_id}'
                }
        
        return {'valid': True, 'reason': 'OK'}
    
    @staticmethod
    def verify_log_integrity():
        """
        Verify entire audit log chain from first to last entry.
        Returns: {'valid': bool, 'broken_at_entry': int or None, 'errors': list}
        """
        all_entries = WORMAuditLog.objects.order_by('entry_id')
        errors = []
        
        previous = None
        for entry in all_entries:
            result = entry.verify_integrity(previous)
            if not result['valid']:
                errors.append({'entry_id': entry.entry_id, 'error': result['reason']})
            previous = entry
        
        return {
            'valid': len(errors) == 0,
            'broken_at_entry': errors[0]['entry_id'] if errors else None,
            'errors': errors
        }
    
    def __str__(self):
        return f"{self.entry_id}: {self.user} - {self.action} @ {self.timestamp}"


class RestrictedAuditAccess(models.Model):
    """
    Model tracking and restricting who can access audit logs.
    Implements audit log access control (admin-only by default).
    """
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='audit_access_grants'
    )
    access_level = models.CharField(
        max_length=20,
        choices=[
            ('view', 'Can view audit logs'),
            ('export', 'Can export audit logs'),
            ('manage', 'Can manage audit log access'),
        ]
    )
    granted_at = models.DateTimeField(auto_now_add=True)
    granted_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='audit_access_grants_given'
    )
    reason = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['user', 'access_level']
        indexes = [
            Index(fields=['user', 'access_level']),
        ]
    
    def is_active(self):
        """Check if access grant is still active."""
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True
    
    def __str__(self):
        return f"{self.user} - {self.access_level}"


class AuditLogAccessTrail(models.Model):
    """
    Track who accessed the audit log and when (meta-audit).
    Provides accountability for audit log access itself.
    """
    
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    accessed_at = models.DateTimeField(auto_now_add=True)
    action = models.CharField(
        max_length=50,
        choices=[
            ('view', 'Viewed audit log'),
            ('export', 'Exported audit log'),
            ('search', 'Searched audit log'),
            ('verify_integrity', 'Verified log integrity'),
        ]
    )
    filters_applied = models.TextField(blank=True, help_text="JSON with applied filters")
    records_accessed = models.IntegerField(default=0)
    export_format = models.CharField(
        max_length=20,
        choices=[
            ('json', 'JSON'),
            ('csv', 'CSV'),
            ('pdf', 'PDF'),
        ],
        blank=True
    )
    
    class Meta:
        ordering = ['-accessed_at']
        indexes = [
            Index(fields=['user', 'accessed_at']),
        ]
    
    def __str__(self):
        return f"{self.user} - {self.action} @ {self.accessed_at}"
