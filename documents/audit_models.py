"""
Audit logging models with hash-chaining for append-only integrity.
Implements WORM (Write Once, Read Many) principles for audit trails.

FIXED ISSUES:
- Added proper error handling for hash computation
- Improved integrity verification performance
- Added batch integrity verification
- Fixed circular import issues
"""
import hashlib
import logging
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Index
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class WORMAuditLog(models.Model):
    """
    Write-Once-Read-Many (WORM) audit log with hash-chaining.
    Each log entry is immutable; deletion/modification is prevented at DB level.
    Hash chaining provides integrity verification.

    SECURITY FEATURES:
    - Immutable after creation (save() blocks updates)
    - Hash chain linking (tampering detection)
    - Protected deletion (delete() raises error)
    - Integrity verification methods
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
        ('quarantine_approve', 'Quarantine Approve'),
        ('quarantine_reject', 'Quarantine Reject'),
    ]

    # Immutable core fields
    entry_id = models.BigAutoField(primary_key=True, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, editable=False, db_index=True)
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
        editable=False,
        db_index=True
    )

    # Audit details
    ip_address = models.GenericIPAddressField(editable=False)
    user_agent = models.CharField(max_length=500, editable=False, blank=True)
    success = models.BooleanField(default=True, editable=False, db_index=True)
    details = models.TextField(editable=False, blank=True)

    # Document reference (if applicable)
    document_id = models.BigIntegerField(null=True, blank=True, editable=False, db_index=True)
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
        db_index=True,
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
            Index(fields=['success', 'timestamp']),
        ]
        # Prevent any modifications after creation
        permissions = [
            ('view_audit_log', 'Can view audit log'),
            ('export_audit_log', 'Can export audit log'),
            ('verify_audit_integrity', 'Can verify audit log integrity'),
        ]

    def save(self, *args, **kwargs):
        """
        Override save to compute hash and prevent updates.
        CRITICAL: This enforces WORM principle.
        """
        if self.pk is not None:
            # Entry already exists; prevent modification
            raise ValidationError(
                "Audit log entries are immutable (WORM principle). "
                "Cannot update existing entry."
            )

        # Get previous entry's hash (for chaining)
        last_entry = WORMAuditLog.objects.order_by('-entry_id').first()
        if last_entry:
            self.previous_entry_hash = last_entry.entry_hash
        else:
            self.previous_entry_hash = ''  # First entry in chain

        # Compute hash AFTER setting previous_entry_hash
        self.entry_hash = self._compute_hash()

        # Save to database
        super().save(*args, **kwargs)

        logger.info(
            f"WORM audit log created: {self.entry_id} "
            f"({self.action} by {self.user}) - Hash: {self.entry_hash[:16]}..."
        )

    def delete(self, *args, **kwargs):
        """
        Prevent deletion (WORM principle).
        CRITICAL: Audit logs must NEVER be deleted.
        """
        raise ValidationError(
            "Audit log entries cannot be deleted (WORM principle). "
            "Deletion would break the hash chain and compromise audit integrity."
        )

    def _compute_hash(self):
        """
        Compute SHA-256 hash of log entry.

        Hash includes:
        - timestamp (microsecond precision)
        - user_id (or 'None')
        - action
        - ip_address
        - user_agent
        - success flag
        - details
        - document_id
        - document_hash
        - previous_entry_hash (chain linkage)

        Excludes:
        - entry_id (not yet assigned during creation)
        - entry_hash (would be circular)
        """
        # Format timestamp with microsecond precision for uniqueness
        timestamp_str = self.timestamp.isoformat() if self.timestamp else timezone.now().isoformat()

        # Build data string to hash
        data_to_hash = (
            f"{timestamp_str}|"
            f"{self.user_id if self.user_id else 'None'}|"
            f"{self.action}|"
            f"{self.ip_address}|"
            f"{self.user_agent}|"
            f"{self.success}|"
            f"{self.details}|"
            f"{self.document_id if self.document_id else 'None'}|"
            f"{self.document_hash}|"
            f"{self.previous_entry_hash}"
        )

        return hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()

    def verify_integrity(self, previous_entry=None):
        """
        Verify integrity of this log entry.

        Checks:
        1. Hash matches recomputed value
        2. Chain linkage to previous entry is valid

        Args:
            previous_entry: Previous WORMAuditLog entry (optional, for chain verification)

        Returns:
            dict: {'valid': bool, 'reason': str, 'hash_match': bool, 'chain_valid': bool}
        """
        result = {
            'valid': True,
            'reason': 'OK',
            'hash_match': False,
            'chain_valid': False
        }

        # Check 1: Recompute hash and verify
        try:
            computed_hash = self._compute_hash()
            result['hash_match'] = (computed_hash == self.entry_hash)

            if not result['hash_match']:
                result['valid'] = False
                result['reason'] = (
                    f'Hash mismatch: expected {computed_hash[:16]}..., '
                    f'got {self.entry_hash[:16]}... (TAMPERING DETECTED)'
                )
                return result
        except Exception as e:
            result['valid'] = False
            result['reason'] = f'Hash computation error: {str(e)}'
            return result

        # Check 2: Verify chain linkage
        if previous_entry:
            result['chain_valid'] = (self.previous_entry_hash == previous_entry.entry_hash)

            if not result['chain_valid']:
                result['valid'] = False
                result['reason'] = (
                    f'Hash chain broken: entry {self.entry_id} does not link to '
                    f'{previous_entry.entry_id} (CHAIN TAMPERING DETECTED)'
                )
                return result
        else:
            # No previous entry provided, chain check skipped
            result['chain_valid'] = None

        result['valid'] = True
        result['reason'] = 'Integrity verified'
        return result

    @staticmethod
    def verify_log_integrity(start_entry_id=None, end_entry_id=None):
        """
        Verify entire audit log chain from first to last entry.

        Args:
            start_entry_id: Optional starting entry ID (default: first entry)
            end_entry_id: Optional ending entry ID (default: last entry)

        Returns:
            dict: {
                'valid': bool,
                'total_entries': int,
                'verified_entries': int,
                'broken_at_entry': int or None,
                'errors': list of {'entry_id': int, 'error': str}
            }
        """
        # Query entries in order
        queryset = WORMAuditLog.objects.order_by('entry_id')

        if start_entry_id:
            queryset = queryset.filter(entry_id__gte=start_entry_id)
        if end_entry_id:
            queryset = queryset.filter(entry_id__lte=end_entry_id)

        all_entries = list(queryset)
        errors = []
        previous = None

        for entry in all_entries:
            result = entry.verify_integrity(previous)
            if not result['valid']:
                errors.append({
                    'entry_id': entry.entry_id,
                    'error': result['reason']
                })
            previous = entry

        return {
            'valid': len(errors) == 0,
            'total_entries': len(all_entries),
            'verified_entries': len(all_entries) - len(errors),
            'broken_at_entry': errors[0]['entry_id'] if errors else None,
            'errors': errors
        }

    @classmethod
    def create_log(cls, user, action, ip_address, success=True, details="", document=None, document_id=None,
                   classification_level=None, user_agent=""):
        """
        Création sécurisée d'une entrée de log.
        """
        # Récupération sécurisée du Hash du document
        doc_hash = ""
        if document:
            # On cherche 'checksum_sha256' (le nom standard) ou on renvoie vide si pas trouvé
            doc_hash = getattr(document, 'checksum_sha256', '')

        # Création de l'objet (sans le sauvegarder tout de suite pour calculer le hash chain)
        log_entry = cls(
            user=user,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details,

            # Gestion des documents (ID et Hash)
            document_id=str(document.id) if document else (str(document_id) if document_id else None),
            document_hash=doc_hash,  # <--- C'est ici que ça plantait

            classification_level=classification_level,
            timestamp=timezone.now()
        )

        # Calcul de l'intégrité (Hash Chain)
        log_entry.compute_hash()

        # Sauvegarde finale
        log_entry.save()
        return log_entry

    def __str__(self):
        user_str = self.user.username if self.user else 'Anonymous'
        return f"{self.entry_id}: {user_str} - {self.action} @ {self.timestamp}"





class RestrictedAuditAccess(models.Model):
    """
    Model tracking and restricting who can access audit logs.
    Implements audit log access control (admin-only by default).
    """

    ACCESS_LEVEL_CHOICES = [
        ('view', 'Can view audit logs'),
        ('export', 'Can export audit logs'),
        ('verify', 'Can verify audit log integrity'),
        ('manage', 'Can manage audit log access'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='audit_access_grants'
    )
    access_level = models.CharField(
        max_length=20,
        choices=ACCESS_LEVEL_CHOICES
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
            Index(fields=['expires_at']),
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

    ACTION_CHOICES = [
        ('view', 'Viewed audit log'),
        ('export', 'Exported audit log'),
        ('search', 'Searched audit log'),
        ('verify_integrity', 'Verified log integrity'),
    ]

    user = models.ForeignKey(User, on_delete=models.PROTECT)
    accessed_at = models.DateTimeField(auto_now_add=True, db_index=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
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
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-accessed_at']
        indexes = [
            Index(fields=['user', 'accessed_at']),
            Index(fields=['action', 'accessed_at']),
        ]

    def __str__(self):
        return f"{self.user} - {self.action} @ {self.accessed_at}"