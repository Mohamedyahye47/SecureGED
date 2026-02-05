"""documents/models.py"""
from __future__ import annotations
import logging
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist

# Crypto imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)
User = get_user_model()


class Department(models.Model):
    """
    Représente un département (RH, IT, etc.).
    """
    name = models.CharField(max_length=100)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Clés cryptographiques
    signature = models.TextField(blank=True)
    signer_pubkey = models.TextField(blank=True)

    # CORRECTION 1 : On ajoute un champ pour la clé privée (à protéger absolument en prod !)
    # Dans une vraie GED WORM, cette clé serait dans un module HSM matériel.
    signer_privkey_encrypted = models.TextField(blank=True, help_text="Clé privée chiffrée (simulée)")

    def save(self, *args, **kwargs):
        # Génération automatique des clés à la création si absentes
        if not self.signer_pubkey:
            try:
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                public_key = private_key.public_key()

                # Stockage Clé Publique
                self.signer_pubkey = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')

                # CORRECTION 1 (Suite) : Stockage Clé Privée (PEM)
                # Note : Ici on la stocke en clair pour l'exemple, mais il faudrait la chiffrer
                self.signer_privkey_encrypted = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
            except Exception as e:
                logger.error(f"Erreur génération clés crypto dept: {e}")

        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class UserProfile(models.Model):
    class ApprovalStatus(models.TextChoices):
        PENDING = 'PENDING', 'En attente'
        APPROVED = 'APPROVED', 'Approuvé'
        REJECTED = 'REJECTED', 'Rejeté'

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')

    # Hiérarchie
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    is_department_staff = models.BooleanField(default=False, help_text="Est responsable/staff du département")

    # OAuth & Sécurité
    is_oauth_user = models.BooleanField(default=False)

    # CORRECTION 2 : Le statut par défaut doit être PENDING pour sécuriser l'entrée
    approval_status = models.CharField(
        max_length=10,
        choices=ApprovalStatus.choices,
        default=ApprovalStatus.PENDING
    )

    google_id = models.CharField(max_length=255, blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)

    # Sécurité connexion
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)

    def is_approved(self):
        # Un utilisateur est approuvé SI statut=APPROVED ET il a un département
        # (Sauf superuser géré ailleurs, mais ici on parle du profil métier)
        return self.approval_status == self.ApprovalStatus.APPROVED and self.department is not None

    def increment_failed_attempts(self):
        self.failed_login_attempts += 1
        # On utilise des valeurs par défaut si settings n'est pas configuré
        max_attempts = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
        timeout = getattr(settings, 'LOGIN_ATTEMPT_TIMEOUT', 300)

        if self.failed_login_attempts >= max_attempts:
            self.account_locked_until = timezone.now() + timezone.timedelta(seconds=timeout)
        self.save()

    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save()

    def is_account_locked(self):
        if self.account_locked_until and timezone.now() < self.account_locked_until:
            return True
        return False

    def is_approved(self):
        """
        Vérifie si l'utilisateur a accès à l'application.
        MODIFICATION : Les Staffs et Superusers sont approuvés d'office.
        """
        # 1. Si c'est un SuperAdmin ou un Staff Département -> TOUJOURS APPROUVÉ
        if self.user.is_superuser or self.is_department_staff:
            return True

        # 2. Pour les utilisateurs normaux, on vérifie le statut en base
        return self.approval_status == self.ApprovalStatus.APPROVED


    def __str__(self):
        return f"Profile de {self.user.username}"




from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from cryptography.fernet import Fernet
import base64

User = get_user_model()


class DepartmentMessage(models.Model):
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')

    # On garde le sujet en clair pour faciliter le tri/recherche (compromis acceptable)
    subject = models.CharField(max_length=255)

    # Le message sera stocké chiffré. On augmente la taille car le chiffrement prend de la place.
    message = models.TextField(help_text="Ce contenu est chiffré en base de données (AES-256).")

    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        """
        Chiffre le message avant de l'enregistrer si ce n'est pas déjà fait.
        """
        # On ne chiffre que si le message semble être en clair (pas de préfixe spécifique par exemple)
        # Mais pour faire simple, on suppose que si on sauvegarde, on chiffre le contenu actuel.
        # Attention : Pour éviter le double chiffrement lors des updates, on vérifie un flag ou on gère ça dans la vue.
        # Ici, une approche robuste : on chiffre à la volée.

        # 1. Récupérer la clé de chiffrement (définie dans settings.py)
        # Assurez-vous que settings.ENCRYPTION_KEY existe (c'est le cas dans votre projet)
        f = Fernet(settings.ENCRYPTION_KEY)

        # 2. Si le message n'est pas vide et ne commence pas par le format chiffré (g_AAAA...)
        # Note : Fernet produit des strings qui commencent souvent par gAAAA...
        if self.message and not self.message.startswith('gAAAA'):
            encrypted_bytes = f.encrypt(self.message.encode('utf-8'))
            self.message = encrypted_bytes.decode('utf-8')

        super().save(*args, **kwargs)

    @property
    def get_decrypted_message(self):
        """
        Retourne le message en clair pour l'affichage.
        """
        try:
            f = Fernet(settings.ENCRYPTION_KEY)
            # On encode en bytes, on déchiffre, on décode en utf-8
            decrypted_text = f.decrypt(self.message.encode('utf-8')).decode('utf-8')
            return decrypted_text
        except Exception as e:
            return f"[Erreur de déchiffrement ou message corrompu] : {str(e)}"

    def __str__(self):
        return f"De {self.sender} - {self.subject}"



class Document(models.Model):
    class Classification(models.TextChoices):
        PUBLIC = 'PUBLIC', 'Public (Tout le monde)'
        INTERNAL = 'INTERNAL', 'Interne (Département entier)'
        SECRET = 'SECRET', 'Secret (Staff département uniquement)'
        PERSONAL = 'PERSONAL', 'Personnel (Destinataire unique)'

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    # Fichier
    original_filename = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500)
    file_size = models.BigIntegerField()
    mime_type = models.CharField(max_length=100)

    # Métadonnées
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_documents')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # RBAC
    classification_level = models.CharField(max_length=20, choices=Classification.choices, default=Classification.INTERNAL)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    target_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='received_documents')

    # Sécurité
    is_encrypted = models.BooleanField(default=True)
    status = models.CharField(max_length=20, default='approved')
    checksum_sha256 = models.CharField(max_length=64, blank=True)
    integrity_verified_at = models.DateTimeField(null=True, blank=True)

    def set_title(self, name):
        self.title = name

    def set_description(self, desc):
        self.description = desc

    def get_title(self):
        return self.title

    def get_classification_level_display(self):
        return dict(self.Classification.choices).get(self.classification_level, self.classification_level)

    def compute_integrity_fields(self, raw_bytes):
        import hashlib
        self.checksum_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        self.integrity_verified_at = timezone.now()

    def verify_integrity(self, decrypted_bytes):
        import hashlib
        current_hash = hashlib.sha256(decrypted_bytes).hexdigest()
        if current_hash != self.checksum_sha256:
            logger.critical(f"INTEGRITY FAILURE: Document {self.id} hash mismatch!")
            raise ValueError("Erreur d'intégrité critique : Le fichier semble corrompu ou altéré.")
        return True

    def can_access(self, user):
        """Logique centrale des permissions RBAC"""
        # 1. Superuser (Accès restreint par design, ou True pour debug)
        if user.is_superuser:
            return False

        # 2. Propriétaire
        if self.uploaded_by == user:
            return True

        # 3. Public
        if self.classification_level == self.Classification.PUBLIC:
            return True

        # 4. Personnel
        if self.classification_level == self.Classification.PERSONAL:
            return self.target_user == user

        # CORRECTION 3 : Sécurisation de l'accès au profil
        # On vérifie d'abord si le profil existe
        try:
            profile = user.profile
        except ObjectDoesNotExist:
            return False # Pas de profil = Pas d'accès interne

        # 5. Interne / Secret
        if not profile.department:
            return False

        if self.department == profile.department:
            if self.classification_level == self.Classification.INTERNAL:
                # Tout le département, MAIS seulement si approuvé
                return profile.is_approved()
            if self.classification_level == self.Classification.SECRET:
                return profile.is_department_staff

        return False

    def __str__(self):
        return f"{self.title} ({self.classification_level})"


# Signal pour donner les permissions Django Admin
@receiver(post_save, sender=UserProfile)
def auto_assign_permissions(sender, instance, created, **kwargs):
    user = instance.user
    if instance.is_department_staff:
        if not user.is_staff:
            user.is_staff = True
            user.save()

        # Attribution des droits sur le modèle User pour gérer l'équipe
        content_type = ContentType.objects.get_for_model(User)
        required_perms = Permission.objects.filter(
            content_type=content_type,
            codename__in=['view_user', 'change_user']
        )
        for perm in required_perms:
            if not user.has_perm(f"auth.{perm.codename}"):
                user.user_permissions.add(perm)

    elif not instance.is_department_staff and user.is_staff and not user.is_superuser:
        # Révocation si on retire le rôle Staff Dept
        user.is_staff = False
        user.user_permissions.clear()
        user.save()