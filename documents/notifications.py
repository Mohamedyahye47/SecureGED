"""
documents/notifications.py

✅ SYSTÈME DE NOTIFICATIONS POUR LES STAFFS

Gère les notifications pour :
- Nouvelles demandes d'accès au département
- Documents en quarantaine
- Activités suspectes
"""

import logging
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User
from .models import UserProfile, Department
from .audit_models import WORMAuditLog

logger = logging.getLogger(__name__)


def notify_department_staff_new_request(profile, department):
    """
    Notifie les staffs du département d'une nouvelle demande d'accès.

    Args:
        profile: UserProfile de l'utilisateur demandeur
        department: Department choisi
    """
    # Récupérer tous les staffs du département
    staff_users = User.objects.filter(
        profile__department=department,
        profile__is_department_staff=True,
        is_active=True
    ).exclude(email="")

    if not staff_users.exists():
        logger.warning(f"Aucun staff trouvé pour le département {department.name}")
        return

    # Préparer l'email
    subject = f"[GED] Nouvelle demande d'accès - {department.name}"

    message = f"""
Bonjour,

Une nouvelle demande d'accès au département {department.name} a été reçue.

DÉTAILS DU DEMANDEUR :
- Nom : {profile.user.get_full_name()}
- Email : {profile.user.email}
- Téléphone : {profile.phone or 'Non renseigné'}
- Date de demande : {profile.updated_at.strftime('%d/%m/%Y à %H:%M')}

ACTION REQUISE :
Veuillez vous connecter au système pour examiner et approuver/rejeter cette demande.
URL : {settings.SITE_URL}/staff/pending-requests/

Cordialement,
Système GED Sécurisé
"""

    recipient_list = list(staff_users.values_list('email', flat=True))

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_list,
            fail_silently=False,
        )
        logger.info(f"✅ Notification envoyée à {len(recipient_list)} staffs pour {profile.user.username}")
    except Exception as e:
        logger.error(f"❌ Erreur envoi notification : {e}")


def notify_user_approval(profile, approved_by):
    """
    Notifie l'utilisateur que sa demande a été approuvée.

    Args:
        profile: UserProfile de l'utilisateur
        approved_by: User qui a approuvé
    """
    if not profile.user.email:
        return

    subject = "✅ Votre accès au GED a été approuvé"

    message = f"""
Bonjour {profile.user.get_full_name()},

Bonne nouvelle ! Votre demande d'accès au département {profile.department.name} a été approuvée.

Vous pouvez maintenant vous connecter et accéder aux documents de votre département.

URL : {settings.SITE_URL}/login/

Approuvé par : {approved_by.get_full_name()}
Date : {profile.approved_at.strftime('%d/%m/%Y à %H:%M')}

Cordialement,
Système GED Sécurisé
"""

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[profile.user.email],
            fail_silently=False,
        )
        logger.info(f"✅ Notification d'approbation envoyée à {profile.user.email}")
    except Exception as e:
        logger.error(f"❌ Erreur envoi notification approbation : {e}")


def notify_user_rejection(profile, rejected_by, reason=""):
    """
    Notifie l'utilisateur que sa demande a été rejetée.

    Args:
        profile: UserProfile de l'utilisateur
        rejected_by: User qui a rejeté
        reason: Raison du rejet (optionnel)
    """
    if not profile.user.email:
        return

    subject = "❌ Votre demande d'accès au GED"

    reason_text = f"\n\nRaison : {reason}" if reason else ""

    message = f"""
Bonjour {profile.user.get_full_name()},

Votre demande d'accès au département {profile.pending_department.name if profile.pending_department else 'N/A'} n'a pas pu être approuvée.{reason_text}

Pour plus d'informations, veuillez contacter le responsable de votre département.

Cordialement,
Système GED Sécurisé
"""

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[profile.user.email],
            fail_silently=False,
        )
        logger.info(f"✅ Notification de rejet envoyée à {profile.user.email}")
    except Exception as e:
        logger.error(f"❌ Erreur envoi notification rejet : {e}")


def notify_staff_quarantine_document(document):
    """
    Notifie les staffs du département qu'un nouveau document est en quarantaine.

    Args:
        document: Document en quarantaine
    """
    if not document.department:
        # Si pas de département, notifier les superusers
        staff_users = User.objects.filter(is_superuser=True, is_active=True).exclude(email="")
    else:
        # Notifier les staffs du département
        staff_users = User.objects.filter(
            profile__department=document.department,
            profile__is_department_staff=True,
            is_active=True
        ).exclude(email="")

    if not staff_users.exists():
        logger.warning(f"Aucun staff à notifier pour le document {document.id}")
        return

    subject = f"[GED] Nouveau document en quarantaine - {document.get_title()}"

    message = f"""
Bonjour,

Un nouveau document a été uploadé et attend validation en quarantaine.

DÉTAILS DU DOCUMENT :
- Titre : {document.get_title()}
- Uploadé par : {document.uploaded_by.get_full_name() if document.uploaded_by else 'Inconnu'}
- Taille : {document.file_size / 1024:.2f} Ko
- Type : {document.mime_type}
- Classification : {document.get_classification_level_display()}
- Date : {document.uploaded_at.strftime('%d/%m/%Y à %H:%M')}

ACTION REQUISE :
Examinez et approuvez/rejetez ce document dans la section Quarantaine.
URL : {settings.SITE_URL}/quarantine/

Cordialement,
Système GED Sécurisé
"""

    recipient_list = list(staff_users.values_list('email', flat=True))

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_list,
            fail_silently=False,
        )
        logger.info(f"✅ Notification quarantaine envoyée à {len(recipient_list)} staffs")
    except Exception as e:
        logger.error(f"❌ Erreur envoi notification quarantaine : {e}")


def get_pending_requests_count(department):
    """
    Retourne le nombre de demandes en attente pour un département.

    Args:
        department: Department

    Returns:
        int: Nombre de demandes en attente
    """
    return UserProfile.objects.filter(
        pending_department=department,
        approval_status=UserProfile.ApprovalStatus.PENDING
    ).count()


def get_staff_notifications_summary(user):
    """
    Retourne un résumé des notifications pour un staff.

    Args:
        user: User (doit être staff)

    Returns:
        dict: Résumé des notifications
    """
    try:
        profile = UserProfile.objects.get(user=user)

        if not (user.is_superuser or profile.is_department_staff):
            return {
                'pending_requests': 0,
                'quarantine_docs': 0,
                'total': 0
            }

        department = profile.department

        # Compter les demandes en attente
        pending_requests = UserProfile.objects.filter(
            pending_department=department,
            approval_status=UserProfile.ApprovalStatus.PENDING
        ).count() if department else 0

        # Compter les documents en quarantaine
        from .models import Document
        if user.is_superuser:
            quarantine_docs = Document.objects.filter(status='quarantine').count()
        elif department:
            quarantine_docs = Document.objects.filter(
                status='quarantine',
                department=department
            ).count()
        else:
            quarantine_docs = 0

        return {
            'pending_requests': pending_requests,
            'quarantine_docs': quarantine_docs,
            'total': pending_requests + quarantine_docs
        }

    except UserProfile.DoesNotExist:
        return {
            'pending_requests': 0,
            'quarantine_docs': 0,
            'total': 0
        }