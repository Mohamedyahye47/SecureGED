"""documents/views.py"""
import logging
from pathlib import Path
from datetime import datetime
import csv

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.core.mail import send_mail

from .audit_models import WORMAuditLog
from .forms import DocumentUploadForm, LoginForm, PrivateMessageForm
from .models import Department, Document, UserProfile
from .security import EncryptionManager
from .antivirus_scanner import AntivirusScanner

logger = logging.getLogger(__name__)


# -----------------
# UTILITAIRES
# -----------------

def get_client_ip(request):
    """Récupère l'adresse IP du client."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def log_access(document, user, action, request, success=True, details=""):
    """Enregistre l'activité dans le journal d'audit WORM immuable."""
    try:
        WORMAuditLog.create_log(
            user=user if user and getattr(user, "is_authenticated", False) else None,
            action=action,
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
            success=success,
            details=details,
            document=document,
            classification_level=document.classification_level if document else None,
        )
    except Exception as e:
        logger.error(f"Erreur Audit Log : {e}")


# Dans documents/views.py

def require_approved_user(view_func):
    """
    Bloque l'accès si l'utilisateur n'est pas approuvé.
    Laisse passer les STAFFS même s'ils sont 'Pending'.
    """
    def _wrapped(request, *args, **kwargs):
        if request.user.is_authenticated:
            # Le Superuser passe toujours
            if request.user.is_superuser:
                return redirect("admin:auth_user_changelist")

            profile, _ = UserProfile.objects.get_or_create(user=request.user)

            # === LA CORRECTION EST ICI ===
            # On autorise si : C'est approuvé OU C'est un Staff
            is_authorized = profile.is_approved() or profile.is_department_staff

            if not is_authorized:
                # Exceptions pour ne pas bloquer la déconnexion
                if request.resolver_match.url_name in ['user_profile', 'logout', 'login']:
                    return view_func(request, *args, **kwargs)

                # Redirection vers la page "En attente" ou Profil
                messages.warning(request, "🔒 Compte en attente de validation.")
                return redirect("user_profile")

        return view_func(request, *args, **kwargs)

    return _wrapped


def save_secure_document(request, uploaded_file, level, title, description, department=None, target_user=None):
    """
    Fonction Helper pour gérer le scan AV, le chiffrement et la sauvegarde BDD.
    Utilisée par l'Upload Standard et la Messagerie.
    """
    # 1. Préparation dossier
    upload_dir = Path(settings.MEDIA_ROOT) / "documents" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    raw = uploaded_file.read()

    # 2. Scan Antivirus
    scanner = AntivirusScanner()
    scan_result = scanner.scan_bytes(raw, uploaded_file.name)

    if scan_result['status'] == 'infected':
        msg = f"MALWARE: {scan_result.get('threat_name', 'Inconnu')}"
        logger.warning(f"{msg} dans {uploaded_file.name} par {request.user.username}")
        log_access(None, request.user, "upload_reject", request, False, msg)
        messages.error(request, f"🦠 Fichier rejeté : Virus détecté ({scan_result.get('threat_name')}).")
        return None
    elif scan_result['status'] == 'error':
        messages.error(request, "❌ Erreur lors de l'analyse antivirus.")
        return None

    # 3. Chiffrement
    manager = EncryptionManager()
    encrypted = manager.encrypt_file(raw)

    safe_name = f"{timezone.now().timestamp()}_{uploaded_file.name}"
    file_path = upload_dir / safe_name
    file_path.write_bytes(encrypted)

    # 4. Création en Base
    doc = Document(
        original_filename=uploaded_file.name,
        file_path=str(file_path),
        file_size=len(encrypted),
        mime_type=getattr(uploaded_file, "content_type", "application/octet-stream"),
        uploaded_by=request.user,
        department=department,
        target_user=target_user,
        classification_level=level,
        is_encrypted=True,
        status="approved",
    )
    doc.set_title(title or uploaded_file.name)
    doc.set_description(description or "")
    doc.compute_integrity_fields(raw)
    doc.save()

    # Log succès
    log_access(doc, request.user, "upload", request, True, f"Niveau: {doc.get_classification_level_display()}")
    return doc


# -----------------
# VUES PUBLIQUES & AUTH
# -----------------

def public_documents_view(request):
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect("admin:auth_user_changelist")

    public_docs = (
        Document.objects.filter(
            status="approved",
            classification_level=Document.Classification.PUBLIC
        )
        .select_related("uploaded_by")
        .order_by("-uploaded_at")
    )

    paginator = Paginator(public_docs, 10)
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "public_documents.html", {
        "documents": page_obj,
        "page_obj": page_obj,
        "paginator": paginator,
        "is_paginated": page_obj.has_other_pages(),
    })


def login_view(request):
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect("admin:auth_user_changelist")
        return redirect("dashboard")

    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]

            try:
                user_obj = User.objects.get(username=username)

                # Bypass profil pour superuser
                if user_obj.is_superuser:
                    user = authenticate(request, username=username, password=password)
                    if user:
                        login(request, user)
                        return redirect("admin:auth_user_changelist")

                profile, _ = UserProfile.objects.get_or_create(user=user_obj)

                if profile.is_account_locked():
                    messages.error(request, "🔒 Compte verrouillé temporairement.")
                    return render(request, "login.html", {"form": form})

                user = authenticate(request, username=username, password=password)

                if user is not None and user.is_active:
                    login(request, user)
                    profile.reset_failed_attempts()
                    log_access(None, user, "login", request, True, "Succès")
                    return redirect("dashboard")

                profile.increment_failed_attempts()
                messages.error(request, "❌ Identifiants invalides.")
                log_access(None, user_obj, "login", request, False, "Echec Auth")

            except User.DoesNotExist:
                messages.error(request, "❌ Identifiants invalides")
    else:
        form = LoginForm()

    return render(request, "login.html", {"form": form})


def logout_view(request):
    if request.user.is_authenticated and not request.user.is_superuser:
        log_access(None, request.user, "logout", request, True)
    logout(request)
    messages.success(request, "👋 Déconnexion réussie.")
    return redirect("login")


# -----------------
# DASHBOARD
# -----------------

@login_required
@require_approved_user
def dashboard_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    # 1. Public
    q = Q(status="approved", classification_level=Document.Classification.PUBLIC)

    # 2. Département (Automatique)
    if profile.department_id:
        # Interne : Visible par tout le département
        q |= Q(
            status="approved",
            classification_level=Document.Classification.INTERNAL,
            department_id=profile.department_id,
        )
        # Secret : Visible seulement par le staff du département
        if profile.is_department_staff:
            q |= Q(
                status="approved",
                classification_level=Document.Classification.SECRET,
                department_id=profile.department_id,
            )

    # 3. Documents Personnels (Reçus)
    q |= Q(
        status="approved",
        classification_level=Document.Classification.PERSONAL,
        target_user=request.user
    )

    accessible_docs = (
        Document.objects.filter(q)
        .distinct()
        .select_related("uploaded_by", "department", "target_user")
        .order_by("-uploaded_at")[:10]
    )

    # Documents que j'ai uploadés
    my_docs = (
        Document.objects.filter(uploaded_by=request.user)
        .select_related("department", "target_user")
        .order_by("-uploaded_at")[:5]
    )

    total_accessible = Document.objects.filter(q).distinct().count() + my_docs.count()

    return render(request, "dashboard.html", {
        "user_documents": my_docs,
        "accessible_documents": accessible_docs,
        "total_accessible": total_accessible,
        "department": profile.department,
        "is_staff": profile.is_department_staff,
        "is_admin": False,
    })


# -----------------
# UPLOAD ORGANISATIONNEL (Sans 'Personnel')
# -----------------

@login_required
@require_approved_user
def document_upload_view(request):
    """
    Permet d'uploader Public, Interne, Secret.
    Le département est assigné automatiquement.
    """
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == "POST":
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                uploaded_file = request.FILES["file"]
                level = form.cleaned_data["classification_level"] # C'est une string ici

                department = None

                # Logique d'assignation auto du département
                if level in (Document.Classification.INTERNAL, Document.Classification.SECRET):
                    department = profile.department
                    if not department:
                        messages.error(request, "❌ Impossible : Vous n'avez pas de département assigné.")
                        return render(request, "document_upload.html", {"form": form})

                # Appel de la fonction de sauvegarde sécurisée
                doc = save_secure_document(
                    request=request,
                    uploaded_file=uploaded_file,
                    level=level,
                    title=form.cleaned_data["title"],
                    description=form.cleaned_data["description"],
                    department=department,
                    target_user=None # Pas de cible user ici
                )

                if doc:
                    messages.success(request, f"✅ Document '{doc.get_title()}' déposé avec succès.")
                    return redirect("dashboard")

            except Exception as e:
                logger.error(f"Erreur Upload : {e}", exc_info=True)
                messages.error(request, f"❌ Erreur technique : {e}")

    else:
        form = DocumentUploadForm()

    return render(request, "document_upload.html", {"form": form})


# -----------------
# MESSAGERIE / CONTACT (Avec Fichier Personnel)
# -----------------

@login_required
def contact_view(request):
    """
    Permet d'envoyer un message + Fichier Personnel optionnel.
    Filtre : Exclut les superusers et l'utilisateur lui-même.
    """
    # 1. Récupération des utilisateurs pour le menu de recherche (Select2)
    # On exclut les superusers (admins techniques) et soi-même
    users = User.objects.filter(
        is_active=True,
        is_superuser=False
    ).exclude(
        id=request.user.id
    ).select_related(
        'profile',
        'profile__department'
    ).order_by('last_name', 'first_name')

    if request.method == 'POST':
        # On passe 'users' au formulaire s'il a besoin de valider le choix,
        # mais ici on traite la requête manuellement pour plus de flexibilité avec Select2
        form = PrivateMessageForm(request.POST, request.FILES, user=request.user)

        # Note: PrivateMessageForm attend 'recipient' qui est validé par le queryset défini dans son __init__.
        # Assurez-vous que le queryset du form correspond à celui de la vue pour éviter des erreurs de validation.

        if form.is_valid():
            recipient = form.cleaned_data['recipient']
            subject = form.cleaned_data['subject']
            message_text = form.cleaned_data['message']
            uploaded_file = form.cleaned_data['file']

            try:
                doc_link_text = ""

                # 2. Traitement du fichier joint (si présent)
                if uploaded_file:
                    doc = save_secure_document(
                        request=request,
                        uploaded_file=uploaded_file,
                        level=Document.Classification.PERSONAL,
                        title=subject,  # Le titre du doc = sujet du message
                        description=message_text,
                        department=None,
                        target_user=recipient  # Assignation au destinataire
                    )

                    if not doc:
                        # Si échec (virus), on arrête
                        return redirect('contact_view')

                    doc_link_text = f"\n\n📎 PIÈCE JOINTE SÉCURISÉE : {doc.get_title()}"
                    log_access(doc, request.user, "contact_file", request, True, f"Envoyé à {recipient.username}")

                # 3. Envoi Email
                email_subject = f"[Secure GED] Message de {request.user.get_full_name() or request.user.username}"
                email_body = (
                    f"Bonjour {recipient.first_name},\n\n"
                    f"Vous avez reçu un message de {request.user.get_full_name()} ({request.user.email}).\n\n"
                    f"OBJET : {subject}\n\n"
                    f"MESSAGE :\n{message_text}\n"
                    f"{doc_link_text}\n\n"
                    f"Accédez à la plateforme : {getattr(settings, 'SITE_URL', 'http://localhost:8000')}"
                )

                send_mail(
                    email_subject,
                    email_body,
                    settings.DEFAULT_FROM_EMAIL,
                    [recipient.email],
                    fail_silently=False
                )

                # 4. Log Audit pour le message simple (si pas de fichier)
                if not uploaded_file:
                    WORMAuditLog.create_log(
                        user=request.user,
                        action="contact",
                        ip_address=get_client_ip(request),
                        success=True,
                        details=f"Message à {recipient.username}: {subject}"
                    )

                messages.success(request, f"✅ Message envoyé à {recipient.get_full_name()}.")
                return redirect('dashboard')

            except Exception as e:
                logger.error(f"Erreur Contact : {e}", exc_info=True)
                messages.error(request, "❌ Une erreur est survenue lors de l'envoi.")

    else:
        form = PrivateMessageForm(user=request.user)

    # On passe la liste 'users' au template pour peupler le <select> manuellement si besoin
    # ou pour l'utiliser avec Select2
    return render(request, "contact.html", {'form': form, 'users': users})


# -----------------
# DÉTAIL & DOWNLOAD
# -----------------

@login_required
@require_approved_user
def document_detail_view(request, document_id):
    document = get_object_or_404(Document, id=document_id)

    if not document.can_access(request.user):
        log_access(document, request.user, "view", request, False, "Accès Refusé")
        return HttpResponseForbidden(render(request, "access_denied.html", {"document": document}))

    log_access(document, request.user, "view", request, True)

    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    show_logs = profile.is_department_staff

    recent_logs = []
    if show_logs:
        recent_logs = WORMAuditLog.objects.filter(document_id=document.id).select_related("user").order_by("-timestamp")[:10]

    return render(request, "document_detail.html", {
        "document": document,
        "recent_logs": recent_logs,
        "can_download": True,
        "show_logs": show_logs,
        "back_url_name": "dashboard",
    })


@login_required
@require_approved_user
def document_download_view(request, document_id):
    document = get_object_or_404(Document, id=document_id)

    if not document.can_access(request.user):
        log_access(document, request.user, "download", request, False, "Refusé")
        messages.error(request, "❌ Accès refusé.")
        return redirect("dashboard")

    try:
        file_path = Path(document.file_path).resolve()

        # Sécurité Path Traversal
        if not str(file_path).startswith(str(Path(settings.MEDIA_ROOT).resolve())):
            return HttpResponse("Erreur chemin fichier.", status=404)

        if not file_path.exists():
            return HttpResponse("Fichier introuvable.", status=404)

        # Déchiffrement
        manager = EncryptionManager()
        decrypted_data = manager.decrypt_file(file_path.read_bytes())

        # Vérification intégrité
        document.verify_integrity(decrypted_data)

        log_access(document, request.user, "download", request, True)

        resp = HttpResponse(decrypted_data, content_type=document.mime_type)
        resp["Content-Disposition"] = f'inline; filename="{document.original_filename}"'
        return resp

    except Exception as e:
        logger.error(f"DL Error: {e}")
        messages.error(request, "Erreur technique lors du téléchargement.")
        return redirect("dashboard")


# -----------------
# AUDIT & GESTION USERS
# -----------------

@login_required
def audit_log_view(request):
    profile = get_object_or_404(UserProfile, user=request.user)

    # Sécurité : Seul le staff a accès
    if not profile.is_department_staff:
        messages.error(request, "Accès non autorisé.")
        return redirect('dashboard')

    # 1. Base : Logs concernant le département du staff
    # On récupère les IDs des documents du département pour filtrer les logs associés
    dept_docs = Document.objects.filter(department=profile.department)
    doc_ids = [str(d.id) for d in dept_docs]

    logs = WORMAuditLog.objects.filter(
        Q(user__profile__department=profile.department) |  # Actions des utilisateurs du dept
        Q(document_id__in=doc_ids)  # Actions sur les docs du dept
    ).order_by('-timestamp')

    # 2. APPLICATION DES FILTRES (CORRECTION MAJEURE)
    search_query = request.GET.get('search')
    if search_query:
        logs = logs.filter(
            Q(user__username__icontains=search_query) |
            Q(ip_address__icontains=search_query) |
            Q(details__icontains=search_query)
        )

    action = request.GET.get('action')
    if action:
        logs = logs.filter(action=action)

    success = request.GET.get('success')
    if success == 'true':
        logs = logs.filter(success=True)
    elif success == 'false':
        logs = logs.filter(success=False)

    date_from = request.GET.get('date_from')
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)

    date_to = request.GET.get('date_to')
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)

    # 3. Pagination
    paginator = Paginator(logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, "staff/audit_log.html", {
        "page_obj": page_obj,  # Le template attend page_obj maintenant
    })

@login_required
def manage_users_view(request):
    """
    Gestion de l'équipe : Voir, Bloquer, Activer.
    URL name: 'manage_users'
    """
    profile = get_object_or_404(UserProfile, user=request.user)

    # SÉCURITÉ : Seul le Staff a accès
    if not profile.is_department_staff:
        messages.error(request, "Accès refusé. Espace réservé aux responsables.")
        return redirect('dashboard')

    # On récupère les membres du MÊME département (sauf soi-même et admin)
    users = User.objects.filter(
        profile__department=profile.department,
        is_superuser=False
    ).exclude(id=request.user.id).select_related('profile')

    if request.method == "POST":
        user_id = request.POST.get('user_id')
        target = get_object_or_404(User, id=user_id)

        # SÉCURITÉ CRITIQUE : Vérifier que la cible est bien dans le MÊME département
        if target.profile.department == profile.department:
            action = request.POST.get('action')

            if action == "block":
                target.is_active = False
                target.save()
                messages.warning(request, f"🚫 Accès bloqué pour {target.username}.")

            elif action == "activate":  # ou "unblock" selon votre template
                target.is_active = True
                target.save()
                messages.success(request, f"✅ Accès réactivé pour {target.username}.")
        else:
            messages.error(request, "Vous ne pouvez pas modifier un utilisateur d'un autre service.")

        return redirect('manage_users')  # On recharge la page

    # On renvoie vers le template spécifique (Vérifiez que ce fichier existe !)
    return render(request, 'staff/department_users.html', {'team_members': users})