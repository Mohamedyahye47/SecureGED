from django.shortcuts import render

# Create your views here.
"""
Secure GED Views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, HttpResponseForbidden
from django.utils import timezone
from django.db import transaction
from django.core.paginator import Paginator

from .models import Document, UserProfile, AccessLog
from .security import FileIngestionPipeline, EncryptionManager
from .security_decorators import (
    deny_by_default, mfa_required, require_clearance,
    regenerate_session_id, log_audit_action, get_client_ip
)
from .forms import LoginForm, DocumentUploadForm


def get_client_ip(request):
    """Extract client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_access(document, user, action, request, success=True, details=''):
    """Log document access"""
    AccessLog.objects.create(
        document=document,
        user=user,
        action=action,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        success=success,
        details=details
    )


def can_view_document(user, document):
    """
    Détermine si un utilisateur peut voir un document selon son niveau de classification
    
    Niveaux:
    1 - Public: Tous les utilisateurs authentifiés
    2 - Interne: Tous les utilisateurs
    3 - Confidentiel: Staff (managers) et au-dessus
    4 - Secret: Superusers (admins) uniquement
    """
    classification = document.classification_level
    
    # Niveau 1 (Public) : Tous les utilisateurs authentifiés
    if classification == '1':
        return True
    
    # Niveau 2 (Interne) : Tous les utilisateurs
    if classification == '2':
        return True
    
    # Niveau 3 (Confidentiel) : Staff et admins
    if classification == '3':
        return user.is_staff or user.is_superuser
    
    # Niveau 4 (Secret) : Admins uniquement
    if classification == '4':
        return user.is_superuser
    
    return False


def login_view(request):
    """
    Secure login with brute force protection and session hardening.
    - Rate limiting with progressive delays
    - MFA enforcement checks (stub for future integration)
    - Session ID regeneration after authentication
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            
            try:
                from django.contrib.auth.models import User
                user = User.objects.get(username=username)
                profile = user.profile
                
                # Check if account is locked
                if profile.is_account_locked():
                    messages.error(request, 'Compte verrouillé. Réessayez plus tard.')
                    return render(request, 'login.html', {'form': form})
                
                # Authenticate
                user = authenticate(request, username=username, password=password)
                
                if user is not None:
                    # MFA check: if enabled, user must verify before session creation
                    profile = user.profile
                    if profile.mfa_enabled:
                        # TODO: Redirect to MFA verification view
                        # return redirect('mfa_verify')
                        pass  # For now, proceed (MFA infra not yet implemented)
                    
                    # Regenerate session ID after successful authentication
                    request.session.flush()  # Clear old session
                    login(request, user)
                    request.session.create()  # Create new session with new ID
                    
                    # Mark login time for session age tracking
                    request.session['login_time'] = timezone.now().timestamp()
                    request.session.modified = True
                    
                    profile.reset_failed_attempts()
                    messages.success(request, 'Connexion réussie!')
                    
                    # Log successful authentication
                    AccessLog.objects.create(
                        document=None,
                        user=user,
                        action='login',
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                        success=True,
                        details='Successful authentication'
                    )
                    
                    return redirect('dashboard')
                else:
                    profile.increment_failed_attempts()
                    remaining = 5 - profile.failed_login_attempts
                    if remaining > 0:
                        messages.error(request, f'Identifiants invalides. {remaining} tentatives restantes.')
                    else:
                        messages.error(request, 'Compte verrouillé pour 15 minutes.')
                    
                    # Log failed authentication
                    try:
                        AccessLog.objects.create(
                            document=None,
                            user=user,
                            action='login',
                            ip_address=get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                            success=False,
                            details=f'Failed attempt {profile.failed_login_attempts}'
                        )
                    except:
                        pass  # Log creation is non-critical
                    
            except User.DoesNotExist:
                messages.error(request, 'Identifiants invalides')
                # Log failed authentication attempt (no user found)
                AccessLog.objects.create(
                    document=None,
                    user=None,
                    action='login',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                    success=False,
                    details=f'User not found: {username}'
                )
    else:
        form = LoginForm()
    
    return render(request, 'login.html', {'form': form})


def logout_view(request):
    """
    Logout user and clear session securely.
    Logs the logout event for audit trail.
    """
    if request.user.is_authenticated:
        user = request.user
        ip = get_client_ip(request)
        
        # Log logout event
        AccessLog.objects.create(
            document=None,
            user=user,
            action='logout',
            ip_address=ip,
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            success=True,
            details='User logout'
        )
    
    logout(request)
    request.session.flush()  # Ensure complete session cleanup
    messages.success(request, 'Déconnexion réussie.')
    return redirect('login')


@login_required
def dashboard_view(request):
    """Main dashboard - Affiche uniquement les documents accessibles par l'utilisateur"""
    
    # Documents uploadés par l'utilisateur
    user_documents = Document.objects.filter(
        uploaded_by=request.user,
        status='approved'
    ).order_by('-uploaded_at')
    
    # Documents accessibles selon le niveau de classification
    all_accessible_docs = Document.objects.filter(
        status='approved'
    ).exclude(uploaded_by=request.user).order_by('-uploaded_at')
    
    # Filtrer selon les permissions
    accessible_docs = [
        doc for doc in all_accessible_docs 
        if can_view_document(request.user, doc)
    ][:10]
    
    # Statistiques
    total_accessible = len([
        doc for doc in Document.objects.filter(status='approved')
        if can_view_document(request.user, doc)
    ])
    
    context = {
        'user_documents': user_documents,
        'accessible_documents': accessible_docs,
        'total_accessible': total_accessible,
        'clearance_level': request.user.profile.get_clearance_level_display(),
        'is_admin': request.user.is_superuser,
        'is_staff': request.user.is_staff,
    }
    
    return render(request, 'dashboard.html', context)


@login_required
def document_upload_view(request):
    """Upload document with security pipeline"""
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        
        if form.is_valid():
            uploaded_file = request.FILES['file']
            classification = form.cleaned_data['classification_level']
            
            # Vérifier si l'utilisateur peut uploader à ce niveau
            if classification == '4' and not request.user.is_superuser:
                messages.error(request, '❌ Seuls les admins peuvent créer des documents "Secret"')
                return render(request, 'document_upload.html', {'form': form})
            
            if classification == '3' and not (request.user.is_staff or request.user.is_superuser):
                messages.error(request, '❌ Seul le personnel autorisé peut créer des documents "Confidentiel"')
                return render(request, 'document_upload.html', {'form': form})
            
            # Process through security pipeline
            pipeline = FileIngestionPipeline()
            result = pipeline.process_upload(
                uploaded_file,
                request.user,
                {
                    'title': form.cleaned_data['title'],
                    'description': form.cleaned_data['description'],
                    'classification_level': form.cleaned_data['classification_level'],
                }
            )
            
            if result['status'] == 'approved':
                # Create document record
                with transaction.atomic():
                    document = Document.objects.create(
                        title=form.cleaned_data['title'],
                        description=form.cleaned_data['description'],
                        classification_level=form.cleaned_data['classification_level'],
                        original_filename=result['filename'],
                        file_path=result['file_path'],
                        file_size=result['file_size'],
                        mime_type=result['mime_type'],
                        file_hash=result['file_hash'],
                        status='approved',
                        is_encrypted=True,
                        uploaded_by=request.user
                    )
                    
                    # Log upload
                    log_access(document, request.user, 'upload', request, True, 
                              'Document uploaded and encrypted')
                
                messages.success(request, '✅ Document téléchargé avec succès!')
                return redirect('document_detail', document_id=document.id)
            else:
                messages.error(request, f"❌ Échec: {result.get('error', 'Erreur inconnue')}")
    else:
        form = DocumentUploadForm()
    
    return render(request, 'document_upload.html', {'form': form})


@login_required
def document_detail_view(request, document_id):
    """View document details - Vérifie les permissions"""
    document = get_object_or_404(Document, id=document_id)
    
    # Vérifier les permissions selon le niveau de classification
    if not can_view_document(request.user, document):
        log_access(document, request.user, 'view', request, False, 
                   f'Access denied - Classification {document.get_classification_level_display()}, User level insufficient')
        
        # Message personnalisé selon le niveau
        if document.classification_level == '4':
            messages.error(request, '🚨 Accès refusé : Ce document "Secret" nécessite des privilèges administrateur')
        elif document.classification_level == '3':
            messages.error(request, '🔒 Accès refusé : Ce document "Confidentiel" nécessite une autorisation de niveau staff')
        else:
            messages.error(request, '❌ Accès refusé : Habilitation insuffisante')
        
        return HttpResponseForbidden(
            render(request, 'access_denied.html', {
                'document': document,
                'required_level': document.get_classification_level_display()
            })
        )
    
    # Log successful access
    log_access(document, request.user, 'view', request, True, 
              f'Viewed {document.get_classification_level_display()} document')
    document.last_accessed = timezone.now()
    document.save()
    
    # Get access logs for this document
    recent_logs = AccessLog.objects.filter(document=document).order_by('-timestamp')[:10]
    
    context = {
        'document': document,
        'recent_logs': recent_logs,
        'can_download': can_view_document(request.user, document),
        'user_can_view': True,
    }
    
    return render(request, 'document_detail.html', context)


@login_required
def document_download_view(request, document_id):
    """Secure document download with on-the-fly decryption"""
    document = get_object_or_404(Document, id=document_id)
    
    # Verify access selon niveau de classification
    if not can_view_document(request.user, document):
        log_access(document, request.user, 'download', request, False, 
                   f'Download denied - Classification {document.get_classification_level_display()}')
        messages.error(request, '❌ Téléchargement refusé : Habilitation insuffisante')
        return HttpResponseForbidden('Accès refusé')
    
    try:
        # Decrypt file
        encryptor = EncryptionManager()
        decrypted_content = encryptor.decrypt_file(
            document.file_path, 
            document.classification_level
        )
        
        # Log download
        log_access(document, request.user, 'download', request, True, 
                   f'Document {document.get_classification_level_display()} decrypted and downloaded')
        
        # Stream to browser
        response = HttpResponse(
            decrypted_content,
            content_type=document.mime_type
        )
        
        # Set headers for inline viewing
        response['Content-Disposition'] = f'inline; filename="{document.original_filename}"'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        
        return response
        
    except Exception as e:
        log_access(document, request.user, 'download', request, False, 
                   f'Error: {str(e)}')
        messages.error(request, f'❌ Erreur lors de la récupération du document: {str(e)}')
        return HttpResponse('Erreur lors de la récupération du document', status=500)


@login_required
def document_list_view(request):
    """Liste tous les documents accessibles par l'utilisateur"""
    
    # Tous les documents approuvés
    all_documents = Document.objects.filter(status='approved').order_by('-uploaded_at')
    
    # Filtrer selon les permissions
    visible_documents = [
        doc for doc in all_documents 
        if can_view_document(request.user, doc)
    ]
    
    # Pagination
    paginator = Paginator(visible_documents, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'documents': page_obj,
        'page_obj': page_obj,
        'total_documents': len(visible_documents),
    }
    
    return render(request, 'document_list.html', context)


@login_required
def audit_log_view(request):
    """Vue des logs d'audit avec pagination (réservée aux admins)"""
    if not request.user.is_staff:
        messages.error(request, '❌ Accès refusé : vous devez être administrateur.')
        return redirect('dashboard')

    # Tous les logs, triés du plus récent au plus ancien
    logs_list = AccessLog.objects.all().order_by('-timestamp')

    # Pagination
    paginator = Paginator(logs_list, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'logs': page_obj,
        'page_obj': page_obj,
        'paginator': paginator,
        'is_paginated': page_obj.has_other_pages(),
    }

    return render(request, 'audit_log.html', context)