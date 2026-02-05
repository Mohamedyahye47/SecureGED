"""
documents/staff_views.py - ✅ VERSION SIMPLIFIÉE SANS approved_by
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.http import require_POST
from django.db import transaction

from .models import UserProfile, Department, DepartmentMessage
from .forms import StaffUserCreationForm


# =========================================================
# 1. LISTE DES DEMANDES
# =========================================================
@login_required
def pending_requests_view(request):
    try:
        staff_profile = request.user.profile
    except UserProfile.DoesNotExist:
        messages.error(request, "Profil introuvable.")
        return redirect('dashboard')

    if not staff_profile.is_department_staff or not staff_profile.department:
        messages.error(request, "Accès réservé aux responsables.")
        return redirect('dashboard')

    pending_requests = UserProfile.objects.filter(
        department=staff_profile.department,
        approval_status='PENDING'
    ).select_related('user')

    return render(request, 'staff/pending_requests.html', {
        'department': staff_profile.department,
        'pending_requests': pending_requests,
    })


# =========================================================
# 2. APPROUVER UN UTILISATEUR (SIMPLIFIÉ)
# =========================================================
@login_required
@require_POST
def approve_user_view(request, user_id):
    """✅ Approuve un utilisateur - TRIPLE SÉCURITÉ"""

    staff_profile = request.user.profile
    if not staff_profile.is_department_staff:
        return redirect('dashboard')

    target_user = get_object_or_404(User, id=user_id)
    target_profile = target_user.profile

    # Vérification département
    if target_profile.department != staff_profile.department:
        messages.error(request, "Cet utilisateur n'est pas lié à votre département.")
        return redirect('pending_requests')

    # ✅ TRIPLE SÉCURITÉ
    with transaction.atomic():
        # Méthode 1 : Via le profil
        target_profile.approval_status = 'APPROVED'
        target_profile.save()

        # Méthode 2 : Update SQL direct
        UserProfile.objects.filter(user=target_user).update(
            approval_status='APPROVED'
        )

        # Méthode 3 : Activation du compte
        target_user.is_active = True
        target_user.save()

    # Email de confirmation
    try:
        site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')
        send_mail(
            subject="✅ Compte Validé - Secure GED",
            message=f"""Bonjour {target_user.first_name},

Bonne nouvelle ! Votre compte a été validé.

Département : {staff_profile.department.name}
Vous pouvez maintenant vous connecter : {site_url}

Cordialement,
L'équipe SecureGED
""",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[target_user.email],
            fail_silently=True
        )
    except Exception:
        pass

    messages.success(request, f"✅ Utilisateur {target_user.username} approuvé avec succès !")
    return redirect('pending_requests')


# =========================================================
# 3. REJETER UN UTILISATEUR
# =========================================================
@login_required
@require_POST
def reject_user_view(request, user_id):
    staff_profile = request.user.profile
    if not staff_profile.is_department_staff:
        return redirect('dashboard')

    target_user = get_object_or_404(User, id=user_id)
    target_profile = target_user.profile

    if target_profile.department != staff_profile.department:
        return redirect('pending_requests')

    with transaction.atomic():
        target_profile.approval_status = 'REJECTED'
        target_profile.save()

        target_user.is_active = False
        target_user.save()

    messages.warning(request, f"❌ Utilisateur {target_user.username} rejeté.")
    return redirect('pending_requests')


# =========================================================
# 4. LISTE UTILISATEURS DU DÉPARTEMENT
# =========================================================
@login_required
def department_users_view(request):
    profile = request.user.profile
    if not profile.is_department_staff:
        return redirect('dashboard')

    users = User.objects.filter(
        profile__department=profile.department
    ).exclude(id=request.user.id).select_related('profile').order_by('-date_joined')

    return render(request, 'staff/department_users.html', {
        'department': profile.department,
        'users': users,
    })


# =========================================================
# 5. CRÉER UN UTILISATEUR (✅ APPROUVÉ AUTOMATIQUEMENT)
# =========================================================
@login_required
def create_department_user_view(request):
    """
    Permet au Staff de créer un utilisateur DIRECTEMENT APPROUVÉ.
    PAS BESOIN D'APPROBATION MANUELLE APRÈS.
    """
    try:
        staff_profile = request.user.profile
        if not staff_profile.is_department_staff or not staff_profile.department:
            messages.error(request, "Accès refusé.")
            return redirect('dashboard')
    except:
        return redirect('dashboard')

    if request.method == 'POST':
        form = StaffUserCreationForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data

            try:
                with transaction.atomic():
                    # 1. Créer l'utilisateur Django
                    new_user = User.objects.create_user(
                        username=data['email'],  # Email comme username
                        email=data['email'],
                        password=data['password'],
                        first_name=data['first_name'],
                        last_name=data['last_name']
                    )
                    new_user.is_active = True  # ✅ Actif immédiatement
                    new_user.save()

                    # 2. Créer le profil (ou récupérer s'il existe)
                    profile, created = UserProfile.objects.get_or_create(user=new_user)

                    # 3. ✅ CONFIGURATION COMPLÈTE - APPROUVÉ DIRECTEMENT
                    profile.department = staff_profile.department
                    profile.approval_status = 'APPROVED'  # ✅ PAS DE PENDING !
                    profile.is_department_staff = False
                    profile.is_oauth_user = False
                    profile.save()

                    # 4. Double sécurité SQL
                    UserProfile.objects.filter(user=new_user).update(
                        approval_status='APPROVED',
                        department=staff_profile.department
                    )

                messages.success(
                    request,
                    f"✅ Utilisateur {data['first_name']} {data['last_name']} créé et approuvé ! "
                    f"Il peut se connecter immédiatement."
                )
                return redirect('admin_users')

            except Exception as e:
                messages.error(request, f"❌ Erreur technique : {e}")
    else:
        form = StaffUserCreationForm()

    return render(request, 'staff_create_user.html', {
        'form': form,
        'department': staff_profile.department
    })


# =========================================================
# 6. CONTACT & MESSAGERIE
# =========================================================
@login_required
def contact_department_staff_view(request):
    profile = request.user.profile
    department = profile.department

    if not department:
        messages.error(request, "Aucun département associé.")
        return redirect('dashboard')

    if request.method == 'POST':
        subject = request.POST.get('subject')
        message_content = request.POST.get('message')

        DepartmentMessage.objects.create(
            department=department,
            sender=request.user,
            subject=subject,
            message=message_content
        )
        messages.success(request, "✅ Message envoyé aux responsables.")
        return redirect('dashboard')

    return render(request, 'contact_department_staff.html', {'department': department})


@login_required
def staff_inbox_view(request):
    profile = request.user.profile
    if not profile.is_department_staff:
        return redirect('dashboard')

    messages_list = DepartmentMessage.objects.filter(
        department=profile.department
    ).order_by('-created_at')

    return render(request, 'staff/inbox.html', {
        'department': profile.department,
        'messages_list': messages_list
    })


@login_required
def staff_reply_view(request, message_id):
    profile = request.user.profile
    if not profile.is_department_staff:
        return redirect('dashboard')

    original_msg = get_object_or_404(DepartmentMessage, id=message_id, department=profile.department)
    recipient = original_msg.sender

    if request.method == 'POST':
        subject = request.POST.get('subject')
        content = request.POST.get('message')

        try:
            send_mail(
                f"[Réponse Staff] {subject}",
                content,
                settings.DEFAULT_FROM_EMAIL,
                [recipient.email],
                fail_silently=False
            )
            original_msg.is_read = True
            original_msg.save()
            messages.success(request, "✅ Réponse envoyée.")
            return redirect('staff_inbox')
        except Exception as e:
            messages.error(request, f"❌ Erreur mail: {e}")

    return render(request, 'staff/reply_message.html', {
        'original_msg': original_msg,
        'recipient': recipient,
        'default_subject': f"RE: {original_msg.subject}"
    })


@login_required
def superuser_manage_staffs_view(request):
    if not request.user.is_superuser:
        return redirect('dashboard')

    staffs = User.objects.filter(profile__is_department_staff=True)
    return render(request, 'staff/superuser_manage_staffs.html', {'staffs': staffs})