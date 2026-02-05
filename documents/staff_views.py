from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.http import require_POST
from .models import UserProfile, Department, DepartmentMessage


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

    # Liste des demandes PENDING du département
    pending_requests = UserProfile.objects.filter(
        department=staff_profile.department,
        approval_status=UserProfile.ApprovalStatus.PENDING
    ).select_related('user')

    return render(request, 'staff/pending_requests.html', {
        'department': staff_profile.department,
        'pending_requests': pending_requests,
    })


# =========================================================
# 2. ACTIONS (APPROUVER) - ✅ CORRIGÉ
# =========================================================
@login_required
@require_POST
def approve_user_view(request, user_id):
    """✅ CORRECTION : Triple sécurité pour l'approbation"""
    staff_profile = request.user.profile
    if not staff_profile.is_department_staff:
        return redirect('dashboard')

    target_user = get_object_or_404(User, id=user_id)
    target_profile = target_user.profile

    # Vérification département
    if target_profile.department != staff_profile.department:
        messages.error(request, "Cet utilisateur n'est pas lié à votre département.")
        return redirect('pending_requests')

    # ✅ MÉTHODE 1 : Via Enum
    target_profile.approval_status = UserProfile.ApprovalStatus.APPROVED
    target_profile.approved_by = request.user
    target_profile.save()

    # ✅ MÉTHODE 2 : Update SQL direct (sécurité supplémentaire)
    UserProfile.objects.filter(user=target_user).update(
        approval_status='APPROVED'
    )

    # ✅ MÉTHODE 3 : Vérification immédiate
    target_profile.refresh_from_db()
    if target_profile.approval_status != UserProfile.ApprovalStatus.APPROVED:
        # Si ça a échoué, on force brutalement
        target_profile.approval_status = UserProfile.ApprovalStatus.APPROVED
        target_profile.save(update_fields=['approval_status'])

    # ✅ Activation du compte utilisateur
    if not target_user.is_active:
        target_user.is_active = True
        target_user.save()

    # Email de confirmation
    try:
        site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')
        send_mail(
            subject="✅ Compte Validé - Secure GED",
            message=f"""Bonjour {target_user.first_name},

Bonne nouvelle ! Votre compte a été validé par {request.user.get_full_name()}.

Département : {staff_profile.department.name}
Vous pouvez maintenant accéder à tous les services de la plateforme GED.

Connexion : {site_url}

Cordialement,
L'équipe SecureGED
""",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[target_user.email],
            fail_silently=True
        )
    except Exception as e:
        # On ne bloque pas si l'email échoue
        print(f"Erreur envoi email: {e}")

    messages.success(
        request,
        f"✅ Utilisateur {target_user.username} approuvé avec succès ! "
        f"Il peut maintenant se connecter."
    )
    return redirect('pending_requests')


# =========================================================
# 3. ACTIONS (REJETER)
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

    # Rejet
    target_profile.approval_status = UserProfile.ApprovalStatus.REJECTED
    target_profile.save()

    # Désactivation du compte
    target_user.is_active = False
    target_user.save()

    # Email de notification
    try:
        send_mail(
            subject="❌ Demande d'accès refusée - Secure GED",
            message=f"""Bonjour {target_user.first_name},

Votre demande d'accès au département {staff_profile.department.name} n'a pas été acceptée.

Pour plus d'informations, veuillez contacter le responsable de votre département.

Cordialement,
L'équipe SecureGED
""",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[target_user.email],
            fail_silently=True
        )
    except Exception:
        pass

    messages.warning(request, f"❌ Utilisateur {target_user.username} rejeté.")
    return redirect('pending_requests')


# =========================================================
# 4. GESTION DÉPARTEMENT
# =========================================================

@login_required
def department_users_view(request):
    profile = request.user.profile
    if not profile.is_department_staff:
        return redirect('dashboard')

    users = User.objects.filter(
        profile__department=profile.department
    ).exclude(id=request.user.id).select_related('profile')

    return render(request, 'staff/department_users.html', {
        'department': profile.department,
        'active_users': users.filter(profile__approval_status=UserProfile.ApprovalStatus.APPROVED),
        'pending_users': users.filter(profile__approval_status=UserProfile.ApprovalStatus.PENDING)
    })


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


# =========================================================
# 5. DEBUG (À SUPPRIMER EN PRODUCTION)
# =========================================================
def debug_db_view(request):
    """Vue de diagnostic - À supprimer en production"""
    from django.http import HttpResponse
    from .models import UserProfile

    html = "<h1>Diagnostic Global des Profils</h1><ul>"
    all_profiles = UserProfile.objects.all().select_related('user', 'department')

    for p in all_profiles:
        html += f"""<li>
            User: <b>{p.user.username}</b> | 
            Statut en base: <span style="color:red">"{p.approval_status}"</span> | 
            Département: {p.department.name if p.department else 'Aucun'} |
            is_active: {p.user.is_active}
        </li>"""

    html += "</ul><p>Vérifiez si le statut est exactement 'APPROVED' (majuscules).</p>"
    return HttpResponse(html)