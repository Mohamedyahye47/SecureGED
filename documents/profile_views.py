# documents/profile_views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.db import transaction
from django.core.mail import send_mail
from django.conf import settings
import random
import string

# Assurez-vous que le formulaire existe
from .forms import UserProfileForm
from .models import UserProfile, Document, Department


# ============================================
# 1. DÉCORATEURS & UTILITAIRES
# ============================================

def is_manager_check(user):
    """
    Autorise :
    1. Le SuperUser (Administrateur global)
    2. Le Staff (Responsable de département)
    """
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True

    try:
        # Il faut être Staff ET avoir un département
        return user.profile.is_department_staff and user.profile.department is not None
    except:
        return False


# =================================
# 2. VUES PERSONNELLES (Mon Profil)
# ============================================

@login_required
def user_profile_view(request):
    """
    Mon profil.
    Intègre une AUTO-RÉPARATION pour débloquer les Staffs coincés.
    """
    profile, created = UserProfile.objects.get_or_create(user=request.user)

    # --- AUTO-CORRECTION DES STAFFS ---
    # Si je suis Staff mais que mon statut n'est pas "APPROVED", je me débloque tout seul.
    if profile.is_department_staff and profile.approval_status != UserProfile.ApprovalStatus.APPROVED:
        profile.approval_status = UserProfile.ApprovalStatus.APPROVED
        profile.save(update_fields=['approval_status'])

    # Variable pour le template
    is_approved = (
            profile.approval_status == UserProfile.ApprovalStatus.APPROVED
            or profile.is_department_staff
    )

    missing_info = (profile.department is None)

    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            # Mise à jour User standard
            user = request.user
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.save()
            messages.success(request, "✅ Profil mis à jour.")
            return redirect('dashboard')
    else:
        form = UserProfileForm(instance=profile)

    return render(request, 'user_profile.html', {
        'form': form,
        'profile': profile,
        'missing_info': missing_info,
        'is_approved': is_approved
    })


@login_required
def change_password_view(request):
    """Changer mon mot de passe"""
    if request.method == 'POST':
        new_pass = request.POST.get('new_password1')
        confirm_pass = request.POST.get('new_password2')
        if new_pass == confirm_pass and len(new_pass) >= 8:
            request.user.set_password(new_pass)
            request.user.save()
            update_session_auth_hash(request, request.user)
            messages.success(request, "✅ Mot de passe modifié.")
        else:
            messages.error(request, "❌ Les mots de passe ne correspondent pas ou sont trop courts.")
    return redirect('user_profile')


# ============================================
# 3. GESTION UTILISATEURS (HIÉRARCHIQUE)
# ============================================

@login_required
@user_passes_test(is_manager_check)
def users_management_view(request):
    """
    AFFICHE LA LISTE :
    - SuperUser -> Voit uniquement les STAFFS (Chefs).
    - Staff -> Voit uniquement les UTILISATEURS de son département.
    """
    try:
        if request.user.is_superuser:
            # LE SUPERUSER NE VOIT QUE LES CHEFS
            users = User.objects.filter(profile__is_department_staff=True).exclude(id=request.user.id).order_by(
                'profile__department')
            department_name = "Super Admin (Vue des Chefs de Service)"
        else:
            # LE STAFF VOIT SES EMPLOYÉS (Pas les autres staffs)
            my_dept = request.user.profile.department
            users = User.objects.filter(profile__department=my_dept, profile__is_department_staff=False).order_by(
                '-date_joined')
            department_name = f"Département : {my_dept.name}"
    except:
        return redirect('dashboard')

    # Action de suppression/désactivation
    if request.method == 'POST' and request.POST.get('action') == 'delete_user':
        try:
            u = User.objects.get(id=request.POST.get('user_id'))
            # Sécurité : Un Staff ne peut pas supprimer un SuperUser
            if not u.is_superuser:
                u.is_active = False
                u.save()
                messages.success(request, f"🚫 Utilisateur {u.username} désactivé.")
        except:
            pass

    return render(request, 'users_management.html', {'users': users, 'department': department_name})


# ============================================
# 4. CRÉATION UTILISATEUR (VALIDATION FORCÉE)
# ============================================

@login_required
@user_passes_test(is_manager_check)
def create_user_view(request):
    """
    CRÉATION STRICTE :
    - SuperUser -> Crée un STAFF (et choisit le département).
    - Staff -> Crée un USER STANDARD (dans son département).
    - TOUS SONT 'APPROVED' IMMÉDIATEMENT.
    """

    # --- 1. DÉTERMINATION DU RÔLE ET DU DÉPARTEMENT ---
    departments = None
    target_department = None
    is_creating_staff = False
    role_label = ""

    if request.user.is_superuser:
        # SuperUser : Crée un Staff, doit choisir le département
        departments = Department.objects.all()
        is_creating_staff = True
        role_label = "Responsable (Staff)"
        if not departments.exists():
            messages.error(request, "⚠️ Créez d'abord un département via l'admin Django.")
            return redirect('dashboard')
    else:
        # Staff : Crée un User, département fixé
        target_department = request.user.profile.department
        is_creating_staff = False
        role_label = "Collaborateur"

    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')

        # Si SuperUser, on récupère le département choisi dans le select
        if request.user.is_superuser:
            dept_id = request.POST.get('department')
            if dept_id:
                target_department = Department.objects.get(id=dept_id)
            else:
                messages.error(request, "❌ Le département est obligatoire.")
                return render(request, 'create_user.html', {'departments': departments, 'role_label': role_label})

        # Vérification doublon
        if User.objects.filter(username=username).exists():
            messages.error(request, f"❌ L'utilisateur '{username}' existe déjà.")
            return render(request, 'create_user.html', {'departments': departments, 'role_label': role_label})

        try:
            with transaction.atomic():
                # A. Création User Django
                user = User.objects.create_user(
                    username=username, email=email, password=password,
                    first_name=first_name, last_name=last_name
                )
                user.save()

                # B. Création Profil FORCÉE APPROUVÉE
                # On utilise .value pour éviter les soucis d'Enum
                status_approved = UserProfile.ApprovalStatus.APPROVED.value

                UserProfile.objects.create(
                    user=user,
                    department=target_department,
                    is_department_staff=is_creating_staff,
                    phone="",
                    approval_status=status_approved,  # <--- CLÉ DU SUCCÈS
                    approved_by=request.user
                )

                # C. Notification Email
                try:
                    site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')
                    send_mail(
                        subject=f"Bienvenue - Compte {role_label} créé",
                        message=(
                            f"Bonjour {first_name},\n\n"
                            f"Votre compte a été créé et validé automatiquement.\n\n"
                            f"Rôle : {role_label}\n"
                            f"Identifiant : {username}\n"
                            f"Mot de passe : {password}\n\n"
                            f"Connectez-vous ici : {site_url}/login/"
                        ),
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=True
                    )
                    notif_msg = "+ Email envoyé"
                except:
                    notif_msg = "(Email non configuré)"

            messages.success(request, f"✅ {role_label} '{username}' créé et activé immédiatement {notif_msg}.")
            return redirect('admin_users')

        except Exception as e:
            messages.error(request, f"❌ Erreur technique : {str(e)}")

    return render(request, 'create_user.html', {
        'departments': departments,
        'target_department': target_department,
        'role_label': role_label,
        'is_superuser': request.user.is_superuser
    })