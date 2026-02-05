# documents/auth_views.py

import logging
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.conf import settings
import logging
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import UserProfile, Department
from .oauth import GoogleOAuthManager
from .forms import LoginForm
from .models import UserProfile, Department
from .oauth import GoogleOAuthManager

logger = logging.getLogger(__name__)


def login_view(request):
    """
    Connexion : Redirection DIRECTE pour les Staffs.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)

            if user:
                if not user.is_active:
                    messages.error(request, "Compte désactivé.")
                    return redirect('login')

                login(request, user)

                # --- LOGIQUE DE REDIRECTION ---
                try:
                    profile = user.profile

                    # 1. SI C'EST UN STAFF -> DASHBOARD DIRECT
                    # (On ne regarde même pas le statut approval, on fait confiance au rôle)
                    if profile.is_department_staff:
                        # Auto-réparation silencieuse si nécessaire
                        if profile.approval_status != 'APPROVED':
                            profile.approval_status = 'APPROVED'
                            profile.save()
                        return redirect('dashboard')

                    # 2. Si Utilisateur Standard Approuvé -> Dashboard
                    if profile.approval_status == 'APPROVED':
                        return redirect('dashboard')

                    # 3. Sinon -> Pending
                    return redirect('profile_pending_approval')

                except Exception:
                    # Pas de profil ? Dashboard par défaut
                    return redirect('dashboard')
            else:
                messages.error(request, "Identifiants incorrects.")
    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})

def google_login_view(request):
    """Redirige vers Google OAuth"""
    manager = GoogleOAuthManager()
    auth_url = manager.get_authorization_url(request)
    return redirect(auth_url)


def google_callback_view(request):
    """
    Callback OAuth Google.
    Gère la connexion et redirige intelligemment selon le rôle (Staff ou User).
    """
    code = request.GET.get("code")

    if not code:
        error = request.GET.get("error", "Autorisation refusée")
        messages.error(request, f"❌ Connexion Google échouée: {error}")
        return redirect("login")

    try:
        # 1. Échange du code
        manager = GoogleOAuthManager()
        token_response = manager.exchange_code_for_token(request, code)

        if "error" in token_response:
            logger.error(f"OAuth token error: {token_response['error']}")
            messages.error(request, f"❌ {token_response['error']}")
            return redirect("login")

        access_token = token_response.get("access_token")

        # 2. Infos utilisateur
        user_info = manager.get_user_info(access_token)

        if "error" in user_info:
            logger.error(f"OAuth userinfo error: {user_info['error']}")
            messages.error(request, f"❌ {user_info['error']}")
            return redirect("login")

        # 3. Données
        google_id = user_info.get("sub")
        email = user_info.get("email")
        first_name = user_info.get("given_name", "")
        last_name = user_info.get("family_name", "")

        if not google_id or not email:
            messages.error(request, "❌ Informations utilisateur incomplètes")
            return redirect("login")

        # 4. Recherche ou Création
        created = False
        try:
            profile = UserProfile.objects.get(google_id=google_id)
            user = profile.user
        except UserProfile.DoesNotExist:
            try:
                user = User.objects.get(email=email)
                profile = user.profile
                profile.is_oauth_user = True
                profile.google_id = google_id
                profile.save()
            except User.DoesNotExist:
                # Création nouveau compte
                username = email.split('@')[0]
                # Gestion collision username
                counter = 1
                while User.objects.filter(username=username).exists():
                    username = f"{email.split('@')[0]}{counter}"
                    counter += 1

                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name
                )
                user.set_unusable_password()
                user.save()

                profile, _ = UserProfile.objects.get_or_create(user=user)
                profile.is_oauth_user = True
                profile.google_id = google_id
                # Par défaut PENDING
                profile.approval_status = UserProfile.ApprovalStatus.PENDING
                profile.save()
                created = True

        # 5. Login
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')

        # 6. Vérification des champs requis
        is_incomplete = (
                not user.first_name or
                not user.last_name or
                not profile.department
        )

        # === LOGIQUE DE REDIRECTION (C'est ici que ça se joue) ===

        # Cas 1 : Infos incomplètes (Nouveau ou Manquant)
        if created or is_incomplete:
            messages.info(request, f"👋 Bienvenue {user.first_name} ! Veuillez compléter votre profil.")
            return redirect('complete_oauth_profile')

        # Cas 2 : C'est un STAFF -> PRIORITÉ ABSOLUE
        # On ignore le statut PENDING pour le staff, on l'approuve et on le laisse passer.
        elif profile.is_department_staff:
            if profile.approval_status != UserProfile.ApprovalStatus.APPROVED:
                profile.approval_status = UserProfile.ApprovalStatus.APPROVED
                profile.save()
            return redirect('dashboard')

        # Cas 3 : Utilisateur normal EN ATTENTE
        elif profile.approval_status == UserProfile.ApprovalStatus.PENDING:
            messages.warning(request, "⏳ Votre compte est en attente d'approbation.")
            return redirect('profile_pending_approval')

        # Cas 4 : Rejeté
        elif profile.approval_status == UserProfile.ApprovalStatus.REJECTED:
            messages.error(request, "❌ Accès refusé.")
            return redirect('login')

        # Cas 5 : Tout est bon
        else:
            messages.success(request, f"✅ Bon retour {user.first_name} !")
            return redirect('dashboard')

    except Exception as e:
        logger.error(f"OAuth callback error: {e}", exc_info=True)
        messages.error(request, f"❌ Erreur inattendue: {str(e)}")
        return redirect('login')


# documents/auth_views.py (Extrait de la fonction complete_oauth_profile_view)

@login_required
def complete_oauth_profile_view(request):
    """
    Force l'utilisateur à choisir un département.
    """
    if request.user.is_superuser:
        return redirect('dashboard')

    profile = request.user.profile

    # Si l'utilisateur a déjà un département, on l'éjecte vers la suite logique
    if profile.department:
        if profile.approval_status == 'APPROVED':
            return redirect('dashboard')
        return redirect('profile_pending_approval')

    if request.method == 'POST':
        department_id = request.POST.get('department')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')

        if department_id:
            try:
                dept = Department.objects.get(id=department_id)

                # 1. Mise à jour User
                user = request.user
                user.first_name = first_name
                user.last_name = last_name
                user.save()

                # 2. Mise à jour Profil
                profile.department = dept

                # ✅ IMPORTANT : On le met en PENDING pour qu'il apparaisse chez le Staff
                # On force la MAJUSCULE pour éviter les bugs de filtre
                profile.approval_status = 'PENDING'

                profile.save()

                messages.success(request, "✅ Profil complété. En attente de validation.")
                return redirect('profile_pending_approval')

            except Department.DoesNotExist:
                messages.error(request, "Département invalide.")
        else:
            messages.error(request, "Veuillez choisir un département.")

    departments = Department.objects.all()
    return render(request, 'complete_oauth_profile.html', {
        'departments': departments,
        'profile': profile
    })

@login_required
def profile_pending_approval_view(request):
    """
    Page d'attente pour les utilisateurs PENDING.
    CORRECTION MAJEURE : Vérifie si c'est un Staff pour le débloquer.
    """
    if request.user.is_superuser:
        return redirect('admin:index')

    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        return redirect('complete_oauth_profile')

    # === DÉBLOCAGE DU STAFF ===
    # Si par erreur un staff arrive ici, on corrige son statut et on le redirige.
    if profile.is_department_staff:
        if profile.approval_status != UserProfile.ApprovalStatus.APPROVED:
            profile.approval_status = UserProfile.ApprovalStatus.APPROVED
            profile.save()
        return redirect('dashboard')
    # ==========================

    # Si déjà approuvé
    if profile.approval_status == UserProfile.ApprovalStatus.APPROVED:
        return redirect('dashboard')

    context = {
        'profile': profile,
        'department': profile.department,
    }
    return render(request, 'profile_pending_approval.html', context)


def password_reset_request_view(request):
    return render(request, 'password_reset_request.html')


def password_reset_confirm_view(request, uidb64, token):
    return render(request, 'password_reset_confirm.html')