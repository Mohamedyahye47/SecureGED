# documents/profile_completion_middleware.py

from django.shortcuts import redirect
from .models import UserProfile

class ProfileCompletionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.allowed_paths = [
            '/auth/complete-profile/',
            '/auth/pending-approval/',
            '/logout/',
            '/admin/',
            '/static/',
            '/media/',
            '/favicon.ico',
        ]

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        # 1. Superuser passe toujours
        if request.user.is_superuser:
            return self.get_response(request)

        try:
            profile = request.user.profile
        except UserProfile.DoesNotExist:
            return self.get_response(request)

        # 2. Staff : Passe-droit (car ils ont forcément un département défini à la création)
        if profile.is_department_staff:
            return self.get_response(request)

        # Vérification des URLs autorisées pour éviter les boucles
        current_path = request.path
        if any(current_path.startswith(path) for path in self.allowed_paths):
            return self.get_response(request)

        # ==============================================================================
        # ✅ CORRECTION PRIORITAIRE :
        # On vérifie le DÉPARTEMENT AVANT le statut.
        # Si un user est "Approved" mais n'a pas de département, il est bloqué ICI.
        # ==============================================================================
        if profile.is_oauth_user and not profile.department:
             return redirect('complete_oauth_profile')

        # 3. Ensuite, on vérifie le statut
        status = str(profile.approval_status).upper()
        if status != 'APPROVED':
            return redirect('profile_pending_approval')

        return self.get_response(request)