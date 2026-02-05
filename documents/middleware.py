# documents/middleware.py

from django.shortcuts import redirect
from django.urls import reverse


class RestrictAdminMiddleware:
    """
    Empêche l'accès à /admin/ pour tout le monde sauf le Superuser.
    Redirige les curieux vers le tableau de bord.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Si l'URL commence par /admin/ et que l'utilisateur n'est PAS superuser
        if request.path.startswith('/admin/'):
            if request.user.is_authenticated and not request.user.is_superuser:
                return redirect('dashboard')

        return self.get_response(request)