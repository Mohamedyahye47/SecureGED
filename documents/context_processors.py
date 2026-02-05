"""documents/context_processors.py"""
from documents.models import UserProfile

from documents.models import UserProfile

def global_context(request):
    """
    Context processor global.
    Injecte :
    - Les compteurs de notifications (pour les staffs).
    - Les drapeaux de sécurité (is_approved_user) pour masquer/afficher le menu.
    """
    context = {
        'pending_count': 0,  # Pour Staff Dept
        'superuser_pending_count': 0,  # Pour Superuser
        'is_department_staff': False,
        'is_approved_user': False,  # PAR DÉFAUT : BLOQUÉ
        'user_department_name': ''
    }

    if not request.user.is_authenticated:
        return context

    # 1. CAS SUPERUSER : Toujours approuvé, voit tout
    if request.user.is_superuser:
        context['is_approved_user'] = True
        context['is_department_staff'] = True  # Pour voir les menus d'admin

        # Compteur global pour le superuser
        context['superuser_pending_count'] = UserProfile.objects.filter(
            approval_status=UserProfile.ApprovalStatus.PENDING
        ).count()
        return context

    # 2. CAS UTILISATEUR STANDARD
    try:
        profile = UserProfile.objects.get(user=request.user)

        # Vérification critique : Est-ce que le compte est validé ?
        context['is_approved_user'] = profile.is_approved()
        context['is_department_staff'] = profile.is_department_staff

        if profile.department:
            # Affichage du nom du département avec mention si en attente
            if profile.approval_status == UserProfile.ApprovalStatus.PENDING:
                context['user_department_name'] = f"{profile.department.name} (En attente)"
            else:
                context['user_department_name'] = profile.department.name

            # Si c'est un staff, on compte les demandes de SON département
            if profile.is_department_staff:
                context['pending_count'] = UserProfile.objects.filter(
                    department=profile.department,
                    approval_status=UserProfile.ApprovalStatus.PENDING
                ).count()

    except UserProfile.DoesNotExist:
        pass

    return context