from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User, Group
from .models import Department, UserProfile

# On retire les groupes
admin.site.unregister(Group)


# ========================================== #
# 1. GESTION DES DÉPARTEMENTS
# ========================================== #
@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at', 'created_by')
    fields = ('name',)

    def save_model(self, request, obj, form, change):
        if not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


# ========================================== #
# 2. INLINE (Sélection du département)
# ========================================== #
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name = "Affectation"
    verbose_name_plural = "Département d'affectation"

    # On affiche uniquement le menu déroulant du département
    fields = ('department',)

    # Note : On a déplacé la logique de validation dans le parent (UserAdmin)
    # pour être sûr à 100% qu'elle s'applique en dernier.


# ========================================== #
# 3. FORMULAIRE SPÉCIFIQUE (Email Requis)
# ========================================== #
class CustomUserForm(forms.ModelForm):
    """
    On surcharge le formulaire pour rendre l'email OBLIGATOIRE.
    """
    email = forms.EmailField(required=True, label="Adresse électronique")

    class Meta:
        model = User
        fields = '__all__'


# ========================================== #
# 4. INTERFACE SUPERUSER BLINDÉE
# ========================================== #
class CustomUserAdmin(UserAdmin):
    form = CustomUserForm
    inlines = (UserProfileInline,)

    # Colonnes du tableau
    list_display = ('username', 'email', 'get_department', 'is_active', 'get_status')
    list_filter = ('profile__department', 'is_active')

    # --- FORMULAIRE D'ÉDITION ---
    fieldsets = (
        ('Identifiants', {'fields': ('username', 'password')}),
        ('Informations personnelles', {'fields': ('email',)}),
    )

    # --- AUTOMATISME 1 : ACTIVATION DU COMPTE USER ---
    def save_model(self, request, obj, form, change):
        # Force le compte Django à être ACTIF par défaut
        if not change:
            obj.is_active = True
        super().save_model(request, obj, form, change)

    # --- AUTOMATISME 2 : FORÇAGE DU PROFIL (LE VERROU) ---
    def save_related(self, request, form, formsets, change):
        """
        Cette méthode est appelée APRÈS que le User et l'Inline (Département) soient sauvés.
        C'est ici qu'on force le statut APPROVED et STAFF.
        """
        super().save_related(request, form, formsets, change)

        # On récupère l'instance User qui vient d'être sauvée
        user = form.instance

        try:
            # On s'assure que le profil existe et on le met à jour
            if hasattr(user, 'profile'):
                profile = user.profile

                # FORCE BRUTE : On écrase toute valeur précédente
                profile.is_department_staff = True
                profile.approval_status = 'APPROVED'  # Toujours en MAJUSCULE

                profile.save()
        except Exception as e:
            # Sécurité au cas où le profil n'existe pas encore (peu probable)
            pass

    # --- AFFICHAGE ---
    def get_department(self, obj):
        return obj.profile.department.name if hasattr(obj, 'profile') and obj.profile.department else "-"

    get_department.short_description = "Département"

    def get_status(self, obj):
        return obj.profile.approval_status if hasattr(obj, 'profile') else "-"

    get_status.short_description = "Statut Profil"


# Ré-enregistrement
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)