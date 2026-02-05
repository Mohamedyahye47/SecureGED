"""documents/forms.py"""
from django import forms
from django.contrib.auth.models import User
from .models import Document, Department, UserProfile

# ---------------------------
# LOGIN FORM
# ---------------------------
class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        label="Nom d'utilisateur",
        widget=forms.TextInput(attrs={"autocomplete": "username", "class": "form-control"})
    )
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "class": "form-control"})
    )

# ---------------------------
# DOCUMENT UPLOAD FORM
# ---------------------------
class DocumentUploadForm(forms.Form):
    title = forms.CharField(
        max_length=255,
        label="Titre du document",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ex: Procédure interne...'})
    )
    description = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 3, 'class': 'form-control', 'placeholder': 'Description du contenu...'}),
        required=False,
        label="Description"
    )
    file = forms.FileField(
        label="Fichier",
        widget=forms.FileInput(attrs={'class': 'form-control'})
    )
    classification_level = forms.ChoiceField(
        choices=[
            (k, v) for k, v in Document.Classification.choices
            if k != Document.Classification.PERSONAL
        ],
        label="Niveau de confidentialité",
        help_text="Public : Tout le monde. Interne : Votre département. Secret : Staff du département.",
        widget=forms.Select(attrs={'class': 'form-select'})
    )

# ---------------------------
# PRIVATE MESSAGE FORM
# ---------------------------
class PrivateMessageForm(forms.Form):
    recipient = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="Destinataire",
        widget=forms.Select(attrs={'class': 'form-select'}),
        empty_label="-- Choisir un collègue --"
    )
    subject = forms.CharField(
        max_length=200,
        label="Sujet / Titre",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ex: Dossier confidentiel...'})
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4, 'placeholder': 'Votre message...'}),
        label="Message",
        required=False
    )
    file = forms.FileField(
        label="Pièce jointe (Optionnel)",
        required=False,
        widget=forms.FileInput(attrs={'class': 'form-control'}),
        help_text="Ce fichier sera classé 'Personnel' et visible uniquement par le destinataire."
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            self.fields['recipient'].queryset = User.objects.filter(
                is_active=True,
                is_superuser=False
            ).exclude(id=user.id).order_by('last_name', 'first_name')

# ---------------------------
# ✅ USER PROFILE FORM (SÉCURISÉ)
# ---------------------------
class UserProfileForm(forms.ModelForm):
    """
    Permet à l'utilisateur de compléter son profil.
    SÉCURITÉ : Le département est verrouillé une fois choisi.
    """
    first_name = forms.CharField(
        label="Prénom",
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    last_name = forms.CharField(
        label="Nom",
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )

    # On définit le champ ici pour forcer le widget et le required=True pour les nouveaux
    department = forms.ModelChoiceField(
        queryset=Department.objects.all(),
        required=True,
        empty_label="-- Sélectionnez votre département --",
        label="Département / Service",
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    class Meta:
        model = UserProfile
        fields = ['department', 'profile_picture']
        labels = {
            'profile_picture': 'Photo de profil'
        }
        widgets = {
            'profile_picture': forms.FileInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.instance and self.instance.pk:
            # 1. Pré-remplissage des champs User (Prénom/Nom)
            self.fields['first_name'].initial = self.instance.user.first_name
            self.fields['last_name'].initial = self.instance.user.last_name

            # 2. SÉCURITÉ : BLOQUER LE DÉPARTEMENT SI DÉJÀ DÉFINI
            # Si l'utilisateur a déjà un département (il n'est pas None), on désactive le champ.
            if self.instance.department:
                self.fields['department'].disabled = True
                self.fields['department'].required = False  # Pas requis car déjà en base
                self.fields['department'].help_text = "🔒 Département verrouillé. Contactez l'administrateur pour changer."