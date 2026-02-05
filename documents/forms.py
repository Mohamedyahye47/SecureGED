"""documents/forms.py - ✅ AJOUT du formulaire de création utilisateur"""
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
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        label="Message",
        required=False
    )
    file = forms.FileField(
        label="Pièce jointe (Optionnel)",
        required=False,
        widget=forms.FileInput(attrs={'class': 'form-control'})
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
# USER PROFILE FORM
# ---------------------------
class UserProfileForm(forms.ModelForm):
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
        widgets = {
            'profile_picture': forms.FileInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields['first_name'].initial = self.instance.user.first_name
            self.fields['last_name'].initial = self.instance.user.last_name
            if self.instance.department:
                self.fields['department'].disabled = True
                self.fields['department'].required = False


# ---------------------------
# ✅ STAFF USER CREATION FORM
# ---------------------------
class StaffUserCreationForm(forms.Form):
    """
    Formulaire pour que les Staffs créent des utilisateurs dans leur département.
    """
    first_name = forms.CharField(
        max_length=150,
        label="Prénom",
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Prénom de l\'utilisateur'
        })
    )

    last_name = forms.CharField(
        max_length=150,
        label="Nom",
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nom de famille'
        })
    )

    email = forms.EmailField(
        label="Email (utilisé comme identifiant)",
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'utilisateur@domaine.com'
        }),
        help_text="Cet email servira de nom d'utilisateur et de contact."
    )

    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Minimum 8 caractères'
        }),
        min_length=8,
        help_text="Minimum 8 caractères."
    )

    password_confirm = forms.CharField(
        label="Confirmer le mot de passe",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Retapez le mot de passe'
        })
    )

    def clean_email(self):
        """Vérifie que l'email n'existe pas déjà"""
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Cet email est déjà utilisé.")
        return email

    def clean(self):
        """Vérifie que les mots de passe correspondent"""
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')

        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError("Les mots de passe ne correspondent pas.")

        return cleaned_data