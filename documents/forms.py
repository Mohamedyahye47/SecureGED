"""
Django Forms for Secure GED
"""
from django import forms
from django.contrib.auth.models import User
from .models import Document


class LoginForm(forms.Form):
    """Secure login form"""
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nom d\'utilisateur',
            'autocomplete': 'username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe',
            'autocomplete': 'current-password'
        })
    )


class DocumentUploadForm(forms.Form):
    """Document upload form with validation"""
    title = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Titre du document'
        })
    )
    
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'placeholder': 'Description (optionnelle)',
            'rows': 3
        })
    )
    
    classification_level = forms.ChoiceField(
        choices=Document.CLASSIFICATION_LEVELS,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )
    
    file = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.docx,.doc,.jpg,.jpeg,.png'
        })
    )
    
    def clean_classification_level(self):
        level = int(self.cleaned_data['classification_level'])
        return level