from django.contrib import admin
from django.urls import path, include # N'oublie pas d'importer include

urlpatterns = [
    path('admin/', admin.site.urls),
    # On lie la racine du site à ton fichier d'URLs secondaire
    path('', include('documents.urls')), 
]