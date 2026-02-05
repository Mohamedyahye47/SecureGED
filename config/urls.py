from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),

    # AJOUTEZ CETTE LIGNE (Elle active : reset password, login, logout, etc.)
    path('accounts/', include('django.contrib.auth.urls')),

    path('', include('documents.urls')),

    # Catch all (Gardez ceci à la fin)
    path('404/', RedirectView.as_view(url='/', permanent=False)),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)