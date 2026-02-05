"""
documents/urls.py

✅ ROUTES SANS QUARANTAINE VISIBLE
Le scan antivirus est automatique, pas d'interface de quarantaine
"""

from django.urls import path
from . import views, profile_views, auth_views, staff_views
from .views import manage_users_view

urlpatterns = [
    # ============================================
    # PUBLIC
    # ============================================
    path('', views.public_documents_view, name='public_documents'),

    # ============================================
    # AUTHENTIFICATION
    # ============================================
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # OAuth Google
    path('auth/google/login/', auth_views.google_login_view, name='google_login'),
    path('auth/google/callback/', auth_views.google_callback_view, name='google_callback'),

    # Complétion du profil OAuth
    path('auth/complete-profile/', auth_views.complete_oauth_profile_view,
         name='complete_oauth_profile'),

    # ============================================
    # DASHBOARD & DOCUMENTS
    # ============================================
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('upload/', views.document_upload_view, name='document_upload'),
    path('document/<int:document_id>/', views.document_detail_view, name='document_detail'),
    path('document/<int:document_id>/download/', views.document_download_view, name='document_download'),

    # ============================================
    # PROFIL UTILISATEUR
    # ============================================
    path('profile/', profile_views.user_profile_view, name='user_profile'),
    path('profile/change-password/', profile_views.change_password_view, name='change_password'),

    # ============================================
    # STAFF - GESTION DU DÉPARTEMENT
    # ============================================
    # Demandes d'accès
    path('staff/pending-requests/', staff_views.pending_requests_view,
         name='pending_requests'),

    # Utilisateurs du département
    path('staff/department-users/', staff_views.department_users_view,
         name='department_users'),

    # ============================================
    # ADMIN / STAFF - AUDIT (PAS DE QUARANTAINE)
    # ============================================
    path('audit/', views.audit_log_view, name='audit_log'),

    # ============================================
    # GESTION DES UTILISATEURS
    # ============================================
    path('users/', profile_views.users_management_view, name='admin_users'),
    path('users/create/', profile_views.create_user_view, name='admin_create_user'),

    # ============================================
    # SUPERUSER - GESTION DES STAFFS
    # ============================================
    path('superuser/manage-staffs/', staff_views.superuser_manage_staffs_view,
         name='superuser_manage_staffs'),

    # ============================================
    # CONTACT
    # ============================================
    # Contact Global (Tout le monde)
    path('contact/', views.contact_view, name='contact_view'),

path('auth/complete-profile/', auth_views.complete_oauth_profile_view, name='complete_oauth_profile'),
    path('auth/pending-approval/', auth_views.profile_pending_approval_view, name='profile_pending_approval'),


path('staff/users/', profile_views.users_management_view, name='admin_users'),

path('staff/inbox/', staff_views.staff_inbox_view, name='staff_inbox'),

path('staff/approve/<int:user_id>/', staff_views.approve_user_view, name='approve_user'),
    path('staff/reject/<int:user_id>/', staff_views.reject_user_view, name='reject_user'),
path('staff/contact-managers/', staff_views.contact_department_staff_view, name='contact_department_staff'),


path('staff/inbox/', staff_views.staff_inbox_view, name='staff_inbox'),
    path('staff/reply/<int:message_id>/', staff_views.staff_reply_view, name='staff_reply'),

path('staff/users/', profile_views.users_management_view, name='admin_users'),
    path('staff/users/create/', profile_views.create_user_view, name='admin_create_user'),
]