"""
Documents URLs
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('upload/', views.document_upload_view, name='document_upload'),
    path('document/<int:document_id>/', views.document_detail_view, name='document_detail'),
    path('document/<int:document_id>/download/', views.document_download_view, name='document_download'),
    path('audit/', views.audit_log_view, name='audit_log'),
]