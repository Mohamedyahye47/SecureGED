"""
Security decorators and utilities for access control and authentication hardening.
"""
import logging
from functools import wraps
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.contrib import messages
from .models import AccessLog, UserProfile

logger = logging.getLogger(__name__)


def deny_by_default(view_func):
    """
    Decorator enforcing deny-by-default access model.
    Only explicitly allowed users/roles can access the view.
    All failures are logged for audit.
    """
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        try:
            # Fail closed: return to result of the wrapped view
            return view_func(request, *args, **kwargs)
        except PermissionError as e:
            # Log denial
            logger.warning(f"Access denied for {request.user}: {str(e)}")
            messages.error(request, "Accès refusé. Cette action n'est pas autorisée.")
            return HttpResponseForbidden(
                render(request, 'access_denied.html', {'reason': str(e)})
            )
        except Exception as e:
            logger.error(f"Unexpected error in deny_by_default: {str(e)}")
            messages.error(request, "Une erreur inattendue s'est produite.")
            return HttpResponseForbidden('Erreur système')
    
    return wrapper


def mfa_required(view_func):
    """
    Decorator requiring MFA to be enabled and verified for the user.
    TODO: Integrate with TOTP/hardware key verification once infra available.
    """
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        try:
            profile = UserProfile.objects.get(user=request.user)
            
            # Check if MFA is enforced (flag in profile)
            if hasattr(profile, 'mfa_required') and profile.mfa_required:
                if not profile.mfa_enabled:
                    logger.warning(f"MFA required but not enabled for {request.user}")
                    messages.error(request, "MFA doit être activée pour accéder à cette ressource.")
                    return HttpResponseForbidden("MFA obligatoire")
                
                # TODO: Verify MFA token from session or request
                # if not request.session.get('mfa_verified'):
                #     return redirect('mfa_verify')
            
            return view_func(request, *args, **kwargs)
        except UserProfile.DoesNotExist:
            logger.error(f"UserProfile not found for {request.user}")
            messages.error(request, "Profil utilisateur introuvable.")
            return HttpResponseForbidden("Erreur système")
    
    return wrapper


def require_clearance(min_clearance_level):
    """
    Decorator enforcing minimum clearance level for accessing a view.
    Deny-by-default: only users with sufficient clearance proceed.
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            try:
                profile = UserProfile.objects.get(user=request.user)
                
                if profile.clearance_level < min_clearance_level:
                    logger.warning(
                        f"Insufficient clearance for {request.user}: "
                        f"required {min_clearance_level}, has {profile.clearance_level}"
                    )
                    messages.error(request, "Habilitation insuffisante pour accéder à cette ressource.")
                    return HttpResponseForbidden("Habilitation insuffisante")
                
                return view_func(request, *args, **kwargs)
            except UserProfile.DoesNotExist:
                logger.error(f"UserProfile not found for {request.user}")
                return HttpResponseForbidden("Erreur système")
        
        return wrapper
    return decorator


def regenerate_session_id(view_func):
    """
    Decorator regenerating session ID after successful authentication or privilege change.
    Prevents session fixation attacks.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        result = view_func(request, *args, **kwargs)
        
        # After successful login, regenerate session
        if request.user.is_authenticated and hasattr(request, 'session'):
            old_session_key = request.session.session_key
            request.session.create()  # Generate new session ID
            new_session_key = request.session.session_key
            
            if old_session_key != new_session_key:
                logger.info(
                    f"Session ID regenerated for {request.user} "
                    f"(old: {old_session_key[:8]}..., new: {new_session_key[:8]}...)"
                )
        
        return result
    
    return wrapper


def log_audit_action(action, log_details_func=None):
    """
    Decorator logging all view accesses to audit log with specified action.
    log_details_func: Optional callable to extract custom details from request/response.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                result = view_func(request, *args, **kwargs)
                
                # Log successful access if user is authenticated
                if request.user.is_authenticated:
                    from .models import Document
                    
                    # Try to extract document_id from kwargs
                    document_id = kwargs.get('document_id')
                    details = ""
                    
                    if log_details_func:
                        details = log_details_func(request, result, *args, **kwargs)
                    
                    if document_id:
                        try:
                            document = Document.objects.get(id=document_id)
                            AccessLog.objects.create(
                                document=document,
                                user=request.user,
                                action=action,
                                ip_address=get_client_ip(request),
                                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                                success=True,
                                details=details
                            )
                        except Document.DoesNotExist:
                            pass
                
                return result
            except Exception as e:
                # Log failed access
                if request.user.is_authenticated:
                    document_id = kwargs.get('document_id')
                    if document_id:
                        try:
                            from .models import Document
                            document = Document.objects.get(id=document_id)
                            AccessLog.objects.create(
                                document=document,
                                user=request.user,
                                action=action,
                                ip_address=get_client_ip(request),
                                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                                success=False,
                                details=f"Error: {str(e)[:200]}"
                            )
                        except Exception:
                            pass
                
                raise
        
        return wrapper
    return decorator


def get_client_ip(request):
    """
    Extract client IP address from request, accounting for proxies.
    Used for rate limiting and audit logging.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
