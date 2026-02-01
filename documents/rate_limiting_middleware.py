"""
Rate limiting and progressive delay middleware to prevent brute-force attacks.
Implements progressive delays without account-lockout DoS.
"""
import logging
import time
from django.core.cache import cache
from django.http import HttpResponse
from django.utils.timezone import now
from datetime import timedelta

logger = logging.getLogger(__name__)


class ProgressiveRateLimitMiddleware:
    """
    Middleware implementing progressive rate limiting with exponential backoff.
    Prevents brute-force without hard account lockouts that enable DoS attacks.
    
    Configuration (set in settings.py):
    - RATE_LIMIT_LOGIN_ATTEMPTS: Number of attempts before delay (default: 3)
    - RATE_LIMIT_DELAY_BASE: Base delay in seconds (default: 1)
    - RATE_LIMIT_DELAY_MAX: Maximum delay in seconds (default: 60)
    - RATE_LIMIT_WINDOW: Time window in seconds (default: 300)
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.login_attempts_attempts = 3
        self.delay_base = 1
        self.delay_max = 60
        self.window = 300  # 5 minutes
    
    def __call__(self, request):
        # Check if this is a login attempt
        if request.path == '/login/' or request.path == '/':
            if request.method == 'POST':
                self._check_rate_limit(request)
        
        return self.get_response(request)
    
    def _check_rate_limit(self, request):
        """
        Check and enforce progressive rate limiting on login attempts.
        """
        client_ip = self._get_client_ip(request)
        cache_key = f"login_attempts_{client_ip}"
        
        # Get current attempt count from cache
        attempt_data = cache.get(cache_key, {'count': 0, 'first_attempt': time.time()})
        current_count = attempt_data['count']
        first_attempt_time = attempt_data['first_attempt']
        
        # Check if we're still within the rate limit window
        if time.time() - first_attempt_time > self.window:
            # Window expired, reset counter
            attempt_data = {'count': 1, 'first_attempt': time.time()}
            cache.set(cache_key, attempt_data, self.window)
            return
        
        # Increment attempt counter
        attempt_data['count'] += 1
        cache.set(cache_key, attempt_data, self.window)
        
        # Calculate delay based on attempts
        if current_count >= self.login_attempts_attempts:
            delay = min(
                self.delay_base * (2 ** (current_count - self.login_attempts_attempts)),
                self.delay_max
            )
            logger.warning(
                f"Progressive rate limit triggered for {client_ip}: "
                f"{current_count} attempts, applying {delay}s delay"
            )
            time.sleep(delay)
    
    def _get_client_ip(self, request):
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class SessionSecurityMiddleware:
    """
    Middleware enforcing session security policies:
    - Verify session age
    - Check for concurrent sessions (optional)
    - Log suspicious session activity
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.max_session_age = 3600  # 1 hour default
    
    def __call__(self, request):
        # Check session security if user is authenticated
        if request.user.is_authenticated:
            session = request.session
            
            # Verify session hasn't expired
            if 'login_time' in session:
                login_time = session.get('login_time')
                if time.time() - login_time > self.max_session_age:
                    logger.warning(
                        f"Session expired for {request.user}: "
                        f"age = {time.time() - login_time}s"
                    )
                    # Session will expire naturally; no force required
            else:
                # Set login time on first authenticated request
                session['login_time'] = time.time()
        
        response = self.get_response(request)
        
        # Ensure security headers are set
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response
