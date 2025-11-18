from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.conf import settings
import datetime
import logging

logger = logging.getLogger(__name__)

class TwoFactorMiddleware:
    """
    Middleware to check if 2FA verification is needed for all authenticated pages.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        # Critical: Always exempt 2FA verification paths
        self.default_exempt_paths = [
            '/2fa/',           # All 2FA URLs - this is crucial!
            '/admin/',         # All admin URLs
        ]
        
        # Get exempt paths from settings
        self.exempt_paths = self._get_exempt_paths()

    def __call__(self, request):
        # Skip if user is not authenticated
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        # Check if the path is exempt FIRST (before any other checks)
        path = request.path
        if self._is_path_exempt(path):
            return self.get_response(request)
        
        # Check if superuser is exempt
        if self._is_superuser_exempt(request):
            return self.get_response(request)
        
        # Check if user has 2FA enabled and needs verification
        try:
            from .models import UserTwoFactorSettings
            
            try:
                two_factor_settings = UserTwoFactorSettings.objects.get(user=request.user)
                
                # If 2FA is not enabled, skip verification
                if not two_factor_settings.is_enabled:
                    return self.get_response(request)
                
                # Check if 2FA is already verified in this session
                if self._is_2fa_verified(request):
                    return self.get_response(request)
                
                # Store the current URL for redirection after verification
                request.session['next_url'] = request.get_full_path()
                
                # Redirect to verification page
                return redirect('twofactor:verify_2fa')
                
            except UserTwoFactorSettings.DoesNotExist:
                # User doesn't have 2FA settings, let the request through
                pass
                
        except Exception as e:
            # Log the error but don't block the request
            logger.error(f"Error in 2FA middleware: {str(e)}")
        
        return self.get_response(request)
    
    def _get_exempt_paths(self):
        """
        Get exempt paths from settings or use defaults.
        """
        exempt_paths = self.default_exempt_paths.copy()
        
        # Add paths from settings if configured
        custom_exempt_paths = getattr(settings, 'TWO_FACTOR_EXEMPT_PATHS', [])
        if custom_exempt_paths:
            exempt_paths.extend(custom_exempt_paths)
        
        # Remove duplicates and return
        return list(set(exempt_paths))
    
    def _is_superuser_exempt(self, request):
        """
        Check if superuser is exempt based on settings.
        """
        exempt_superusers = getattr(settings, 'TWO_FACTOR_EXEMPT_SUPERUSERS', False)
        return exempt_superusers and request.user.is_superuser
    
    def _is_path_exempt(self, path):
        """
        Check if the current path is exempt from 2FA verification.
        """
        for exempt_path in self.exempt_paths:
            if path.startswith(exempt_path):
                return True
        return False
    
    def _is_2fa_verified(self, request):
        """
        Check if 2FA has been verified in the current session.
        """
        # Check session verification timestamp
        verified_at = request.session.get('2fa_verified_at')
        if not verified_at:
            return False
        
        try:
            # Parse the ISO format datetime
            if isinstance(verified_at, str):
                verified_at = timezone.datetime.fromisoformat(verified_at)
            
            # Convert to timezone-aware if it's naive
            if timezone.is_naive(verified_at):
                verified_at = timezone.make_aware(verified_at)
            
            # Check if verification is still valid (within configured window)
            verification_window_hours = getattr(settings, 'TWO_FACTOR_VERIFICATION_WINDOW_DAYS', 14) * 24
            now = timezone.now()
            verification_valid = (now - verified_at) < datetime.timedelta(hours=verification_window_hours)
            
            return verification_valid
            
        except (ValueError, TypeError) as e:
            logger.error(f"Error parsing 2FA verification timestamp: {str(e)}")
            return False