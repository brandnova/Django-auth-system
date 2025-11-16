from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

class TwoFactorMiddleware:
    """
    Middleware to check if 2FA verification is needed.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        # Paths that don't require 2FA verification
        self.exempt_paths = [
            '/2fa/',
            '/twofactor/',
            '/accounts/login/',
            '/accounts/logout/',
            '/admin/',
            '/admin/login/',
            '/admin/logout/',
            '/static/',
            '/media/',
        ]

    def __call__(self, request):
        # Skip if user is not authenticated
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        # Check if the path is exempt
        path = request.path
        if any(path.startswith(exempt_path) for exempt_path in self.exempt_paths):
            return self.get_response(request)
        
        # Check if user has 2FA enabled and needs verification
        try:
            from .models import UserTwoFactorSettings
            
            try:
                two_factor_settings = UserTwoFactorSettings.objects.get(user=request.user)
                
                # If 2FA is not enabled, skip verification
                if not two_factor_settings.is_enabled:
                    return self.get_response(request)
                
                # Check if verification is needed
                if two_factor_settings.needs_verification():
                    # Check if we're already in the verification process
                    if request.session.get('2fa_verification_in_progress'):
                        # Let the request through to prevent loops
                        return self.get_response(request)
                    
                    # Store the current URL for redirection after verification
                    request.session['next_url'] = request.get_full_path()
                    
                    # Set a flag to prevent redirect loops
                    request.session['2fa_verification_in_progress'] = True
                    
                    # Save the session to ensure flags are persisted
                    request.session.save()
                    
                    # Redirect to verification page
                    return redirect('twofactor:verify_2fa')
            except UserTwoFactorSettings.DoesNotExist:
                # User doesn't have 2FA settings, let the request through
                pass
        except Exception as e:
            # Log the error but don't block the request
            logger.error(f"Error in 2FA middleware: {str(e)}")
        
        return self.get_response(request)