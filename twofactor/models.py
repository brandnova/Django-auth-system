from django.db import models
from django.conf import settings
from django.utils import timezone
import datetime
import logging

logger = logging.getLogger(__name__)

class UserTwoFactorSettings(models.Model):
    """
    Model to store user's two-factor authentication settings.
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='two_factor')
    is_enabled = models.BooleanField(default=False)
    method = models.CharField(max_length=20, choices=[('totp', 'Authenticator App'), ('email', 'Email')], default='totp')
    totp_secret = models.CharField(max_length=255, blank=True, null=True)
    backup_codes = models.JSONField(default=list, blank=True)
    used_backup_codes = models.JSONField(default=list, blank=True)  # Track used codes
    last_verified = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} - 2FA Settings"

    def needs_verification(self):
        """
        Check if the user needs to verify 2FA.
        """
        # If 2FA is not enabled, no verification needed
        if not self.is_enabled:
            return False

        # Check if there's a verified session
        from django.contrib import auth
        request = getattr(auth, 'get_request', lambda: None)()
        if request and request.session.get('2fa_verified_at'):
            try:
                # Parse the ISO format datetime
                verified_at = timezone.datetime.fromisoformat(request.session['2fa_verified_at'])
                
                # Convert to timezone-aware if it's naive
                if timezone.is_naive(verified_at):
                    verified_at = timezone.make_aware(verified_at)
                
                # Check if verification is still valid (within 12 hours)
                now = timezone.now()
                verification_valid = (now - verified_at) < datetime.timedelta(hours=12)
                
                if verification_valid:
                    return False
            except Exception as e:
                logger.error(f"Error checking 2FA session verification: {str(e)}")

        # Check if last_verified is recent enough (within 12 hours)
        if self.last_verified:
            now = timezone.now()
            verification_valid = (now - self.last_verified) < datetime.timedelta(hours=12)
            
            if verification_valid:
                return False

        return True

    def update_last_verified(self):
        """
        Update the last_verified timestamp.
        """
        self.last_verified = timezone.now()
        self.save(update_fields=['last_verified'])

    def verify_backup_code(self, code):
        """
        Verify a backup code and mark it as used.
        Returns True if valid, False otherwise.
        """
        # Check if code exists in backup_codes and not in used_backup_codes
        if code in self.backup_codes and code not in self.used_backup_codes:
            # Mark the code as used
            self.used_backup_codes.append(code)
            self.save(update_fields=['used_backup_codes'])
            return True
        return False

    def get_available_backup_codes(self):
        """
        Get list of available (unused) backup codes.
        """
        return [code for code in self.backup_codes if code not in self.used_backup_codes]

    def get_used_backup_codes(self):
        """
        Get list of used backup codes.
        """
        return self.used_backup_codes

    def has_available_backup_codes(self):
        """
        Check if there are any available backup codes.
        """
        return len(self.get_available_backup_codes()) > 0
    


class EmailOTP(models.Model):
    """
    Stores email one-time password codes.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='email_otps')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"OTP for {self.user.email}"
    
    def is_valid(self):
        """
        Check if the OTP is still valid (not expired and not used).
        """
        return not self.is_used and timezone.now() < self.expires_at
    
    def mark_as_used(self):
        """
        Mark the OTP as used.
        """
        self.is_used = True
        self.save(update_fields=['is_used'])