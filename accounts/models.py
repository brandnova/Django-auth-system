from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

class UserManager(BaseUserManager):
    """
    Custom user manager for email-based authentication.
    """
    def normalize_email(self, email):
        """
        Normalize the email address by lowercasing the domain part of it.
        """
        email = email or ''
        try:
            email_name, domain_part = email.strip().rsplit('@', 1)
        except ValueError:
            pass
        else:
            email = email_name + '@' + domain_part.lower()
        return email
        
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and save a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_email_verified', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    """
    Custom User model that uses email as the unique identifier
    instead of username for authentication.
    """
    email = models.EmailField(_('email address'), unique=True)
    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        blank=True,
        null=True,
        help_text=_('Optional. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
    )
    is_email_verified = models.BooleanField(
        _('email verified'),
        default=False,
        help_text=_('Designates whether this user has verified their email address.'),
    )
    scheduled_deletion = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Email is already required by default
    
    objects = UserManager()

    def __str__(self):
        return self.email

    @property
    def is_pending_deletion(self):
        """
        Check if the user account is pending deletion.
        """
        return self.scheduled_deletion is not None and not self.is_active
    
    def reactivate_account(self):
        """
        Reactivate a user account that was scheduled for deletion.
        """
        if self.is_pending_deletion:
            self.is_active = True
            self.scheduled_deletion = None
            self.save(update_fields=['is_active', 'scheduled_deletion'])
            return True
        return False

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        swappable = 'AUTH_USER_MODEL'


class UserProfile(models.Model):
    """
    Extended profile information for users.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    avatar = models.ImageField(upload_to='profile_avatars/', blank=True, null=True)
    cover_photo = models.ImageField(upload_to='profile_covers/', blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email}'s profile"


class UserSocialAccount(models.Model):
    """
    Model to store social authentication information.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='social_accounts')
    provider = models.CharField(max_length=50)  # 'google', 'facebook', etc.
    provider_id = models.CharField(max_length=255)
    provider_avatar = models.URLField(blank=True, null=True)
    extra_data = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('provider', 'provider_id')

    def __str__(self):
        return f"{self.user.email} - {self.provider}"


class MagicLinkToken(models.Model):
    """
    Model to store magic link tokens for passwordless authentication.
    """
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='magic_link_tokens'
    )
    token = models.CharField(max_length=100, unique=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"Magic link for {self.user.email} - {'Used' if self.used else 'Active'}"

    def is_valid(self):
        """
        Check if the token is still valid and not used.
        """
        return not self.used and timezone.now() < self.expires_at

    class Meta:
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'used', 'expires_at']),
        ]
        verbose_name = _('magic link token')
        verbose_name_plural = _('magic link tokens')


class UserPreferences(models.Model):
    """
    User preferences for security and authentication features.
    """
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='preferences'
    )
    # Magic Links toggle
    enable_magic_links = models.BooleanField(
        _('enable magic links'),
        default=False,
        help_text=_('Allow logging in with magic links sent to your email.')
    )
    # Login notifications toggle
    enable_login_notifications = models.BooleanField(
        _('enable login notifications'),
        default=True,
        help_text=_('Receive email notifications for new logins.')
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email}'s preferences"

    class Meta:
        verbose_name = _('user preference')
        verbose_name_plural = _('user preferences')
