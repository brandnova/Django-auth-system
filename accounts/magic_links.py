import secrets
from django.utils import timezone
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.urls import reverse
from .models import MagicLinkToken, UserPreferences

def generate_magic_token():
    """
    Generate a secure random token for magic links.
    """
    return secrets.token_urlsafe(32)

def create_magic_link(user, request, token_length=32):
    """
    Create a magic link token for the user.
    Works for both active users and users pending deletion.
    """
    # Check if user has magic links enabled
    try:
        if not user.preferences.enable_magic_links:
            return None
    except UserPreferences.DoesNotExist:
        return None

    # Get token lifespan from settings (default 10 minutes)
    token_lifespan_minutes = getattr(settings, 'MAGIC_LINK_TOKEN_LIFESPAN', 10)
    expires_at = timezone.now() + timezone.timedelta(minutes=token_lifespan_minutes)
    
    # Generate token
    token = generate_magic_token()
    
    # Create magic link token
    magic_token = MagicLinkToken.objects.create(
        user=user,
        token=token,
        ip_address=request.META.get('REMOTE_ADDR'),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        expires_at=expires_at
    )
    
    return magic_token

def send_magic_link_email(user, magic_token, request):
    """
    Send magic link email to the user using the base email template.
    """
    current_site = get_current_site(request)
    protocol = 'https' if request.is_secure() else 'http'
    site_url = f"{protocol}://{current_site.domain}"
    
    # Build magic link URL
    magic_link_url = reverse('accounts:magic_link_verify', kwargs={'token': magic_token.token})
    full_magic_link_url = f"{site_url}{magic_link_url}"
    
    # Email context
    context = {
        'user': user,
        'magic_link': full_magic_link_url,
        'site_url': site_url,
        'expires_minutes': getattr(settings, 'MAGIC_LINK_TOKEN_LIFESPAN', 10),
        'ip_address': magic_token.ip_address,
    }
    
    # Render email template
    subject = 'Your Magic Login Link - Brand Nova Auth'
    message = render_to_string('accounts/emails/magic_link_email.html', context)
    
    # Send email
    email = EmailMessage(subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def send_magic_link_request_notification(user, request):
    """
    Send notification when magic link is requested but not used.
    This is sent after a delay if the link wasn't used.
    """
    current_site = get_current_site(request)
    protocol = 'https' if request.is_secure() else 'http'
    site_url = f"{protocol}://{current_site.domain}"
    
    context = {
        'user': user,
        'site_url': site_url,
        'ip_address': request.META.get('REMOTE_ADDR'),
        'timestamp': timezone.now(),
    }
    
    subject = 'Magic Login Link Requested - Brand Nova Auth'
    message = render_to_string('accounts/emails/magic_link_requested.html', context)
    
    email = EmailMessage(subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def verify_magic_token(token, request):
    """
    Verify a magic link token and return the user if valid.
    """
    try:
        magic_token = MagicLinkToken.objects.get(token=token)
        
        if not magic_token.is_valid():
            return None
        
        # Optional: Verify IP address or user agent for extra security
        verify_ip = getattr(settings, 'MAGIC_LINK_VERIFY_IP', False)
        if verify_ip:
            current_ip = request.META.get('REMOTE_ADDR')
            if magic_token.ip_address and magic_token.ip_address != current_ip:
                return None
        
        # Mark token as used
        magic_token.used = True
        magic_token.save()
        
        return magic_token.user
        
    except MagicLinkToken.DoesNotExist:
        return None