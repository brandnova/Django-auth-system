from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from user_agents import parse
import requests

def get_client_ip(request):
    """
    Get the client IP address from the request.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', 'Unknown')
    return ip

def get_location_from_ip(ip):
    """
    Get location information from IP address using ipinfo.io.
    """
    try:
        # Use ipinfo.io API (free tier has rate limits)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            return {
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'location': data.get('loc', 'Unknown')
            }
    except Exception:
        pass
    
    return {
        'city': 'Unknown',
        'region': 'Unknown',
        'country': 'Unknown',
        'location': 'Unknown'
    }

def get_device_info(request):
    """
    Get detailed device information from the user agent.
    """
    user_agent_string = request.META.get('HTTP_USER_AGENT', '')
    
    try:
        # Parse user agent with user-agents library
        user_agent = parse(user_agent_string)
        
        return {
            'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
            'os': f"{user_agent.os.family} {user_agent.os.version_string}",
            'device': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'is_bot': user_agent.is_bot
        }
    except Exception:
        # Fallback to basic parsing if library fails
        browser = 'Unknown'
        device = 'Unknown'
        
        if 'Mobile' in user_agent_string:
            device = 'Mobile'
        elif 'Tablet' in user_agent_string:
            device = 'Tablet'
        else:
            device = 'Desktop'
            
        if 'Firefox' in user_agent_string:
            browser = 'Firefox'
        elif 'Chrome' in user_agent_string:
            browser = 'Chrome'
        elif 'Safari' in user_agent_string:
            browser = 'Safari'
        elif 'Edge' in user_agent_string:
            browser = 'Edge'
        elif 'MSIE' in user_agent_string or 'Trident' in user_agent_string:
            browser = 'Internet Explorer'
        
        return {
            'browser': browser,
            'os': 'Unknown',
            'device': device,
            'is_mobile': device == 'Mobile',
            'is_tablet': device == 'Tablet',
            'is_pc': device == 'Desktop',
            'is_bot': False
        }

User = get_user_model()

def get_site_url(request):
    """
    Get the site URL including protocol and domain.
    """
    current_site = get_current_site(request)
    protocol = 'https' if request.is_secure() else 'http'
    site_url = f"{protocol}://{current_site.domain}"
    return site_url

def send_activation_email(user, request):
    """
    Send account activation email with verification link.
    """
    current_site = get_current_site(request)
    site_url = get_site_url(request)
    mail_subject = 'Activate your account'
    
    message = render_to_string('accounts/emails/activation_email.html', {
        'user': user,
        'site_url': site_url,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
        'domain': current_site.domain,
    })
    
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def send_password_reset_email(user, request):
    """
    Send password reset email with reset link.
    """
    current_site = get_current_site(request)
    site_url = get_site_url(request)
    mail_subject = 'Reset your password'
    
    message = render_to_string('accounts/emails/password_reset_email.html', {
        'user': user,
        'site_url': site_url,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
        'domain': current_site.domain,
    })
    
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def send_email_change_verification(user, request):
    """
    Send email change verification email.
    """
    current_site = get_current_site(request)
    site_url = get_site_url(request)
    mail_subject = 'Verify your new email address'
    
    message = render_to_string('accounts/emails/email_change.html', {
        'user': user,
        'site_url': site_url,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
        'domain': current_site.domain,
        # Use the new URL name for email change verification
        'verification_url': reverse('accounts:verify_email_change', kwargs={
            'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': default_token_generator.make_token(user)
        })
    })
    
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def send_password_change_notification(user, request):
    """
    Send password change notification email.
    """
    site_url = get_site_url(request)
    mail_subject = 'Your password has been changed'
    
    # Get IP address from request
    ip_address = request.META.get('REMOTE_ADDR', 'Unknown')
    
    message = render_to_string('accounts/emails/password_change_notification.html', {
        'user': user,
        'site_url': site_url,
        'ip_address': ip_address,
    })
    
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def send_welcome_email(user, request):
    """
    Send welcome email after account verification.
    """
    site_url = get_site_url(request)
    mail_subject = 'Welcome to Our Platform!'
    
    message = render_to_string('accounts/emails/welcome_email.html', {
        'user': user,
        'site_url': site_url,
    })
    
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def send_login_notification(user, request):
    """
    Send enhanced login notification email with IP, location, and device info.
    """
    site_url = get_site_url(request)
    mail_subject = 'New login to your account'
    
    # Get IP address from request
    ip_address = get_client_ip(request)
    
    # Get location information
    location_info = get_location_from_ip(ip_address)
    
    # Get detailed device information
    device_info = get_device_info(request)
    
    # Log the login activity if the model exists
    try:
        from .models import LoginActivity
        LoginActivity.objects.create(
            user=user,
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            city=location_info.get('city'),
            region=location_info.get('region'),
            country=location_info.get('country'),
            device_type='Mobile' if device_info['is_mobile'] else 'Tablet' if device_info['is_tablet'] else 'Desktop'
        )
    except (ImportError, AttributeError):
        # LoginActivity model doesn't exist yet, skip logging
        pass
    
    # Prepare context for email template
    context = {
        'user': user,
        'site_url': site_url,
        'ip_address': ip_address,
        'device': device_info['device'],
        'browser': device_info['browser'],
        'os': device_info['os'],
        'location': f"{location_info['city']}, {location_info['region']}, {location_info['country']}",
        'timestamp': timezone.now(),
    }
    
    message = render_to_string('accounts/emails/login_notification.html', context)
    
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def verify_account_activation_token(uidb64, token):
    """
    Verify the activation token and return the user if valid.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        return user
    return None