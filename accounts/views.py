from django.utils import timezone
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.http import JsonResponse
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.views.decorators.http import require_http_methods
from django.urls import reverse
from django.conf import settings
from .forms import (
    SignupForm, LoginForm, CustomPasswordResetForm, 
    CustomSetPasswordForm, CustomPasswordChangeForm, ProfileUpdateForm, EmailChangeForm
)
from .models import UserProfile, UserPreferences, MagicLinkToken
from .tokens import account_activation_token
from .utils import (
    send_activation_email, 
    send_password_reset_email, 
    verify_account_activation_token,
    send_password_change_notification, 
    send_welcome_email,
    send_login_notification,
    send_email_change_verification
)
from .magic_links import create_magic_link, send_magic_link_email, verify_magic_token, send_magic_link_request_notification
import requests

def verify_recaptcha(recaptcha_response):
    """
    Verify the reCAPTCHA response with Google's API.
    """
    if not recaptcha_response:
        return False
    
    data = {
        'secret': settings.RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response
    }
    
    try:
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()
        return result.get('success', False)
    except Exception:
        return False


User = get_user_model()

def signup_view(request):
    """
    Handle user registration with reCAPTCHA verification.
    Preserves the 'next' parameter for post-authentication redirection.
    """
    if request.user.is_authenticated:
        # If already logged in, respect the 'next' parameter
        next_url = request.GET.get('next', 'home')
        return redirect(next_url)
    
    # Save the 'next' parameter to pass along the authentication flow
    next_param = request.GET.get('next', '')
    
    if request.method == 'POST':
        form = SignupForm(request.POST)
        
        # Verify reCAPTCHA if enabled in settings
        recaptcha_enabled = getattr(settings, 'RECAPTCHA_ENABLED', False)
        if recaptcha_enabled:
            recaptcha_response = request.POST.get('g-recaptcha-response')
            recaptcha_valid = verify_recaptcha(recaptcha_response)
            
            if not recaptcha_valid:
                messages.error(request, "Please complete the reCAPTCHA verification.")
                return render(request, 'accounts/auth/signup.html', {
                    'form': form,
                    'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY,
                    'next': next_param  # Preserve 'next' parameter
                })
        
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.is_email_verified = False
            user.save()
            
            # Create user profile if it doesn't exist
            UserProfile.objects.get_or_create(user=user)
            
            # Send activation email
            send_activation_email(user, request)
            
            messages.success(
                request, 
                'Account created successfully. Please check your email to verify your account.'
            )
            # Redirect to login with the 'next' parameter preserved
            redirect_url = reverse('accounts:login')
            if next_param:
                redirect_url = f"{redirect_url}?next={next_param}"
            return redirect(redirect_url)
    else:
        form = SignupForm()
    
    # Pass reCAPTCHA site key and 'next' parameter to template
    context = {
        'form': form,
        'next': next_param  # Include 'next' parameter in the context
    }
    if getattr(settings, 'RECAPTCHA_ENABLED', False):
        context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
    
    return render(request, 'accounts/auth/signup.html', context)

def activate_account_view(request, uidb64, token):
    """
    Verify email and activate new user account.
    Preserves the 'next' parameter if present in the URL.
    """
    user = verify_account_activation_token(uidb64, token)
    next_param = request.GET.get('next', '')
    
    if user:
        # Only handle new account verification in this view
        if not user.is_email_verified:
            user.is_email_verified = True
            user.save()
            
            # Send welcome email for new accounts
            send_welcome_email(user, request)
            messages.success(request, 'Your email has been verified. You can now log in.')
        else:
            # This is likely an email change verification, but using the wrong URL
            messages.info(request, 'This account is already verified. Please log in.')
        
        # Redirect to login with the 'next' parameter preserved
        redirect_url = reverse('accounts:login')
        if next_param:
            redirect_url = f"{redirect_url}?next={next_param}"
        return redirect(redirect_url)
    else:
        messages.error(request, 'Activation link is invalid or has expired.')
        return redirect('accounts:signup')

def verify_email_change_view(request, uidb64, token):
    """
    Verify changed email address for existing user.
    """
    user = verify_account_activation_token(uidb64, token)
    
    if user:
        user.is_email_verified = True
        user.save()
        
        # Check if the user is already logged in
        if request.user.is_authenticated and request.user.pk == user.pk:
            messages.success(request, 'Your new email address has been verified successfully.')
            return redirect('accounts:profile')
        else:
            messages.success(request, 'Your new email address has been verified. Please log in with your new email.')
            return redirect('accounts:login')
    else:
        messages.error(request, 'Verification link is invalid or has expired.')
        return redirect('accounts:login')

def login_view(request):
    """
    Handle user login with reCAPTCHA verification.
    Handles 'next' parameter for redirecting users post-login.
    Now includes magic link option.
    """
    if request.user.is_authenticated:
        next_url = request.GET.get('next', 'home')
        return redirect(next_url)
    
    next_param = request.GET.get('next', '')
    
    # Check if magic link was requested
    magic_link_requested = request.GET.get('magic_link', '')
    if magic_link_requested:
        messages.info(
            request,
            "Enter your email to receive a magic login link. "
            "You must have magic links enabled in your account settings."
        )
        redirect_url = reverse('accounts:magic_link_request')
        if next_param:
            redirect_url = f"{redirect_url}?next={next_param}"
        return redirect(redirect_url)
    
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        
        # Verify reCAPTCHA if enabled in settings
        recaptcha_enabled = getattr(settings, 'RECAPTCHA_ENABLED', False)
        if recaptcha_enabled:
            recaptcha_response = request.POST.get('g-recaptcha-response')
            recaptcha_valid = verify_recaptcha(recaptcha_response)
            
            if not recaptcha_valid:
                messages.error(request, "Please complete the reCAPTCHA verification.")
                return render(request, 'accounts/auth/login.html', {
                    'form': form,
                    'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY,
                    'next': next_param
                })
        
        if form.is_valid():
            email = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                # Check if this is a soft-deleted account trying to reactivate
                if user.is_pending_deletion:
                    # Reactivate the account
                    if user.reactivate_account():
                        messages.success(
                            request, 
                            "Your account has been reactivated! Welcome back."
                        )
                    else:
                        messages.error(
                            request,
                            "Unable to reactivate your account. Please contact support."
                        )
                        return render(request, 'accounts/auth/login.html', {
                            'form': form,
                            'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY if recaptcha_enabled else None,
                            'next': next_param
                        })
                
                login(request, user)
                
                # Send enhanced login notification email if enabled
                if hasattr(user, 'preferences') and user.preferences.enable_login_notifications:
                    send_login_notification(user, request)
                
                next_url = request.POST.get('next', next_param) or 'home'
                return redirect(next_url)
            else:
                # Check if authentication failed due to inactive (soft-deleted) account
                try:
                    user = User.objects.get(email=email)
                    if user.is_pending_deletion:
                        messages.info(
                            request,
                            "Your account is scheduled for deletion. "
                            "Enter your password to reactivate it, or use a magic link if enabled."
                        )
                except User.DoesNotExist:
                    pass  # User doesn't exist, normal login failure
        # Form errors will be displayed by the template
    else:
        form = LoginForm()
    
    context = {
        'form': form,
        'next': next_param,
    }
    if getattr(settings, 'RECAPTCHA_ENABLED', False):
        context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
    
    return render(request, 'accounts/auth/login.html', context)

def logout_view(request):
    """
    Handle user logout.
    Supports 'next' parameter for redirecting after logout.
    """
    next_param = request.GET.get('next', '')
    
    # Clear 2FA verification session
    if '2fa_verified_at' in request.session:
        del request.session['2fa_verified_at']
    if '2fa_verification_in_progress' in request.session:
        del request.session['2fa_verification_in_progress']
    if 'next_url' in request.session:
        del request.session['next_url']
    
    logout(request)
    messages.success(request, 'You have been logged out.')
    
    # Redirect to specified URL or login page
    if next_param:
        return redirect(next_param)
    return redirect('accounts:login')

@login_required
def password_change_view(request):
    """
    Handle password change for authenticated users.
    """
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Update the session to prevent the user from being logged out
            update_session_auth_hash(request, user)
            
            # Send password change notification
            send_password_change_notification(user, request)
            
            messages.success(request, 'Your password was successfully updated!')
            return redirect('accounts:profile')
    else:
        form = CustomPasswordChangeForm(request.user)
    
    return render(request, 'accounts/auth/password_change.html', {'form': form})

def password_reset_view(request):
    """
    Handle password reset request with improved security.
    """
    if request.method == 'POST':
        form = CustomPasswordResetForm(request.POST)
        
        # Verify reCAPTCHA if enabled in settings
        recaptcha_enabled = getattr(settings, 'RECAPTCHA_ENABLED', False)
        if recaptcha_enabled:
            recaptcha_response = request.POST.get('g-recaptcha-response')
            recaptcha_valid = verify_recaptcha(recaptcha_response)
            
            if not recaptcha_valid:
                messages.error(request, "Please complete the reCAPTCHA verification.")
                return render(request, 'accounts/auth/password_reset.html', {
                    'form': form,
                    'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY
                })
        
        if form.is_valid():
            email = form.cleaned_data['email']
            
            # Always show the same message regardless of whether the email exists
            messages.success(
                request,
                'If an account with that email exists, we\'ve sent password reset instructions.'
            )
            
            # Only send the email if the user exists
            try:
                user = User.objects.get(email=email)
                if user.is_active:
                    send_password_reset_email(user, request)
            except User.DoesNotExist:
                pass  # Don't leak which email exists
            
            # Always log out the user after initiating a reset
            if request.user.is_authenticated:
                logout(request)
            
            return redirect('accounts:login')
    else:
        form = CustomPasswordResetForm()
    
    # Pass reCAPTCHA site key to template if enabled
    context = {'form': form}
    if getattr(settings, 'RECAPTCHA_ENABLED', False):
        context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
    
    return render(request, 'accounts/auth/password_reset.html', context)

def password_reset_confirm_view(request, uidb64, token):
    """
    Handle password reset confirmation.
    """
    user = verify_account_activation_token(uidb64, token)
    
    if not user:
        messages.error(request, 'Password reset link is invalid or has expired.')
        return redirect('accounts:password_reset')
    
    if request.method == 'POST':
        form = CustomSetPasswordForm(user, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your password has been reset. You can now log in.')
            return redirect('accounts:login')
    else:
        form = CustomSetPasswordForm(user)
    
    return render(request, 'accounts/auth/password_reset_confirm.html', {'form': form})

@login_required
def profile_view(request):
    """
    Display user profile.
    """
    profile = get_object_or_404(UserProfile, user=request.user)
    return render(request, 'accounts/profile/profile.html', {'profile': profile})

@login_required
def profile_update_view(request):
    """
    Update user profile information.
    """
    profile = get_object_or_404(UserProfile, user=request.user)
    
    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, instance=profile, user=request.user)
        if form.is_valid():
            # Update user fields
            request.user.first_name = form.cleaned_data['first_name']
            request.user.last_name = form.cleaned_data['last_name']
            request.user.username = form.cleaned_data['username']
            request.user.save()
            
            # Update profile fields
            form.save(commit=False)
            profile.bio = form.cleaned_data['bio']
            profile.location = form.cleaned_data['location']
            profile.date_of_birth = form.cleaned_data['date_of_birth']
            profile.save()
            
            messages.success(request, 'Your profile has been updated.')
            return redirect('accounts:profile')
    else:
        form = ProfileUpdateForm(instance=profile, user=request.user)
    
    return render(request, 'accounts/profile/edit_profile.html', {'form': form, 'profile': profile})

@login_required
def profile_images_update_view(request):
    """
    Update user profile images (avatar and cover photo).
    """
    profile = get_object_or_404(UserProfile, user=request.user)
    
    if request.method == 'POST':
        # Variables to track changes
        avatar_updated = False
        cover_updated = False
        
        # Handle avatar update
        if 'avatar' in request.FILES:
            profile.avatar = request.FILES['avatar']
            avatar_updated = True
        
        # Handle cover photo update
        if 'cover_photo' in request.FILES:
            profile.cover_photo = request.FILES['cover_photo']
            cover_updated = True
        
        # Save changes if any
        if avatar_updated or cover_updated:
            profile.save()
            
            # Create appropriate success message
            if avatar_updated and cover_updated:
                success_msg = "Your profile picture and cover photo have been updated."
            elif avatar_updated:
                success_msg = "Your profile picture has been updated."
            else:
                success_msg = "Your cover photo has been updated."
            
            messages.success(request, success_msg)
            return redirect('accounts:profile')
        else:
            # No files were uploaded
            messages.info(request, "No images were selected for upload.")
    
    # GET request - display the form
    return render(request, 'accounts/profile/edit_profile_images.html', {'profile': profile})

@login_required
def email_change_view(request):
    """
    Handle email change request.
    """
    if request.method == 'POST':
        form = EmailChangeForm(request.user, request.POST)
        if form.is_valid():
            new_email = form.cleaned_data['email']
            
            # Store the new email temporarily
            old_email = request.user.email
            request.user.email = new_email
            request.user.is_email_verified = False
            request.user.save()
            
            # Send verification email using the new function
            send_email_change_verification(request.user, request)
            
            messages.success(
                request, 
                f'Email change requested. We\'ve sent a verification link to {new_email}. '
                f'You won\'t be able to login until you verify the new address. '
                # f'If you don\'t verify within 24 hours, your email will remain as {old_email}.'
            )
            return redirect('accounts:profile')
    else:
        form = EmailChangeForm(request.user)
    
    return render(request, 'accounts/auth/email_change.html', {'form': form})

@login_required
def security_settings(request):
    """
    View for security settings page.
    """
    # Ensure user preferences exist
    from .models import UserPreferences
    UserPreferences.objects.get_or_create(user=request.user)
    
    return render(request, 'accounts/security/security_settings.html')

@login_required
def delete_account(request):
    """
    View for handling account deletion.
    """
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_deletion = request.POST.get('confirm_deletion')
        
        # Verify the user's password
        user = authenticate(username=request.user.email, password=password)
        
        if not user:
            messages.error(request, "Incorrect password. Account deletion canceled.")
            return redirect('accounts:security_settings')
        
        if not confirm_deletion:
            messages.error(request, "You must confirm that you understand the consequences of account deletion.")
            return redirect('accounts:security_settings')
        
        # Mark the account for deletion
        user.is_active = False
        user.scheduled_deletion = timezone.now() + timedelta(days=30)
        user.save()
        
        # Log the user out
        logout(request)
        
        messages.success(
            request, 
            "Your account has been scheduled for deletion and will be permanently deleted in 30 days. "
            "If you change your mind, you can reactivate your account by logging in within this period."
        )
        return redirect('home')
    
    # If not a POST request, redirect to security settings
    return redirect('accounts:security_settings')


def magic_link_request_view(request):
    """
    Handle magic link login requests with improved error handling.
    """
    if request.user.is_authenticated:
        next_url = request.GET.get('next', 'home')
        return redirect(next_url)
    
    next_param = request.GET.get('next', '')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Verify reCAPTCHA if enabled
        recaptcha_enabled = getattr(settings, 'RECAPTCHA_ENABLED', False)
        if recaptcha_enabled:
            recaptcha_response = request.POST.get('g-recaptcha-response')
            recaptcha_valid = verify_recaptcha(recaptcha_response)
            
            if not recaptcha_valid:
                messages.error(request, "Please complete the reCAPTCHA verification.")
                return render(request, 'accounts/auth/magic_link_request.html', {
                    'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY,
                    'next': next_param,
                    'email': email,
                    'magic_link_lifespan': getattr(settings, 'MAGIC_LINK_TOKEN_LIFESPAN', 10)
                })
        
        try:
            # Check if user exists and is active OR is pending deletion (can reactivate)
            user = User.objects.get(email=email)
            
            # Allow magic links for active users AND users pending deletion
            if not user.is_active and not user.is_pending_deletion:
                # User exists but is permanently inactive
                messages.error(
                    request, 
                    "This account is permanently deactivated. Please contact support."
                )
                return redirect('accounts:login')
            
            # Check if user has magic links enabled
            if not hasattr(user, 'preferences') or not user.preferences.enable_magic_links:
                messages.error(
                    request, 
                    "Magic links are not enabled for your account. "
                    "Please use your password or enable magic links in your account settings."
                )
                # Preserve email in form for better UX
                context = {
                    'email': email,
                    'next': next_param,
                }
                if recaptcha_enabled:
                    context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
                return render(request, 'accounts/auth/magic_link_request.html', context)
            
            # Create and send magic link
            magic_token = create_magic_link(user, request)
            if magic_token:
                send_magic_link_email(user, magic_token, request)
                
                # Show appropriate message based on account status
                if user.is_pending_deletion:
                    message = (
                        f"We've sent a magic login link to {email}. "
                        f"Click the link to reactivate your account. "
                        f"The link will expire in {getattr(settings, 'MAGIC_LINK_TOKEN_LIFESPAN', 10)} minutes."
                    )
                else:
                    message = (
                        f"We've sent a magic login link to {email}. "
                        f"The link will expire in {getattr(settings, 'MAGIC_LINK_TOKEN_LIFESPAN', 10)} minutes."
                    )
                
                messages.success(request, message)
                
                # Always show the same message regardless of whether the email exists
                # This prevents email enumeration
                return redirect('accounts:login')
            else:
                messages.error(request, "Unable to create magic link. Please try again.")
                
        except User.DoesNotExist:
            # Don't reveal whether the email exists
            messages.success(
                request,
                f"If an account with that email exists, we've sent a magic login link. "
                f"The link will expire in {getattr(settings, 'MAGIC_LINK_TOKEN_LIFESPAN', 10)} minutes."
            )
            return redirect('accounts:login')
    
    # GET request - show magic link request form
    context = {
        'next': next_param,
    }
    if getattr(settings, 'RECAPTCHA_ENABLED', False):
        context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
    
    return render(request, 'accounts/auth/magic_link_request.html', context)

def magic_link_verify_view(request, token):
    """
    Verify and process magic link tokens.
    Handles account reactivation for soft-deleted accounts.
    """
    user = verify_magic_token(token, request)
    
    if user:
        # Check if this is a soft-deleted account trying to reactivate
        if user.is_pending_deletion:
            # Reactivate the account
            if user.reactivate_account():
                messages.success(
                    request, 
                    "Your account has been reactivated! Welcome back."
                )
            else:
                messages.error(
                    request,
                    "Unable to reactivate your account. Please contact support."
                )
                return redirect('accounts:login')
        
        # Log the user in with explicit backend
        from django.contrib.auth import login
        from django.contrib.auth.backends import ModelBackend
        
        # Use the user's backend or fall back to ModelBackend
        backend_path = None
        if hasattr(user, 'backend'):
            backend_path = user.backend
        else:
            # Use the first configured authentication backend
            from django.conf import settings
            backend_path = settings.AUTHENTICATION_BACKENDS[0]
        
        user.backend = backend_path
        login(request, user)
        
        # Send login notification if enabled
        if hasattr(user, 'preferences') and user.preferences.enable_login_notifications:
            send_login_notification(user, request)
        
        messages.success(request, f"Welcome back, {user.first_name or user.email}!")
        
        # Redirect to next parameter or profile
        next_url = request.GET.get('next', 'accounts:profile')
        return redirect(next_url)
    else:
        messages.error(
            request, 
            "This magic link is invalid or has expired. "
            "Please request a new one."
        )
        return redirect('accounts:login')

@login_required
def toggle_magic_links_view(request):
    """
    Toggle magic links feature for the user.
    """
    if request.method == 'POST':
        try:
            preferences = request.user.preferences
            new_state = not preferences.enable_magic_links
            preferences.enable_magic_links = new_state
            preferences.save()
            
            if new_state:
                messages.success(request, "Magic links have been enabled for your account.")
            else:
                messages.success(request, "Magic links have been disabled for your account.")
                
        except UserPreferences.DoesNotExist:
            messages.error(request, "Error updating preferences. Please try again.")
    
    return redirect('accounts:security_settings')

@login_required
def toggle_login_notifications_view(request):
    """
    Toggle login notifications with security warning.
    """
    if request.method == 'POST':
        try:
            preferences = request.user.preferences
            new_state = not preferences.enable_login_notifications
            
            # Show warning when disabling login notifications
            if not new_state:
                # This will be handled in the template with a confirmation modal
                preferences.enable_login_notifications = new_state
                preferences.save()
                messages.warning(
                    request,
                    "Login notifications have been disabled. "
                    "This reduces your account security. "
                    "We recommend keeping this enabled."
                )
            else:
                preferences.enable_login_notifications = new_state
                preferences.save()
                messages.success(request, "Login notifications have been enabled.")
                
        except UserPreferences.DoesNotExist:
            messages.error(request, "Error updating preferences. Please try again.")
    
    return redirect('accounts:security_settings')