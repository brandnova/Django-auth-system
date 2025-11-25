from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.urls import reverse
from django.conf import settings
from django.utils import timezone
import requests

from .forms import (
    SignupForm, LoginForm, CustomPasswordResetForm, 
    CustomSetPasswordForm, CustomPasswordChangeForm, ProfileUpdateForm, EmailChangeForm
)
from .models import UserProfile, UserPreferences, MagicLinkToken
from .tokens import account_activation_token
from .utils import (
    send_activation_email, send_password_reset_email, verify_account_activation_token,
    send_password_change_notification, send_welcome_email,
    send_login_notification, send_email_change_verification
)
from .magic_links import create_magic_link, send_magic_link_email, verify_magic_token, send_magic_link_request_notification


User = get_user_model()


# ------------------------ Utility Functions ------------------------

def verify_recaptcha(recaptcha_response):
    """Verify the reCAPTCHA response with Google API."""
    if not recaptcha_response:
        return False
    try:
        data = {'secret': settings.RECAPTCHA_SECRET_KEY, 'response': recaptcha_response}
        result = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data).json()
        return result.get('success', False)
    except Exception:
        return False


# ------------------------ Authentication Views ------------------------

def signup_view(request):
    """User registration with optional reCAPTCHA."""
    if request.user.is_authenticated:
        return redirect(request.GET.get('next', 'home'))
    
    next_param = request.GET.get('next', '')
    form = SignupForm(request.POST or None)
    
    if request.method == 'POST':
        if getattr(settings, 'RECAPTCHA_ENABLED', False):
            if not verify_recaptcha(request.POST.get('g-recaptcha-response')):
                messages.error(request, "Please complete the reCAPTCHA verification.")
                return render(request, 'accounts/auth/signup.html', {'form': form, 'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY, 'next': next_param})

        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.is_email_verified = False
            user.save()
            UserProfile.objects.get_or_create(user=user)
            send_activation_email(user, request)
            messages.success(request, 'Account created. Check your email to verify.')
            redirect_url = reverse('accounts:login')
            if next_param:
                redirect_url += f"?next={next_param}"
            return redirect(redirect_url)

    context = {'form': form, 'next': next_param}
    if getattr(settings, 'RECAPTCHA_ENABLED', False):
        context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
    return render(request, 'accounts/auth/signup.html', context)


def activate_account_view(request, uidb64, token):
    """Email verification and account activation."""
    user = verify_account_activation_token(uidb64, token)
    next_param = request.GET.get('next', '')
    
    if user:
        if not user.is_email_verified:
            user.is_email_verified = True
            user.save()
            send_welcome_email(user, request)
            messages.success(request, 'Email verified. You can now log in.')
        else:
            messages.info(request, 'Account already verified. Please log in.')
        redirect_url = reverse('accounts:login')
        if next_param:
            redirect_url += f"?next={next_param}"
        return redirect(redirect_url)
    messages.error(request, 'Activation link invalid or expired.')
    return redirect('accounts:signup')


def verify_email_change_view(request, uidb64, token):
    """Verify changed email for existing users."""
    user = verify_account_activation_token(uidb64, token)
    if user:
        user.is_email_verified = True
        user.save()
        if request.user.is_authenticated and request.user.pk == user.pk:
            messages.success(request, 'New email verified.')
            return redirect('accounts:profile')
        messages.success(request, 'Email verified. Log in with new email.')
        return redirect('accounts:login')
    messages.error(request, 'Verification link invalid or expired.')
    return redirect('accounts:login')


def login_view(request):
    """User login with optional reCAPTCHA and magic link."""
    if request.user.is_authenticated:
        return redirect(request.GET.get('next', 'home'))
    
    next_param = request.GET.get('next', '')
    if request.GET.get('magic_link'):
        redirect_url = reverse('accounts:magic_link_request')
        if next_param:
            redirect_url += f"?next={next_param}"
        messages.info(request, "Enter email to receive magic link.")
        return redirect(redirect_url)

    form = LoginForm(request, data=request.POST or None)
    if request.method == 'POST':
        if getattr(settings, 'RECAPTCHA_ENABLED', False):
            if not verify_recaptcha(request.POST.get('g-recaptcha-response')):
                messages.error(request, "Complete reCAPTCHA verification.")
                return render(request, 'accounts/auth/login.html', {'form': form, 'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY, 'next': next_param})

        if form.is_valid():
            email = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=email, password=password)
            if user:
                if user.is_pending_deletion and not user.reactivate_account():
                    messages.error(request, "Cannot reactivate account. Contact support.")
                    return render(request, 'accounts/auth/login.html', {'form': form, 'next': next_param})
                login(request, user)
                if getattr(user, 'preferences', None) and user.preferences.enable_login_notifications:
                    send_login_notification(user, request)
                return redirect(request.POST.get('next', next_param) or 'home')
            else:
                try:
                    user = User.objects.get(email=email)
                    if user.is_pending_deletion:
                        messages.info(request, "Account scheduled for deletion. Enter password to reactivate or use magic link.")
                except User.DoesNotExist:
                    pass

    context = {'form': form, 'next': next_param}
    if getattr(settings, 'RECAPTCHA_ENABLED', False):
        context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
    return render(request, 'accounts/auth/login.html', context)


def logout_view(request):
    """User logout with optional 'next' redirect."""
    next_param = request.GET.get('next', '')
    for key in ['2fa_verified_at', '2fa_verification_in_progress', 'next_url']:
        request.session.pop(key, None)
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect(next_param or 'accounts:login')


# ------------------------ Password Management ------------------------

@login_required
def password_change_view(request):
    """Change password for logged-in users."""
    form = CustomPasswordChangeForm(request.user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        update_session_auth_hash(request, user)
        send_password_change_notification(user, request)
        messages.success(request, 'Password updated successfully!')
        return redirect('accounts:profile')
    return render(request, 'accounts/auth/password_change.html', {'form': form})


def password_reset_view(request):
    """Request password reset."""
    form = CustomPasswordResetForm(request.POST or None)
    if request.method == 'POST':
        if getattr(settings, 'RECAPTCHA_ENABLED', False):
            if not verify_recaptcha(request.POST.get('g-recaptcha-response')):
                messages.error(request, "Complete reCAPTCHA verification.")
                return render(request, 'accounts/auth/password_reset.html', {'form': form, 'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY})
        if form.is_valid():
            email = form.cleaned_data['email']
            messages.success(request, 'If account exists, password reset instructions sent.')
            try:
                user = User.objects.get(email=email)
                if user.is_active:
                    send_password_reset_email(user, request)
            except User.DoesNotExist:
                pass
            if request.user.is_authenticated:
                logout(request)
            return redirect('accounts:login')
    context = {'form': form}
    if getattr(settings, 'RECAPTCHA_ENABLED', False):
        context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
    return render(request, 'accounts/auth/password_reset.html', context)


def password_reset_confirm_view(request, uidb64, token):
    """Confirm and set new password."""
    user = verify_account_activation_token(uidb64, token)
    if not user:
        messages.error(request, 'Password reset link invalid or expired.')
        return redirect('accounts:password_reset')
    
    form = CustomSetPasswordForm(user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, 'Password reset. You can now log in.')
        return redirect('accounts:login')
    return render(request, 'accounts/auth/password_reset_confirm.html', {'form': form})


# ------------------------ Profile Views ------------------------

@login_required
def profile_view(request):
    profile = get_object_or_404(UserProfile, user=request.user)
    return render(request, 'accounts/profile/profile.html', {'profile': profile})


@login_required
def profile_update_view(request):
    profile = get_object_or_404(UserProfile, user=request.user)
    form = ProfileUpdateForm(request.POST or None, instance=profile, user=request.user)
    if request.method == 'POST' and form.is_valid():
        request.user.first_name = form.cleaned_data['first_name']
        request.user.last_name = form.cleaned_data['last_name']
        request.user.username = form.cleaned_data['username']
        request.user.save()
        profile.bio = form.cleaned_data['bio']
        profile.location = form.cleaned_data['location']
        profile.date_of_birth = form.cleaned_data['date_of_birth']
        profile.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('accounts:profile')
    return render(request, 'accounts/profile/edit_profile.html', {'form': form, 'profile': profile})


@login_required
def profile_images_update_view(request):
    profile = get_object_or_404(UserProfile, user=request.user)
    if request.method == 'POST':
        avatar_updated = 'avatar' in request.FILES
        cover_updated = 'cover_photo' in request.FILES
        if avatar_updated:
            profile.avatar = request.FILES['avatar']
        if cover_updated:
            profile.cover_photo = request.FILES['cover_photo']
        if avatar_updated or cover_updated:
            profile.save()
            msg = "Profile image updated." if avatar_updated else ""
            msg += " Cover photo updated." if cover_updated else ""
            messages.success(request, msg)
            return redirect('accounts:profile')
        messages.info(request, "No images selected for upload.")
    return render(request, 'accounts/profile/edit_profile_images.html', {'profile': profile})


# ------------------------ Email Change ------------------------

@login_required
def email_change_view(request):
    form = EmailChangeForm(request.user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        new_email = form.cleaned_data['email']
        request.user.email = new_email
        request.user.is_email_verified = False
        request.user.save()
        send_email_change_verification(request.user, request)
        messages.success(request, f'Email change requested. Verify at {new_email}.')
        return redirect('accounts:profile')
    return render(request, 'accounts/auth/email_change.html', {'form': form})


# ------------------------ Security & Account Deletion ------------------------

@login_required
def security_settings(request):
    UserPreferences.objects.get_or_create(user=request.user)
    return render(request, 'accounts/security/security_settings.html')


@login_required
def delete_account(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_deletion = request.POST.get('confirm_deletion')
        user = authenticate(username=request.user.email, password=password)
        if not user or not confirm_deletion:
            messages.error(request, "Password incorrect or deletion not confirmed.")
            return redirect('accounts:security_settings')
        user.is_active = False
        user.scheduled_deletion = timezone.now() + timedelta(days=30)
        user.save()
        logout(request)
        messages.success(request, "Account scheduled for deletion in 30 days.")
        return redirect('home')
    return redirect('accounts:security_settings')


# ------------------------ Magic Links ------------------------

def magic_link_request_view(request):
    if request.user.is_authenticated:
        return redirect(request.GET.get('next', 'home'))
    next_param = request.GET.get('next', '')
    if request.method == 'POST':
        email = request.POST.get('email')
        if getattr(settings, 'RECAPTCHA_ENABLED', False) and not verify_recaptcha(request.POST.get('g-recaptcha-response')):
            messages.error(request, "Complete reCAPTCHA verification.")
            return render(request, 'accounts/auth/magic_link_request.html', {'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY, 'next': next_param, 'email': email})
        try:
            user = User.objects.get(email=email)
            if not user.is_active and not user.is_pending_deletion:
                messages.error(request, "Account permanently deactivated.")
                return redirect('accounts:login')
            if not getattr(user, 'preferences', None) or not user.preferences.enable_magic_links:
                messages.error(request, "Magic links not enabled. Use password or enable in settings.")
                return render(request, 'accounts/auth/magic_link_request.html', {'email': email, 'next': next_param})
            token = create_magic_link(user, request)
            if token:
                send_magic_link_email(user, token, request)
                messages.success(request, f"Magic link sent to {email}.")
                return redirect('accounts:login')
            messages.error(request, "Unable to create magic link.")
        except User.DoesNotExist:
            messages.success(request, f"If account exists, magic link sent to {email}.")
            return redirect('accounts:login')
    context = {'next': next_param}
    if getattr(settings, 'RECAPTCHA_ENABLED', False):
        context['recaptcha_site_key'] = settings.RECAPTCHA_SITE_KEY
    return render(request, 'accounts/auth/magic_link_request.html', context)


def magic_link_verify_view(request, token):
    user = verify_magic_token(token, request)
    if user:
        if user.is_pending_deletion and not user.reactivate_account():
            messages.error(request, "Cannot reactivate account. Contact support.")
            return redirect('accounts:login')
        user.backend = getattr(user, 'backend', settings.AUTHENTICATION_BACKENDS[0])
        login(request, user)
        if getattr(user, 'preferences', None) and user.preferences.enable_login_notifications:
            send_login_notification(user, request)
        messages.success(request, f"Welcome back, {user.first_name or user.email}!")
        return redirect(request.GET.get('next', 'accounts:profile'))
    messages.error(request, "Magic link invalid or expired. Request new one.")
    return redirect('accounts:login')


@login_required
def toggle_magic_links_view(request):
    if request.method == 'POST':
        try:
            pref = request.user.preferences
            pref.enable_magic_links = not pref.enable_magic_links
            pref.save()
            messages.success(request, f"Magic links {'enabled' if pref.enable_magic_links else 'disabled'}.")
        except UserPreferences.DoesNotExist:
            messages.error(request, "Error updating preferences.")
    return redirect('accounts:security_settings')


@login_required
def toggle_login_notifications_view(request):
    if request.method == 'POST':
        try:
            pref = request.user.preferences
            new_state = not pref.enable_login_notifications
            pref.enable_login_notifications = new_state
            pref.save()
            if not new_state:
                messages.warning(request, "Login notifications disabled. Security reduced.")
            else:
                messages.success(request, "Login notifications enabled.")
        except UserPreferences.DoesNotExist:
            messages.error(request, "Error updating preferences.")
    return redirect('accounts:security_settings')
