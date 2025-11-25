import os
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.cache import cache
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST
from django.http import HttpResponse, Http404
from django.urls import reverse
from django.utils import timezone
from .models import UserTwoFactorSettings
from .forms import (
    TwoFactorSetupForm, TOTPVerificationForm, EmailOTPVerificationForm,
    BackupCodeVerificationForm, DisableTwoFactorForm
)
from .utils import (
    generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp_code,
    generate_backup_codes, generate_email_otp, send_otp_email, validate_email_otp,
    check_rate_limit, increment_rate_limit, clear_rate_limit
)

logger = logging.getLogger(__name__)

# ------------------- Helpers -------------------

def _cleanup_session(request, keys):
    """Remove multiple keys from session."""
    for key in keys:
        request.session.pop(key, None)
    request.session.save()

def _redirect_next(request, default='home'):
    """Redirect to the next URL if exists in session."""
    return redirect(request.session.pop('next_url', default))

def _verify_backup_code(two_factor_settings, request):
    """Handle backup code verification."""
    form = BackupCodeVerificationForm(request.POST or None)
    available_codes = set(two_factor_settings.get_available_backup_codes())

    if request.method == 'POST' and form.is_valid():
        code = form.cleaned_data['code']
        if code in available_codes and two_factor_settings.verify_backup_code(code):
            clear_rate_limit(str(request.user.pk))
            request.session['2fa_verified_at'] = timezone.now().isoformat()
            return True, "Backup code verified successfully."
        increment_rate_limit(str(request.user.pk))
        messages.error(request, "Invalid or used backup code.")
    return False, form

def _verify_totp(two_factor_settings, request):
    """Handle TOTP verification."""
    form = TOTPVerificationForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        code = form.cleaned_data['code']
        if verify_totp_code(two_factor_settings.totp_secret, code):
            clear_rate_limit(str(request.user.pk))
            request.session['2fa_verified_at'] = timezone.now().isoformat()
            return True, "TOTP verified successfully."
        increment_rate_limit(str(request.user.pk))
        messages.error(request, "Invalid TOTP code.")
    return False, form

def _verify_email(two_factor_settings, request):
    """Handle Email OTP verification."""
    otp_sent = request.session.get('email_otp_sent', False)
    form = EmailOTPVerificationForm(request.POST or None) if otp_sent else None

    if request.method == 'POST' and form and form.is_valid():
        code = form.cleaned_data['code']
        if validate_email_otp(request.user, code):
            clear_rate_limit(str(request.user.pk))
            request.session['2fa_verified_at'] = timezone.now().isoformat()
            _cleanup_session(request, ['email_otp_sent'])
            return True, "Email OTP verified successfully."
        increment_rate_limit(str(request.user.pk))
        messages.error(request, "Invalid or expired OTP.")
    return False, form

def _is_2fa_verified(request):
    """Check if 2FA verification is still valid in session."""
    verified_at = request.session.get('2fa_verified_at')
    if not verified_at:
        return False
    try:
        verified_at = timezone.make_aware(timezone.datetime.fromisoformat(verified_at))
        return (timezone.now() - verified_at).total_seconds() < 12 * 3600
    except Exception as e:
        logger.error(f"2FA verification check failed: {e}")
        return False

# ------------------- Views -------------------

@login_required
def twofactor_settings(request):
    """View for 2FA security settings."""
    settings_obj, _ = UserTwoFactorSettings.objects.get_or_create(user=request.user)
    return render(request, 'twofactor/twofactor_settings.html', {'two_factor_settings': settings_obj})


@login_required
def setup_2fa(request):
    """Setup 2FA (TOTP or Email)."""
    settings_obj, _ = UserTwoFactorSettings.objects.get_or_create(user=request.user)
    if settings_obj.is_enabled:
        messages.info(request, "Two-factor authentication is already enabled.")
        return redirect('twofactor:twofactor_settings')

    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            method = form.cleaned_data['method']
            request.session['2fa_setup_method'] = method

            if method == 'totp':
                secret = generate_totp_secret()
                request.session['2fa_setup_secret'] = secret
                totp_uri = get_totp_uri(secret, request.user.email)
                qr_path = generate_qr_code(totp_uri)
                request.session['2fa_qr_code_path'] = qr_path
                return redirect('twofactor:setup_totp')

            elif method == 'email':
                otp = generate_email_otp(request.user)
                send_otp_email(request.user, otp)
                messages.success(request, f"Verification code sent to {request.user.email}.")
                return redirect('twofactor:verify_email_otp')
    else:
        form = TwoFactorSetupForm()
    return render(request, 'twofactor/setup_2fa.html', {'form': form})


@login_required
def setup_totp(request):
    """Setup TOTP 2FA."""
    if '2fa_setup_secret' not in request.session or '2fa_qr_code_path' not in request.session:
        messages.error(request, "Setup session expired. Start again.")
        return redirect('twofactor:setup_2fa')

    secret = request.session['2fa_setup_secret']
    qr_path = request.session['2fa_qr_code_path']
    if not os.path.exists(qr_path):
        messages.error(request, "QR code missing. Retry.")
        return redirect('twofactor:setup_2fa')

    verified, form_or_msg = _verify_totp(UserTwoFactorSettings.objects.get_or_create(user=request.user)[0], request)
    if verified:
        settings_obj = UserTwoFactorSettings.objects.get(user=request.user)
        settings_obj.is_enabled = True
        settings_obj.method = 'totp'
        settings_obj.totp_secret = secret
        settings_obj.backup_codes = generate_backup_codes()
        settings_obj.last_verified = timezone.now()
        settings_obj.save()

        _cleanup_session(request, ['2fa_setup_secret', '2fa_qr_code_path'])
        try: os.remove(qr_path)
        except OSError: pass

        messages.success(request, form_or_msg)
        return redirect('twofactor:twofactor_settings')

    return render(request, 'twofactor/setup_totp.html', {
        'form': form_or_msg,
        'qr_code_url': reverse('twofactor:qr_code'),
        'secret': secret
    })


@login_required
def qr_code(request):
    """Serve QR code image."""
    qr_path = request.session.get('2fa_qr_code_path')
    if not qr_path or not os.path.exists(qr_path):
        raise Http404("QR code not found")
    with open(qr_path, 'rb') as f:
        return HttpResponse(f.read(), content_type='image/png')


@login_required
def verify_email_otp(request):
    """Verify Email OTP for 2FA setup."""
    verified, form_or_msg = _verify_email(UserTwoFactorSettings.objects.get_or_create(user=request.user)[0], request)
    if verified:
        settings_obj = UserTwoFactorSettings.objects.get(user=request.user)
        settings_obj.is_enabled = True
        settings_obj.method = 'email'
        settings_obj.backup_codes = generate_backup_codes()
        settings_obj.last_verified = timezone.now()
        settings_obj.save()
        messages.success(request, form_or_msg)
        return redirect('twofactor:twofactor_settings')

    return render(request, 'twofactor/verify_email_otp.html', {'form': form_or_msg})


@login_required
@never_cache
def verify_2fa(request):
    """Verify 2FA during login."""
    user_id = str(request.user.pk)
    is_limited, remaining, lockout = check_rate_limit(user_id)
    if is_limited:
        messages.error(request, f"Too many attempts. Try in {lockout // 60} mins.")
        return render(request, 'twofactor/verify_2fa.html', {'rate_limited': True, 'lockout_minutes': lockout//60})

    if _is_2fa_verified(request):
        return _redirect_next(request)

    try:
        settings_obj = UserTwoFactorSettings.objects.get(user=request.user)
    except UserTwoFactorSettings.DoesNotExist:
        return _redirect_next(request)

    if not settings_obj.is_enabled:
        return _redirect_next(request)

    method = request.GET.get('method') or settings_obj.method
    verified, form_or_msg = None, None

    if request.GET.get('backup') == 'true':
        verified, form_or_msg = _verify_backup_code(settings_obj, request)
        method = 'backup'
    elif method == 'totp':
        verified, form_or_msg = _verify_totp(settings_obj, request)
    elif method == 'email':
        verified, form_or_msg = _verify_email(settings_obj, request)

    if verified:
        settings_obj.update_last_verified()
        return _redirect_next(request)

    return render(request, 'twofactor/verify_2fa.html', {
        'method': method,
        'form': form_or_msg,
        'remaining_attempts': remaining,
        'has_backup_codes': settings_obj.has_available_backup_codes()
    })


@login_required
def request_verification_otp(request):
    """Request a new OTP for Email 2FA."""
    user_id = str(request.user.pk)
    is_limited, _, lockout = check_rate_limit(user_id, 'send_otp')
    if is_limited:
        messages.error(request, f"Too many requests. Try in {lockout//60} mins.")
        return redirect('twofactor:verify_2fa')

    try:
        settings_obj = UserTwoFactorSettings.objects.get(user=request.user, is_enabled=True, method='email')
        otp = generate_email_otp(request.user)
        send_otp_email(request.user, otp)
        increment_rate_limit(user_id, 'send_otp')
        request.session['email_otp_sent'] = True
        request.session.save()
        messages.success(request, f"New OTP sent to {request.user.email}.")
    except UserTwoFactorSettings.DoesNotExist:
        messages.error(request, "Email 2FA not enabled.")
    except Exception as e:
        logger.error(f"OTP send failed: {e}")
        messages.error(request, "Error sending OTP.")

    return redirect('twofactor:verify_2fa')


@login_required
def disable_2fa(request):
    """Disable 2FA."""
    settings_obj = get_object_or_404(UserTwoFactorSettings, user=request.user, is_enabled=True)
    if request.method == 'POST':
        form = DisableTwoFactorForm(request.POST)
        if form.is_valid():
            settings_obj.is_enabled = False
            settings_obj.totp_secret = None
            settings_obj.backup_codes = []
            settings_obj.save()
            messages.success(request, "Two-factor authentication disabled.")
            return redirect('twofactor:twofactor_settings')
    else:
        form = DisableTwoFactorForm()
    return render(request, 'twofactor/disable_2fa.html', {'form': form, 'two_factor_settings': settings_obj})


@login_required
def view_backup_codes(request):
    """View backup codes."""
    settings_obj = get_object_or_404(UserTwoFactorSettings, user=request.user, is_enabled=True)
    backup_status = [{'code': c, 'is_used': c in settings_obj.used_backup_codes} for c in settings_obj.backup_codes]
    return render(request, 'twofactor/backup_codes.html', {
        'backup_codes_status': backup_status,
        'available_count': len(settings_obj.get_available_backup_codes()),
        'total_count': len(settings_obj.backup_codes)
    })


@login_required
@require_POST
def regenerate_backup_codes(request):
    """Regenerate backup codes."""
    settings_obj = get_object_or_404(UserTwoFactorSettings, user=request.user, is_enabled=True)
    settings_obj.backup_codes = generate_backup_codes()
    settings_obj.used_backup_codes = []
    settings_obj.save()
    messages.success(request, "Backup codes regenerated.")
    return redirect('twofactor:view_backup_codes')


@login_required
def change_2fa_method(request):
    """Change 2FA method."""
    settings_obj = get_object_or_404(UserTwoFactorSettings, user=request.user, is_enabled=True)
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            method = form.cleaned_data['method']
            if method == settings_obj.method:
                messages.info(request, f"Already using {method} for 2FA.")
                return redirect('twofactor:twofactor_settings')

            request.session['2fa_setup_method'] = method
            if method == 'totp':
                secret = generate_totp_secret()
                request.session['2fa_setup_secret'] = secret
                qr_path = generate_qr_code(get_totp_uri(secret, request.user.email))
                request.session['2fa_qr_code_path'] = qr_path
                return redirect('twofactor:setup_totp')
            elif method == 'email':
                otp = generate_email_otp(request.user)
                send_otp_email(request.user, otp)
                messages.success(request, f"Verification code sent to {request.user.email}.")
                return redirect('twofactor:verify_email_otp')
    else:
        form = TwoFactorSetupForm(initial={'method': settings_obj.method})
    return render(request, 'twofactor/change_2fa_method.html', {'form': form, 'two_factor_settings': settings_obj})
