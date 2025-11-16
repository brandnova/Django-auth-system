import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, Http404
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST
# from ratelimit.decorators import ratelimit
import logging
from .models import UserTwoFactorSettings, EmailOTP
from .forms import TwoFactorSetupForm, TOTPVerificationForm, EmailOTPVerificationForm, BackupCodeVerificationForm, DisableTwoFactorForm
from .utils import (
    generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp_code,
    generate_backup_codes, generate_email_otp, send_otp_email, validate_email_otp
)

logger = logging.getLogger(__name__)

@login_required
def twofactor_settings(request):
    """
    View for managing security settings, including 2FA.
    """
    # Get or create 2FA settings
    two_factor_settings, created = UserTwoFactorSettings.objects.get_or_create(user=request.user)
    
    context = {
        'two_factor_settings': two_factor_settings,
    }
    
    return render(request, 'twofactor/twofactor_settings.html', context)

@login_required
def setup_2fa(request):
    """
    View for setting up 2FA.
    """
    # Get or create 2FA settings
    two_factor_settings, created = UserTwoFactorSettings.objects.get_or_create(user=request.user)
    
    # If 2FA is already enabled, redirect to security settings
    if two_factor_settings.is_enabled:
        messages.info(request, "Two-factor authentication is already enabled.")
        return redirect('twofactor:twofactor_settings')
    
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            method = form.cleaned_data['method']
            
            # Store the method in the session for the next step
            request.session['2fa_setup_method'] = method
            
            if method == 'totp':
                # Generate TOTP secret and store in session
                secret = generate_totp_secret()
                request.session['2fa_setup_secret'] = secret
                
                # Generate QR code
                totp_uri = get_totp_uri(secret, request.user.email)
                qr_code_path = generate_qr_code(totp_uri)
                
                # Store the QR code path in the session
                request.session['2fa_qr_code_path'] = qr_code_path
                
                return redirect('twofactor:setup_totp')
            elif method == 'email':
                # Generate and send OTP
                otp = generate_email_otp(request.user)
                send_otp_email(request.user, otp)
                
                messages.success(request, f"A verification code has been sent to {request.user.email}.")
                return redirect('twofactor:verify_email_otp')
    else:
        form = TwoFactorSetupForm()
    
    context = {
        'form': form,
    }
    
    return render(request, 'twofactor/setup_2fa.html', context)

@login_required
def setup_totp(request):
    """
    View for setting up TOTP-based 2FA.
    """
    # Check if we have the necessary session data
    if '2fa_setup_secret' not in request.session or '2fa_qr_code_path' not in request.session:
        messages.error(request, "Setup session expired. Please start again.")
        return redirect('twofactor:setup_2fa')
    
    secret = request.session['2fa_setup_secret']
    qr_code_path = request.session['2fa_qr_code_path']
    
    # Check if the QR code file exists
    if not os.path.exists(qr_code_path):
        messages.error(request, "QR code not found. Please try again.")
        return redirect('twofactor:setup_2fa')
    
    if request.method == 'POST':
        form = TOTPVerificationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['code']
            
            # Verify the code
            if verify_totp_code(secret, code):
                # Get or create 2FA settings
                two_factor_settings, created = UserTwoFactorSettings.objects.get_or_create(user=request.user)
                
                # Update settings
                two_factor_settings.is_enabled = True
                two_factor_settings.method = 'totp'
                two_factor_settings.totp_secret = secret
                two_factor_settings.backup_codes = generate_backup_codes()
                two_factor_settings.last_verified = timezone.now()
                two_factor_settings.save()
                
                # Clean up session
                if '2fa_setup_secret' in request.session:
                    del request.session['2fa_setup_secret']
                
                # Delete the QR code file
                try:
                    os.remove(qr_code_path)
                except OSError:
                    pass  # Ignore errors
                
                if '2fa_qr_code_path' in request.session:
                    del request.session['2fa_qr_code_path']
                
                messages.success(request, "Two-factor authentication has been enabled successfully.")
                return redirect('twofactor:twofactor_settings')
            else:
                messages.error(request, "Invalid verification code. Please try again.")
    else:
        form = TOTPVerificationForm()
    
    context = {
        'form': form,
        'secret': secret,
        'qr_code_url': reverse('twofactor:qr_code'),
    }
    
    return render(request, 'twofactor/setup_totp.html', context)

@login_required
def qr_code(request):
    """
    View for serving the QR code image.
    """
    if '2fa_qr_code_path' not in request.session:
        raise Http404("QR code not found")
    
    qr_code_path = request.session['2fa_qr_code_path']
    
    if not os.path.exists(qr_code_path):
        raise Http404("QR code not found")
    
    with open(qr_code_path, 'rb') as f:
        return HttpResponse(f.read(), content_type='image/png')

@login_required
def verify_email_otp(request):
    """
    View for verifying email OTP during setup.
    """
    if request.method == 'POST':
        form = EmailOTPVerificationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['code']
            
            # Verify the code
            if validate_email_otp(request.user, code):
                # Get or create 2FA settings
                two_factor_settings, created = UserTwoFactorSettings.objects.get_or_create(user=request.user)
                
                # Update settings
                two_factor_settings.is_enabled = True
                two_factor_settings.method = 'email'
                two_factor_settings.last_verified = timezone.now()
                two_factor_settings.backup_codes = generate_backup_codes()
                two_factor_settings.save()
                
                messages.success(request, "Two-factor authentication has been enabled successfully.")
                return redirect('twofactor:twofactor_settings')
            else:
                messages.error(request, "Invalid or expired verification code. Please try again.")
                return redirect('twofactor:request_email_otp')
    else:
        form = EmailOTPVerificationForm()
    
    context = {
        'form': form,
    }
    
    return render(request, 'twofactor/verify_email_otp.html', context)

@login_required
def request_email_otp(request):
    """
    View for requesting a new email OTP.
    """
    # Generate and send OTP
    otp = generate_email_otp(request.user)
    send_otp_email(request.user, otp)
    
    messages.success(request, f"A new verification code has been sent to {request.user.email}.")
    return redirect('twofactor:verify_email_otp')


@login_required
def verify_2fa(request):
    """
    View for verifying 2FA during login.
    """
    # Get 2FA settings
    try:
        two_factor_settings = UserTwoFactorSettings.objects.get(user=request.user)
    except UserTwoFactorSettings.DoesNotExist:
        # If user doesn't have 2FA settings, redirect to home
        if 'next_url' in request.session:
            next_url = request.session.pop('next_url')
            return redirect(next_url)
        return redirect('home')
    
    # If 2FA is not enabled, redirect to the next URL or home
    if not two_factor_settings.is_enabled:
        next_url = request.session.get('next_url', 'home')
        if 'next_url' in request.session:
            del request.session['next_url']
        return redirect(next_url)
    
    # If 2FA is already verified, redirect to the next URL or home
    if not two_factor_settings.needs_verification():
        next_url = request.session.get('next_url', 'home')
        if 'next_url' in request.session:
            del request.session['next_url']
        # Clear the verification in progress flag
        if '2fa_verification_in_progress' in request.session:
            del request.session['2fa_verification_in_progress']
        return redirect(next_url)
    
    # Check if user wants to use backup code
    use_backup_code = request.GET.get('backup') == 'true' or request.POST.get('use_backup_code')
    
    if use_backup_code:
        # Handle backup code verification
        if request.method == 'POST':
            form = BackupCodeVerificationForm(request.POST)
            if form.is_valid():
                code = form.cleaned_data['code']
                
                # Verify the backup code
                if two_factor_settings.verify_backup_code(code):
                    # Update last verified
                    two_factor_settings.update_last_verified()
                    
                    # Set session flag for 2FA verification
                    request.session['2fa_verified_at'] = timezone.now().isoformat()
                    
                    # Clear the verification in progress flag
                    if '2fa_verification_in_progress' in request.session:
                        del request.session['2fa_verification_in_progress']
                    
                    # Save the session to ensure changes are persisted
                    request.session.save()
                    
                    # Redirect to the next URL or home
                    next_url = request.session.get('next_url', 'home')
                    if 'next_url' in request.session:
                        del request.session['next_url']
                    
                    # Show warning about remaining backup codes
                    remaining_codes = len(two_factor_settings.get_available_backup_codes())
                    if remaining_codes == 0:
                        messages.warning(request, "You have used all your backup codes. Please generate new ones from your security settings.")
                    elif remaining_codes <= 2:
                        messages.warning(request, f"You have {remaining_codes} backup codes remaining. Consider generating new ones.")
                    
                    messages.success(request, "Two-factor authentication verified successfully using backup code.")
                    return redirect(next_url)
                else:
                    messages.error(request, "Invalid or already used backup code. Please try again.")
        else:
            form = BackupCodeVerificationForm()
        
        context = {
            'method': 'backup',
            'form': form,
            'available_codes_count': len(two_factor_settings.get_available_backup_codes()),
        }
        
        return render(request, 'twofactor/verify_2fa.html', context)
    
    # Handle TOTP verification
    if two_factor_settings.method == 'totp':
        if request.method == 'POST':
            form = TOTPVerificationForm(request.POST)
            if form.is_valid():
                code = form.cleaned_data['code']
                
                # Verify the code
                if verify_totp_code(two_factor_settings.totp_secret, code):
                    # Update last verified
                    two_factor_settings.update_last_verified()
                    
                    # Set session flag for 2FA verification
                    request.session['2fa_verified_at'] = timezone.now().isoformat()
                    
                    # Clear the verification in progress flag
                    if '2fa_verification_in_progress' in request.session:
                        del request.session['2fa_verification_in_progress']
                    
                    # Save the session to ensure changes are persisted
                    request.session.save()
                    
                    # Redirect to the next URL or home
                    next_url = request.session.get('next_url', 'home')
                    if 'next_url' in request.session:
                        del request.session['next_url']
                    
                    messages.success(request, "Two-factor authentication verified successfully.")
                    return redirect(next_url)
                else:
                    messages.error(request, "Invalid verification code. Please try again.")
        else:
            form = TOTPVerificationForm()
        
        context = {
            'method': 'totp',
            'form': form,
            'has_backup_codes': two_factor_settings.has_available_backup_codes(),
        }
        
        return render(request, 'twofactor/verify_2fa.html', context)
    
    # Handle Email verification (similar structure with backup code option)
    elif two_factor_settings.method == 'email':
        # Check if we need to send an OTP
        otp_sent = request.session.get('email_otp_sent', False)
        
        # Handle POST requests
        if request.method == 'POST':
            # Check if this is a request to send OTP
            if request.POST.get('action') == 'send_otp':
                try:
                    otp = generate_email_otp(request.user)
                    send_otp_email(request.user, otp)
                    
                    request.session['email_otp_sent'] = True
                    request.session.save()
                    otp_sent = True
                    
                    messages.success(request, f"A verification code has been sent to {request.user.email}.")
                except Exception as e:
                    logger.error(f"Error sending OTP: {str(e)}")
                    messages.error(request, "There was an error sending the verification code. Please try again.")
            
            # Check if this is a code verification
            elif otp_sent:
                form = EmailOTPVerificationForm(request.POST)
                if form.is_valid():
                    code = form.cleaned_data['code']
                    
                    # Verify the code
                    if validate_email_otp(request.user, code):
                        # Update last verified
                        two_factor_settings.update_last_verified()
                        
                        # Set session flag for 2FA verification
                        request.session['2fa_verified_at'] = timezone.now().isoformat()
                        
                        # Clear the verification in progress flag
                        if '2fa_verification_in_progress' in request.session:
                            del request.session['2fa_verification_in_progress']
                        
                        # Clean up session
                        if 'email_otp_sent' in request.session:
                            del request.session['email_otp_sent']
                        
                        # Save the session to ensure changes are persisted
                        request.session.save()
                        
                        # Redirect to the next URL or home
                        next_url = request.session.get('next_url', 'home')
                        if 'next_url' in request.session:
                            del request.session['next_url']
                        
                        messages.success(request, "Two-factor authentication verified successfully.")
                        return redirect(next_url)
                    else:
                        messages.error(request, "Invalid or expired verification code. Please try again.")
        
        # For GET requests or when form is needed
        if otp_sent:
            form = EmailOTPVerificationForm()
        else:
            form = None
        
        context = {
            'method': 'email',
            'otp_sent': otp_sent,
            'form': form,
            'has_backup_codes': two_factor_settings.has_available_backup_codes(),
        }
        
        return render(request, 'twofactor/verify_2fa.html', context)
    
    # Fallback for unsupported methods
    messages.error(request, "Unsupported two-factor authentication method.")
    return redirect('home')

@login_required
def request_verification_otp(request):
    """
    View for requesting a new OTP for email verification.
    """
    from .models import UserTwoFactorSettings
    from .utils import generate_email_otp, send_otp_email
    
    try:
        two_factor_settings = UserTwoFactorSettings.objects.get(user=request.user, is_enabled=True, method='email')
        
        # Generate and send OTP
        otp = generate_email_otp(request.user)
        send_otp_email(request.user, otp)
        
        request.session['email_otp_sent'] = True
        request.session.save()
        
        messages.success(request, f"A new verification code has been sent to {request.user.email}.")
    except UserTwoFactorSettings.DoesNotExist:
        messages.error(request, "Email two-factor authentication is not enabled for your account.")
    except Exception as e:
        logger.error(f"Error sending OTP: {str(e)}")
        messages.error(request, "There was an error sending the verification code. Please try again.")
    
    return redirect('twofactor:verify_2fa')

@login_required
def disable_2fa(request):
    """
    View for disabling 2FA.
    """
    # Get 2FA settings
    two_factor_settings = get_object_or_404(UserTwoFactorSettings, user=request.user, is_enabled=True)
    
    if request.method == 'POST':
        form = DisableTwoFactorForm(request.POST)
        if form.is_valid():
            # Disable 2FA
            two_factor_settings.is_enabled = False
            two_factor_settings.totp_secret = None
            two_factor_settings.backup_codes = []
            two_factor_settings.save()
            
            messages.success(request, "Two-factor authentication has been disabled.")
            return redirect('twofactor:twofactor_settings')
    else:
        form = DisableTwoFactorForm()
    
    context = {
        'form': form,
        'two_factor_settings': two_factor_settings,
    }
    
    return render(request, 'twofactor/disable_2fa.html', context)


@login_required
def view_backup_codes(request):
    """
    View for displaying backup codes with their status.
    """
    # Get 2FA settings
    two_factor_settings = get_object_or_404(UserTwoFactorSettings, user=request.user, is_enabled=True)
    
    # Prepare backup codes with their status
    backup_codes_status = []
    for code in two_factor_settings.backup_codes:
        backup_codes_status.append({
            'code': code,
            'is_used': code in two_factor_settings.used_backup_codes
        })
    
    context = {
        'backup_codes_status': backup_codes_status,
        'available_count': len(two_factor_settings.get_available_backup_codes()),
        'total_count': len(two_factor_settings.backup_codes),
    }
    
    return render(request, 'twofactor/backup_codes.html', context)

@login_required
@require_POST
def regenerate_backup_codes(request):
    """
    View for regenerating backup codes.
    """
    # Get 2FA settings
    two_factor_settings = get_object_or_404(UserTwoFactorSettings, user=request.user, is_enabled=True)
    
    # Generate new backup codes and reset used codes
    two_factor_settings.backup_codes = generate_backup_codes()
    two_factor_settings.used_backup_codes = []  # Reset used codes
    two_factor_settings.save()
    
    messages.success(request, "New backup codes have been generated. All previous codes are now invalid.")
    return redirect('twofactor:view_backup_codes')

@login_required
def change_2fa_method(request):
    """
    View for changing 2FA method.
    """
    # Get 2FA settings
    two_factor_settings = get_object_or_404(UserTwoFactorSettings, user=request.user, is_enabled=True)
    
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            method = form.cleaned_data['method']
            
            # If changing to the same method, redirect back
            if method == two_factor_settings.method:
                messages.info(request, f"You are already using {method} for two-factor authentication.")
                return redirect('twofactor:twofactor_settings')
            
            # Store the method in the session for the next step
            request.session['2fa_setup_method'] = method
            
            if method == 'totp':
                # Generate TOTP secret and store in session
                secret = generate_totp_secret()
                request.session['2fa_setup_secret'] = secret
                
                # Generate QR code
                totp_uri = get_totp_uri(secret, request.user.email)
                qr_code_path = generate_qr_code(totp_uri)
                
                # Store the QR code path in the session
                request.session['2fa_qr_code_path'] = qr_code_path
                
                return redirect('twofactor:setup_totp')
            elif method == 'email':
                # Generate and send OTP
                otp = generate_email_otp(request.user)
                send_otp_email(request.user, otp)
                
                messages.success(request, f"A verification code has been sent to {request.user.email}.")
                return redirect('twofactor:verify_email_otp')
    else:
        form = TwoFactorSetupForm(initial={'method': two_factor_settings.method})
    
    context = {
        'form': form,
        'two_factor_settings': two_factor_settings,
    }
    
    return render(request, 'twofactor/change_2fa_method.html', context)