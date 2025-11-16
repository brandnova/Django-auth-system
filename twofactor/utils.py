import os
import pyotp
import qrcode
import random
import string
import tempfile
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from .models import EmailOTP

def generate_totp_secret():
    """
    Generate a new TOTP secret.
    """
    return pyotp.random_base32()

def get_totp_uri(secret, email, issuer="YourApp"):
    """
    Get the TOTP URI for QR code generation.
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)

def generate_qr_code(totp_uri):
    """
    Generate a QR code image for the TOTP URI and return the file path.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Create a temporary file
    fd, filepath = tempfile.mkstemp(suffix='.png')
    os.close(fd)
    
    # Save the image to the temporary file
    img.save(filepath)
    
    return filepath

def verify_totp_code(secret, code):
    """
    Verify a TOTP code against the secret.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_backup_codes(count=8):
    """
    Generate backup codes for 2FA recovery.
    """
    codes = []
    for _ in range(count):
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        codes.append(code)
    return codes

def generate_email_otp(user, expiry_minutes=10):
    """
    Generate a new email OTP for the user.
    """
    # Generate a 6-digit code
    code = ''.join(random.choices(string.digits, k=6))
    
    # Calculate expiry time
    expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
    
    # Create and save the OTP
    otp = EmailOTP.objects.create(
        user=user,
        code=code,
        expires_at=expires_at
    )
    
    return otp

def send_otp_email(user, otp):
    """
    Send the OTP code to the user's email.
    """
    subject = "Your One-Time Password"
    
    # Render the email template
    message = render_to_string('twofactor/emails/otp_email.html', {
        'user': user,
        'otp': otp.code,
        'expiry_minutes': int((otp.expires_at - timezone.now()).total_seconds() / 60)
    })
    
    email = EmailMessage(subject, message, to=[user.email])
    email.content_subtype = 'html'
    email.send()

def validate_email_otp(user, code):
    """
    Validate an email OTP code.
    """
    try:
        # Get the latest unused OTP for the user
        otp = EmailOTP.objects.filter(
            user=user,
            is_used=False,
            expires_at__gt=timezone.now()
        ).latest('created_at')
        
        if otp.code == code:
            otp.mark_as_used()
            return True
        return False
    except EmailOTP.DoesNotExist:
        return False