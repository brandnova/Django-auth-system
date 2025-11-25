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

# --- TOTP Utils ---
def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(secret, email, issuer="YourApp"):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)

def generate_qr_code(totp_uri):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    fd, filepath = tempfile.mkstemp(suffix='.png')
    os.close(fd)
    img.save(filepath)
    return filepath

def verify_totp_code(secret, code):
    return pyotp.TOTP(secret).verify(code)

# --- Backup codes ---
def generate_backup_codes(count=8):
    return [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(count)]

# --- Email OTP ---
def generate_email_otp(user, expiry_minutes=None):
    expiry_minutes = expiry_minutes or getattr(settings, 'TWO_FACTOR_EMAIL_OTP_EXPIRY_MINUTES', 10)
    code = ''.join(random.choices(string.digits, k=6))
    otp = EmailOTP.objects.create(user=user, code=code, expires_at=timezone.now() + timedelta(minutes=expiry_minutes))
    return otp

def send_otp_email(user, otp):
    expiry_minutes = int((otp.expires_at - otp.created_at).total_seconds() / 60)
    message = render_to_string('twofactor/emails/otp_email.html', {'user': user, 'otp': otp.code, 'expiry_minutes': expiry_minutes})
    EmailMessage("Your One-Time Password", message, to=[user.email]).send()

def validate_email_otp(user, code):
    otp = EmailOTP.objects.filter(user=user, is_used=False, expires_at__gt=timezone.now()).last()
    if otp and otp.code == code:
        otp.mark_as_used()
        return True
    return False
