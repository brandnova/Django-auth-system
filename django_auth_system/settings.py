from decouple import config, Csv
from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'django_cleanup.apps.CleanupConfig',
    'django_ckeditor_5',
    'social_django',

    # Custom apps
    'accounts',
    'twofactor',
    'core',
    
    
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'twofactor.middleware.TwoFactorMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',
]

ROOT_URLCONF = 'django_auth_system.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
                'accounts.context_processors.magic_link_settings',
                'core.context_processors.site_settings',
                'core.context_processors.static_pages',
            ],
        },
    },
]

WSGI_APPLICATION = 'django_auth_system.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = "/static/"
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Media files settings
MEDIA_URL = '/media/'  # URL to access media files in templates
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')  # Directory to store uploaded media files

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# --------------------------------------------------
# Custom settings for the project
# --------------------------------------------------

# Custom user model
AUTH_USER_MODEL = 'accounts.User'

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'accounts.backends.EmailBackend',  
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.discord.DiscordOAuth2',
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.facebook.FacebookOAuth2',
]

# Email Settings
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='localhost')
EMAIL_PORT = config('EMAIL_PORT', default=1025, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=False, cast=bool)
EMAIL_USE_SSL = config('EMAIL_USE_SSL', default=False, cast=bool)
EMAIL_TIMEOUT = config('EMAIL_TIMEOUT', default=30, cast=int)  # Optional but recommended
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@example.com')


# For development/testing, you can use the console backend instead of MailHog, to print the emails in the terminal. Comment out the above EMAIL_BACKEND and DEFAULT_FROM_EMAIL lines and uncomment the lines below.

# EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
# DEFAULT_FROM_EMAIL= 'webmaster@localhost.com'


# Login settings
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'accounts:profile'
LOGOUT_REDIRECT_URL = 'home'


# Social Authentication
# Google OAuth2
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = config('SOCIAL_AUTH_GOOGLE_OAUTH2_KEY', default='')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = config('SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET', default='')

# Facebook OAuth2
SOCIAL_AUTH_FACEBOOK_KEY = config('SOCIAL_AUTH_FACEBOOK_KEY', default='')
SOCIAL_AUTH_FACEBOOK_SECRET = config('SOCIAL_AUTH_FACEBOOK_SECRET', default='')
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']
SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {'fields': 'id,name,email'}

# GitHub OAuth
SOCIAL_AUTH_GITHUB_KEY = config('SOCIAL_AUTH_GITHUB_KEY', default='')
SOCIAL_AUTH_GITHUB_SECRET = config('SOCIAL_AUTH_GITHUB_SECRET', default='')
SOCIAL_AUTH_GITHUB_SCOPE = ['user:email']

# Discord OAuth
SOCIAL_AUTH_DISCORD_KEY = config('SOCIAL_AUTH_DISCORD_KEY')
SOCIAL_AUTH_DISCORD_SECRET = config('SOCIAL_AUTH_DISCORD_SECRET')
SOCIAL_AUTH_DISCORD_SCOPE = ['identify', 'email']  
SOCIAL_AUTH_DISCORD_API_URL = 'https://discord.com/api'

# General social auth settings
SOCIAL_AUTH_LOGIN_REDIRECT_URL = 'home'
SOCIAL_AUTH_LOGIN_ERROR_URL = 'accounts:login'
SOCIAL_AUTH_NEW_USER_REDIRECT_URL = 'accounts:profile'
SOCIAL_AUTH_NEW_ASSOCIATION_REDIRECT_URL = 'accounts:profile'
SOCIAL_AUTH_DISCONNECT_REDIRECT_URL = 'accounts:login'

# User model settings
SOCIAL_AUTH_USER_MODEL = 'accounts.User'

# Pipeline to create user profiles and handle email verification
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.user.create_user',
    'accounts.pipeline.create_user_profile',  # Custom function to create user profile
    'accounts.pipeline.set_email_verified',   # Custom function to set email as verified
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
)


# Two-factor authentication settings
TWO_FACTOR_VERIFICATION_WINDOW_DAYS = config('TWO_FACTOR_VERIFICATION_WINDOW_DAYS', default=14, cast=int)
TWO_FACTOR_EMAIL_OTP_EXPIRY_MINUTES = config('TWO_FACTOR_EMAIL_OTP_EXPIRY_MINUTES', default=10, cast=int)

TWO_FACTOR_EXEMPT_SUPERUSERS = config('TWO_FACTOR_EXEMPT_SUPERUSERS', default=False, cast=bool)
TWO_FACTOR_EXEMPT_PATHS = config('TWO_FACTOR_EXEMPT_PATHS', default='', cast=lambda v: [s.strip() for s in v.split(',') if s.strip()])

# Django flash message storage in cookies
MESSAGE_STORAGE = 'django.contrib.messages.storage.cookie.CookieStorage'
# MESSAGE_STORAGE = 'django.contrib.messages.storage.session.SessionStorage'

# reCAPTCHA settings
try:
    recaptcha_value = config('RECAPTCHA_ENABLED', default='false')
    # Strip any comments and whitespace
    recaptcha_value = recaptcha_value.split('#')[0].strip().lower()
    RECAPTCHA_ENABLED = recaptcha_value in ('true', 'yes', '1', 'on')
except Exception:
    # Default to False if there's any issue
    RECAPTCHA_ENABLED = False

try:
    RECAPTCHA_SITE_KEY = config('RECAPTCHA_SITE_KEY', default='')
    RECAPTCHA_SECRET_KEY = config('RECAPTCHA_SECRET_KEY', default='')
except Exception:
    RECAPTCHA_SITE_KEY = ''
    RECAPTCHA_SECRET_KEY = ''

# Magic Links Settings
MAGIC_LINK_TOKEN_LIFESPAN = config('MAGIC_LINK_TOKEN_LIFESPAN', default=10, cast=int)  # minutes
MAGIC_LINK_VERIFY_IP = config('MAGIC_LINK_VERIFY_IP', default=False, cast=bool)  # Extra security

# Django CKEditor settings

CKEDITOR_5_CONFIGS = {
    'default': {
        'toolbar': [
            'heading', '|', 'bold', 'italic', 'link', 'bulletedList', 
            'numberedList', 'blockQuote', '|', 
            'undo', 'redo'
        ],
        # Optionally change the editor language
        # 'language': 'en', 
    },
    
    'comment': {
        'toolbar': ['bold', 'italic', 'link', 'bulletedList', 'numberedList', 'undo', 'redo'],
        # Shorter configuration for comments or simpler fields
    },
    
    'extends': {
        'toolbar': [
            'heading', '|', 'bold', 'italic', 'link',
            'bulletedList', 'numberedList', 'blockQuote',
            '|', 'undo', 'redo'
        ],
    }
}



# Make sure the logs directory exists
os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)

# Logging configuration for production
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True,
        },
        'twofactor': {
            'handlers': ['console', 'file'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}
