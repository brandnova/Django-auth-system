# Django Authentication System Setup Guide

This guide provides comprehensive instructions for setting up and customizing the Django Authentication System, which includes a core authentication app (`accounts`) and an optional Two-Factor Authentication app (`twofactor`).

## Overview

This authentication system provides a complete solution for user authentication in Django projects. It includes:

- Email-based authentication (instead of username)
- Email verification (for account activation)
- Password reset/change functionality
- Google reCAPTCHA
- User profiles with customizable fields
- Social authentication (Google, Facebook, etc.)
- Magic Links - Passwordless authentication via email
- User-controlled security preferences
- Optional Two-Factor Authentication (2FA)
- Account security settings and deletion
- Soft-delete functionality with account reactivation

### Project Structure

The authentication system consists of three main apps:

1. **`accounts`**: Core authentication functionality
2. **`twofactor`**: Optional Two-Factor Authentication
3. **`core`**: Base templates and landing page

## Installation

### Option 1: Start a New Project with This Authentication System

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/django-auth-system.git
   cd django-auth-system
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run migrations:
   ```bash
   python manage.py migrate
   ```

5. Create a superuser:
   ```bash
   python manage.py createsuperuser_email
   ```

6. Run the development server:
   ```bash
   python manage.py runserver
   ```

### Option 2: Add to an Existing Project

1. Copy the `accounts`, `twofactor` (optional), and `core` apps to your project:
   ```bash
   cp -r accounts twofactor core /path/to/your/project/
   ```

2. Add the apps to your `INSTALLED_APPS` in `settings.py`:
   ```python
   INSTALLED_APPS = [
       # Django built-in apps
       'django.contrib.admin',
       'django.contrib.auth',
       'django.contrib.contenttypes',
       'django.contrib.sessions',
       'django.contrib.messages',
       'django.contrib.staticfiles',
       
       # Third-party apps
       'social_django',  # For social authentication
       
       # Local apps
       'accounts',
       'twofactor',  # Optional
       'core',
       
       # Your other apps
   ]
   ```

3. Configure the authentication settings (see [Configuration](#configuration) section)
4. Run migrations:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

## Configuration

### Basic Settings

Add the following to your `settings.py`:

```python
# Authentication settings
AUTH_USER_MODEL = 'accounts.User'
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'accounts.backends.EmailBackend',  
    'social_core.backends.github.GithubOAuth2', # For social auth
    'social_core.backends.discord.DiscordOAuth2', # For social auth
    'social_core.backends.google.GoogleOAuth2', # For social auth
    'social_core.backends.facebook.FacebookOAuth2', # For social auth
]

# Login settings
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'accounts:profile'
LOGOUT_REDIRECT_URL = 'home'

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.example.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@example.com'
EMAIL_HOST_PASSWORD = 'your-password'
DEFAULT_FROM_EMAIL = 'Your Site <noreply@example.com>'

# For development, you can use the console email backend
# EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Social Authentication settings
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = 'your-google-client-id'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'your-google-client-secret'

SOCIAL_AUTH_FACEBOOK_KEY = 'your-facebook-app-id'
SOCIAL_AUTH_FACEBOOK_SECRET = 'your-facebook-app-secret'
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']

SOCIAL_AUTH_GITHUB_KEY= 'your-github-client-id'
SOCIAL_AUTH_GITHUB_SECRET= 'your-github-secret-key'

SOCIAL_AUTH_DISCORD_KEY = 'your-discord-key'
SOCIAL_AUTH_DISCORD_SECRET = 'your-discord-secret'
SOCIAL_AUTH_DISCORD_SCOPE = ['identify', 'email']  
SOCIAL_AUTH_DISCORD_API_URL = 'https://discord.com/api'

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

# reCAPTCHA settings
RECAPTCHA_ENABLED = True
RECAPTCHA_SITE_KEY = 'your-recaptcha-site-key'
RECAPTCHA_SECRET_KEY = 'your-recaptcha-secret-key'

# Magic Links settings
MAGIC_LINK_TOKEN_LIFESPAN = 10  # Minutes before magic link expires (default: 10)
MAGIC_LINK_VERIFY_IP = False    # Extra security: verify IP address (default: False)
```

### URL Configuration

Add the following to your `urls.py`:

```python
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')),
    path('accounts/', include('accounts.urls')),
    path('2fa/', include('twofactor.urls')),  # Optional
    path('social-auth/', include('social_django.urls', namespace='social')),
    # Your other URL patterns
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

### Redirect Handling with "next" Parameter

The authentication system supports automatic redirection using the `next` parameter, allowing users to be redirected back to their original page after login or registration.

#### How It Works

- When a user tries to access a protected page without being logged in, they are redirected to the login page with a `next` parameter containing the original URL
- After successful login or registration, the user is automatically redirected to the URL specified in the `next` parameter
- If no `next` parameter is provided, users are redirected to their profile page (login) or home page

#### Implementation

The system automatically handles `next` parameters in:
- Login page (`/accounts/login/?next=/protected-page/`)
- Registration page (`/accounts/signup/?next=/protected-page/`)
- Magic links (`/accounts/login/magic-link/?next=/protected-page/`)

#### Usage in Your Views

To protect a view and enable automatic redirection, use Django's `@login_required` decorator:

```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def protected_view(request):
    # This view requires authentication
    return render(request, 'app/protected.html')
```

When unauthenticated users access this view, they'll be automatically redirected to:
`/accounts/login/?next=/protected-view/`

After login, they'll be redirected back to `/protected-view/`.

#### Manual Implementation

You can also manually pass the `next` parameter in your templates:

```html
<a href="{% url 'accounts:login' %}?next={{ request.path }}" class="btn-login">
    Login to continue
</a>
```

This ensures users return to the current page after authentication.

## Customization

### Templates

The authentication system uses a base template located at `templates/base.html`. You can customize this template to match your site's design.

All authentication templates are located in the following directories:

- `accounts/templates/accounts/auth/`: Login, signup, password reset, magic links, etc.
- `accounts/templates/accounts/profile/`: User profile templates
- `accounts/templates/accounts/emails/`: Email templates
- `accounts/templates/accounts/security/`: Security settings templates
- `twofactor/templates/twofactor/`: Two-factor authentication templates

To customize a template, modify the existing ones or create a new template with the same name in your project's template directory and delete the existing one.

### Tailwind CSS Build System

This project ships with a dedicated Tailwind build setup located inside the `Tailwind/` directory. It works independently from Django’s apps but integrates cleanly with the template system.

The build script watches your Django templates and any static JavaScript files for class names, then compiles an optimized stylesheet to:

```
static/css/tailwind.css
```

**Key points about the setup:**

* The entire Tailwind workflow is isolated to the `Tailwind/` folder for clarity.
* Node and Tailwind CLI handle compilation; Django never processes Tailwind directly.
* Only classes actually used in templates or JS files are included in the final CSS.
* Hot-reloading is supported during development through the included watcher script.
* Production builds generate a fully minimized stylesheet.

To understand or modify the workflow, check the documentation inside:

```
Tailwind/IMPORTANT.md
```

This explains how to run the dev watcher, create production builds, and adjust Tailwind config as needed.

### User Model

The authentication system uses a custom User model with email as the username field. You can extend this model by adding fields to the `UserProfile` model in `accounts/models.py`.

### Forms

All forms are located in `accounts/forms.py`. You can customize these forms by subclassing them in your project.

### Views

All views are located in `accounts/views.py`. You can customize these views by subclassing them in your project.

## Magic Links Authentication

The system now includes **Magic Links** - a modern, passwordless authentication method that allows users to log in by clicking a secure link sent to their email.

### How Magic Links Work

1. User enters their email on the login page and chooses "Send Magic Link"
2. System generates a secure, one-time token with configurable expiration
3. User receives an email with a login link
4. Clicking the link logs the user in instantly
5. Token is marked as used and cannot be reused

### Features

- **User-controlled**: Magic links must be enabled by users in their security settings (disabled by default)
- **Secure**: Tokens expire after configurable time (default: 10 minutes) and are single-use
- **Account Reactivation**: Can be used to reactivate soft-deleted accounts
- **reCAPTCHA Protected**: Includes reCAPTCHA verification to prevent abuse
- **Email Notifications**: Users receive notifications for magic link requests

### Configuration

Magic links are configured via settings:

```python
# Magic Links settings (add to your settings.py)
MAGIC_LINK_TOKEN_LIFESPAN = 10  # Minutes before magic link expires
MAGIC_LINK_VERIFY_IP = False    # Extra security: verify IP address matches request
```

### URLs

The magic links feature adds the following URLs:

- `accounts:magic_link_request` - Request a magic link
- `accounts:magic_link_verify` - Verify and use a magic link token

## Security Preferences

Users now have granular control over their security settings through the new Security tab in account settings.

### Available Preferences

1. **Magic Links**
   - Enable/disable magic link authentication
   - Disabled by default for security
   - Users must explicitly enable this feature

2. **Login Notifications**
   - Enable/disable email notifications for new logins
   - Enabled by default for security
   - Includes device, browser, location, and IP details
   - Strong warning when disabling for security awareness

### User Experience

- **Intuitive Toggle Switches**: Modern, accessible toggle controls
- **Security Warnings**: Clear warnings when disabling security features
- **Educational Content**: Explanations of why each feature matters
- **Real-time Updates**: Immediate feedback when changing preferences

### Implementation

The security preferences are managed through:
- `UserPreferences` model (extends user settings)
- Dedicated Security tab in account settings
- Contextual warnings for security-sensitive changes
- Responsive design that works on all devices

## Two-Factor Authentication

The Two-Factor Authentication (2FA) app is designed to be modular and can be easily added or removed from your project.

### Enabling 2FA

1. Add `'twofactor'` to your `INSTALLED_APPS` in `settings.py`:
   ```python
   INSTALLED_APPS = [
       # ...
       'twofactor',
       # ...
   ]
   ```

2. Add the 2FA middleware to your `MIDDLEWARE` in `settings.py` right after `'django.contrib.auth.middleware.AuthenticationMiddleware'`:
   ```python
   MIDDLEWARE = [
       # ...
       'twofactor.middleware.TwoFactorMiddleware',  # Add after authentication middleware
       # ...
   ]
   ```

3. Add the 2FA URLs to your project's `urls.py`:
   ```python
   urlpatterns = [
       # ...
       path('2fa/', include('twofactor.urls')),
       # ...
   ]
   ```

4. Add the 2FA button to the security settings template `accounts/templates/accounts/security/security_settings.html`:
   ```html
   <div class="flex justify-center">
       <a href="{% url 'twofactor:twofactor_settings' %}" class="px-6 py-2.5 bg-brand-600 hover:bg-brand-700 text-white rounded-lg transition flex items-center space-x-2">
           <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
               <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
           </svg>
           <span>Manage Two-Factor Authentication</span>
       </a>
   </div>
   ```

5. Run migrations:
   ```bash
   python manage.py makemigrations twofactor
   python manage.py migrate
   ```

### Disabling 2FA

To disable 2FA, simply:

1. Remove `'twofactor'` from `INSTALLED_APPS`
2. Remove `'twofactor.middleware.TwoFactorMiddleware'` from `MIDDLEWARE`
3. Remove the 2FA URL pattern from your project's `urls.py`
4. Remove the 2FA button from your accounts security settings template

No changes to the database are required, as the 2FA tables will simply be ignored when the app is not installed.

### 2FA Configuration

Configure the following settings in your `.env` file and `settings.py`:

**In your `.env` file:**
```bash
# Two-Factor Authentication Settings
TWO_FACTOR_VERIFICATION_WINDOW_DAYS=14        # Days before re-verification is required (default: 14)
TWO_FACTOR_EMAIL_OTP_EXPIRY_MINUTES=10        # Minutes before email OTP expires (default: 10)
TWO_FACTOR_EXEMPT_SUPERUSERS=false            # Exempt superusers from 2FA (default: false)
TWO_FACTOR_EXEMPT_PATHS=/static/,/media/      # Comma-separated paths to exempt from 2FA
```

**In your `settings.py`:**
```python
# Two-Factor Authentication Settings
TWO_FACTOR_VERIFICATION_WINDOW_DAYS = config('TWO_FACTOR_VERIFICATION_WINDOW_DAYS', default=14, cast=int)
TWO_FACTOR_EMAIL_OTP_EXPIRY_MINUTES = config('TWO_FACTOR_EMAIL_OTP_EXPIRY_MINUTES', default=10, cast=int)
TWO_FACTOR_EXEMPT_SUPERUSERS = config('TWO_FACTOR_EXEMPT_SUPERUSERS', default=False, cast=bool)
TWO_FACTOR_EXEMPT_PATHS = config('TWO_FACTOR_EXEMPT_PATHS', default='', cast=lambda v: [s.strip() for s in v.split(',') if s.strip()])
```

**Default Exempt Paths:**
The following paths are exempt from 2FA verification by default:
- `/2fa/` - All 2FA management and verification URLs
- `/admin/` - Django admin interface
You can chage that from the twofactor/middleware.py code.

**Additional Path Exemptions:**
Add paths to `TWO_FACTOR_EXEMPT_PATHS` to exempt them from 2FA verification:
```bash
# Example: Exempt static files, media, API endpoints, or health checks
TWO_FACTOR_EXEMPT_PATHS=/static/,/media/,/api/public/,/healthcheck/
```

**Superuser Exemption:**
Set `TWO_FACTOR_EXEMPT_SUPERUSERS=true` in your `.env` to exempt all superusers from 2FA verification (useful for emergency access).

The 2FA system will automatically protect all authenticated views and redirect users to verification when needed, providing all-round security.


## Integration with Other Apps

### Social Media Platform Example

If you're building a social media platform, you can integrate the authentication system as follows:

1. Create your social media app:
   ```bash
   python manage.py startapp social
   ```

2. Add the app to `INSTALLED_APPS` in `settings.py`:
   ```python
   INSTALLED_APPS = [
       # ...
       'social',
       # ...
   ]
   ```

3. Create models that reference the User model:
   ```python
   from django.db import models
   from django.conf import settings

   class Post(models.Model):
       user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='posts')
       content = models.TextField()
       created_at = models.DateTimeField(auto_now_add=True)
       # Other fields...

   class Follow(models.Model):
       follower = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='following')
       following = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='followers')
       created_at = models.DateTimeField(auto_now_add=True)
       # Other fields...
   ```

4. Create views that require authentication:
   ```python
   from django.shortcuts import render, redirect
   from django.contrib.auth.decorators import login_required
   from .models import Post

   @login_required
   def create_post(request):
       if request.method == 'POST':
           # Process form data
           # ...
           return redirect('social:feed')
       return render(request, 'social/create_post.html')
   ```

5. Add URLs for your social media app:
   ```python
   from django.urls import path
   from . import views

   app_name = 'social'

   urlpatterns = [
       path('feed/', views.feed, name='feed'),
       path('post/create/', views.create_post, name='create_post'),
       # Other URLs...
   ]
   ```

6. Include your app's URLs in the project's `urls.py`:
   ```python
   urlpatterns = [
       # ...
       path('social/', include('social.urls')),
       # ...
   ]
   ```

### E-commerce Example

For an e-commerce site:

1. Create models that reference the User model:
   ```python
   class Order(models.Model):
       user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='orders')
       # Other fields...

   class ShippingAddress(models.Model):
       user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shipping_addresses')
       # Other fields...
   ```

2. Extend the UserProfile model to include customer-specific fields:
   ```python
   # In your app's models.py
   from accounts.models import UserProfile

   class CustomerProfile(models.Model):
       user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='customer_profile')
       customer_id = models.CharField(max_length=100, blank=True)
       loyalty_points = models.IntegerField(default=0)
       # Other fields...
   ```

3. Create a signal to create a CustomerProfile when a UserProfile is created:
   ```python
   from django.db.models.signals import post_save
   from django.dispatch import receiver
   from accounts.models import UserProfile
   from .models import CustomerProfile

   @receiver(post_save, sender=UserProfile)
   def create_customer_profile(sender, instance, created, **kwargs):
       if created:
           CustomerProfile.objects.create(user_profile=instance)
   ```

## Management Commands

### Creating a Superuser

To create a superuser without email verification:

```bash
python manage.py createsuperuser_email
```

### Cleaning Up Deleted Accounts

To permanently delete accounts that were scheduled for deletion and the grace period has expired:

```bash
# Basic usage - permanently delete accounts soft-deleted over 30 days ago
python manage.py cleanup_deleted_accounts

# Dry run - see which accounts would be deleted without actually deleting them
python manage.py cleanup_deleted_accounts --dry-run

# Custom threshold - delete accounts soft-deleted over 60 days ago
python manage.py cleanup_deleted_accounts --days 60

# Verbose output - show detailed information about each account
python manage.py cleanup_deleted_accounts --verbose

# Non-interactive mode (for cron jobs) - skip confirmation prompt
python manage.py cleanup_deleted_accounts --no-input
```

#### Command Options

- `--dry-run`: Show which accounts would be deleted without actually deleting them
- `--days`: Number of days after which to permanently delete accounts (default: 30)
- `--verbose`: Show detailed information about each account being processed
- `--no-input`: Non-interactive mode, skip confirmation prompts

#### Recommended Usage

For production environments, it's recommended to set up a cron job to run this command regularly:

```bash
# Run every Sunday at 2 AM to clean up accounts deleted over 30 days ago
0 2 * * 0 /path/to/your/venv/bin/python /path/to/your/project/manage.py cleanup_deleted_accounts --no-input

# Or with logging:
0 2 * * 0 /path/to/your/venv/bin/python /path/to/your/project/manage.py cleanup_deleted_accounts --no-input >> /var/log/account_cleanup.log 2>&1
```

#### Safety Features

- **Grace Period**: Accounts are only deleted after 30 days (configurable)
- **Confirmation Prompt**: Interactive confirmation required by default
- **Dry Run Mode**: Preview which accounts would be affected
- **Error Handling**: Continues processing other accounts if one fails
- **Audit Logging**: Detailed logging for compliance and debugging

## Troubleshooting

### Common Issues

1. **Migration Issues**:
   If you encounter migration issues, try:
   ```bash
   python manage.py makemigrations
   python manage.py migrate --fake-initial
   ```

2. **Template Not Found**:
   Make sure your template directories are correctly configured in `settings.py`:
   ```python
   TEMPLATES = [
       {
           'BACKEND': 'django.template.backends.django.DjangoTemplates',
           'DIRS': [os.path.join(BASE_DIR, 'templates')],
           'APP_DIRS': True,
           # ...
       },
   ]
   ```

3. **Static Files Not Loading**:
   Make sure your static files are correctly configured in `settings.py`:
   ```python
   STATIC_URL = '/static/'
   STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]
   STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
   ```

4. **Email Not Sending**:
   - Check your email settings in `settings.py`
   - For development, use the console email backend or MailHog (Download and run the MailHog server or check the settings.py file for configuration details)

5. **Magic Links Not Working**:
   - Ensure `MAGIC_LINK_TOKEN_LIFESPAN` is set in settings
   - Check that the context processor is properly configured
   - Verify email backend is working correctly

6. **Authentication Backend Error**:
   If you see "multiple authentication backends configured" error:
   - Ensure the `login_user` utility function is used in magic link views
   - Check that user objects have the backend attribute set

### Getting Help

If you encounter any issues not covered in this guide, please:

1. Check the Django documentation: [https://docs.djangoproject.com/](https://docs.djangoproject.com/)
2. Open an issue on the GitHub repository
3. Contact the maintainers at [brandnova89@gmail.com](mailto:brandnova89@gmail.com)

## File Structure

### Accounts App

```plaintext
accounts/
├── management/
│   └── commands/
│       ├── createsuperuser_email.py
│       └── cleanup_deleted_accounts.py
├── migrations/
│   ├── __init__.py
│   └── ... (migration files)
├── templates/
│   └── accounts/
│       ├── auth/
│       │   ├── email_change.html
│       │   ├── login.html
│       │   ├── magic_link_request.html
│       │   ├── password_change.html
│       │   ├── password_reset.html
│       │   ├── password_reset_confirm.html
│       │   └── signup.html
│       ├── emails/
│       │   ├── activation_email.html
│       │   ├── base_email.html
│       │   ├── email_change.html
│       │   ├── login_notification.html
│       │   ├── magic_link_email.html
│       │   ├── magic_link_requested.html
│       │   ├── password_change_notification.html
│       │   ├── password_reset_email.html
│       │   └── welcome_email.html
│       ├── profile/
│       │   ├── edit_profile.html
│       │   ├── edit_profile_images.html
│       │   └── profile.html
│       └── security/
│           └── security_settings.html
├── __init__.py
├── admin.py
├── apps.py
├── backends.py
├── context_processors.py
├── forms.py
├── magic_links.py
├── models.py
├── pipeline.py
├── signals.py
├── tokens.py
├── urls.py
├── utils.py
├── views.py
└── widgets.py
```

### Two-Factor Authentication App

```plaintext
twofactor/
├── migrations/
│   ├── __init__.py
│   └── ... (migration files)
├── templates/
│   └── twofactor/
│       ├── emails/
│       │   ├── base_email.html
│       │   └── otp_email.html
│       ├── backup_codes.html
│       ├── base_2fa.html
│       ├── change_2fa_method.html
│       ├── disable_2fa.html
│       ├── security_settings.html
│       ├── setup_2fa.html
│       ├── setup_totp.html
│       ├── verify_2fa.html
│       └── verify_email_otp.html
├── __init__.py
├── admin.py
├── apps.py
├── forms.py
├── middleware.py
├── models.py
├── signals.py
├── urls.py
├── utils.py
└── views.py
```

### Core App

```plaintext
core/
├── migrations/
│   ├── __init__.py
│   └── ... (migration files)
├── templates/
│   ├── base.html
│   └── home.html
├── __init__.py
├── admin.py
├── apps.py
├── context_processors.py
├── models.py
├── urls.py
└── views.py
```

This completes the updated setup guide for the Django Authentication System with Magic Links and Security Preferences. For more information, please refer to the documentation or contact the maintainers.