# Django Authentication System

A complete, production-ready authentication system for Django with modern features and security best practices.
>**Django Authentication System** is a **modern, secure, and production-ready authentication platform** for Django projects. It replaces traditional username logins with email-based authentication, supports social logins (Google, GitHub, Discord, Facebook), and offers advanced security features like passwordless magic links, optional two-factor authentication, and user-controlled security preferences. Built with a responsive Tailwind CSS UI, reCAPTCHA protection, and fully extensible user profiles, this system makes adding robust authentication to any Django project **fast, secure, and developer-friendly**.

## ✨ Features

- **Email-based Authentication** - No usernames, just email and password
- **Social Authentication** - Google, GitHub, Discord, and Facebook
- **Magic Links** - Passwordless login via secure email links
- **Two-Factor Authentication** - Optional 2FA with email and authenticator app support
- **Security Preferences** - User-controlled security settings
- **reCAPTCHA Protection** - Secure forms with Google reCAPTCHA
- **User Profiles** - Extensible profile system with avatars and bio
- **Account Security** - Login notifications, email verification, soft deletion
- **Modern UI** - Responsive design with dark mode support

## 🚀 Quick Start

### Installation

1. **Add to your project**:
   ```bash
   # Copy accounts, twofactor (optional), and core apps to your project
   cp -r accounts twofactor core /path/to/your/project/
   ```

2. **Update settings.py**:
   ```python
   INSTALLED_APPS = [
       'django.contrib.admin',
       'django.contrib.auth',
       'django.contrib.contenttypes',
       'django.contrib.sessions',
       'django.contrib.messages',
       'django.contrib.staticfiles',
       'social_django',
       'accounts',
       'twofactor',  # Optional
       'core',
   ]

   AUTH_USER_MODEL = 'accounts.User'
   AUTHENTICATION_BACKENDS = [
      'django.contrib.auth.backends.ModelBackend',
      'accounts.backends.EmailBackend',  
      'social_core.backends.github.GithubOAuth2',
      'social_core.backends.discord.DiscordOAuth2',
      'social_core.backends.google.GoogleOAuth2',
      'social_core.backends.facebook.FacebookOAuth2',
   ]

   LOGIN_URL = 'accounts:login'
   LOGIN_REDIRECT_URL = 'accounts:profile'
   ```

3. **Update urls.py**:
   ```python
   urlpatterns = [
       path('admin/', admin.site.urls),
       path('', include('core.urls')),
       path('accounts/', include('accounts.urls')),
       path('2fa/', include('twofactor.urls')),  # Optional
       path('social-auth/', include('social_django.urls', namespace='social')),
   ]
   ```

4. **Run migrations**:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

## ⚙️ Configuration

### Required Settings

```python
# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@gmail.com'
EMAIL_HOST_PASSWORD = 'your-app-password'

# Social Auth (Optional)
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = 'your-google-client-id'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'your-google-client-secret'

# reCAPTCHA (Optional)
RECAPTCHA_ENABLED = True
RECAPTCHA_SITE_KEY = 'your-site-key'
RECAPTCHA_SECRET_KEY = 'your-secret-key'

# Magic Links (Optional)
MAGIC_LINK_TOKEN_LIFESPAN = 10  # Minutes
```

### Environment Variables

Use a `.env` file for sensitive settings:

```bash
# Email
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Social Auth
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY=your-client-id
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET=your-client-secret

# reCAPTCHA
RECAPTCHA_SITE_KEY=your-site-key
RECAPTCHA_SECRET_KEY=your-secret-key
```

## 🔐 Key Features

### Magic Links Authentication
- Passwordless login via secure email links
- User-controlled (disabled by default)
- Configurable expiration (default: 10 minutes)
- Single-use tokens for security

### Security Preferences
- Enable/disable magic links
- Control login notifications
- Security warnings for sensitive changes
- Modern toggle interface

### Social Authentication
- Google, GitHub, Discord, Facebook
- Automatic profile creation
- Email verification bypass for social accounts
- Provider-specific avatars

### Two-Factor Authentication
- Optional 2FA module
- Email OTP and authenticator app support
- Backup codes
- Easy enable/disable

## 🛠 Management Commands

```bash
# Create superuser with email
python manage.py createsuperuser_email

# Cleanup deleted accounts (for production)
python manage.py cleanup_deleted_accounts

# Dry run cleanup
python manage.py cleanup_deleted_accounts --dry-run
```

## 🎨 Customization

### Templates
All templates are located in:
- `accounts/templates/accounts/` - Authentication templates
- `accounts/templates/accounts/emails/` - Email templates
- `accounts/templates/accounts/security/` - Security settings

### Models
Extend user profiles by modifying:
- `UserProfile` model in `accounts/models.py`
- Add signals for custom profile creation

### Styling

Uses Tailwind CSS with Alpine.js for interactions. Customize the base template in `core/templates/base.html`.

**Tailwind Build System**
The project includes a standalone `Tailwind/` directory that handles all Tailwind compilation using Node. This system scans Django templates and static JS files for Tailwind classes and automatically generates the final `static/css/tailwind.css` file.
For full setup and usage details, see `Tailwind/IMPORTANT.md`.

## 🔧 Integration

### Protecting Views
```python
from django.contrib.auth.decorators import login_required

@login_required
def protected_view(request):
    return render(request, 'app/protected.html')
```

### User References
```python
from django.conf import settings

class Post(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
```

## 🚨 Troubleshooting

### Common Issues

**Emails not sending?**
- Check EMAIL_BACKEND and SMTP settings
- Use console backend for development: `EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'`

**Social auth not working?**
- Verify callback URLs in provider settings
- Check social auth keys in environment

**Migration errors?**
```bash
python manage.py makemigrations
python manage.py migrate --fake-initial
```

## 📁 Project Structure

```
project/
├── accounts/          # Core authentication
├── twofactor/         # 2FA (optional)
├── core/             # Base templates
└── your_app/         # Your custom apps
```

## 📚 Documentation (MkDocs)

For detailed documentation, see the full setup guide in the `docs/` directory. The `docs/` directory contains the full project documentation powered by [MkDocs](https://www.mkdocs.org/). 

- `mkdocs.yml`: Main configuration file.
- `docs/`: Markdown files and images used for the docs.
  
You can build and preview the docs locally:

```bash
# Install MkDocs if not already installed
pip install mkdocs

# Install material theme used in the docs
pip install mkdocs-material

# Serve docs locally
cd docs
mkdocs serve
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

---

**Ready to use?** Check out the full [documentation](https://brandnova.github.io/Django-auth-system/
) for advanced configuration and customization options!
