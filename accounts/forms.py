from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordResetForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from .models import UserProfile

User = get_user_model()

# ----- Inline Tailwind Widgets -----
TAILWIND_BASE_CLASSES = "w-full px-3 py-2 border border-secondary-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"

class TailwindTextInput(forms.TextInput):
    def __init__(self, attrs=None):
        default_attrs = {'class': TAILWIND_BASE_CLASSES}
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)

class TailwindEmailInput(forms.EmailInput):
    def __init__(self, attrs=None):
        default_attrs = {
            'class': TAILWIND_BASE_CLASSES,
            'placeholder': 'you@email.com',
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)

class TailwindPasswordInput(forms.PasswordInput):
    def __init__(self, attrs=None):
        default_attrs = {
            'class': TAILWIND_BASE_CLASSES,
            'placeholder': '••••••••',
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)

class TailwindTextarea(forms.Textarea):
    def __init__(self, attrs=None):
        default_attrs = {
            'class': TAILWIND_BASE_CLASSES,
            'rows': 4
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)

class TailwindDateInput(forms.DateInput):
    def __init__(self, attrs=None, format=None):
        default_attrs = {
            'class': TAILWIND_BASE_CLASSES,
            'type': 'date'
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs, format=format)

class TailwindFileInput(forms.ClearableFileInput):
    def __init__(self, attrs=None):
        default_attrs = {'class': TAILWIND_BASE_CLASSES}
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)

# ----- Forms -----

class SignupForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=True, widget=TailwindTextInput())
    last_name = forms.CharField(max_length=30, required=True, widget=TailwindTextInput())
    email = forms.EmailField(
        max_length=254, required=True,
        help_text='Required. Enter a valid email address.',
        widget=TailwindEmailInput()
    )
    username = forms.CharField(
        max_length=150, required=False,
        help_text='Optional. Letters, digits and @/./+/-/_ only.',
        widget=TailwindTextInput()
    )
    password1 = forms.CharField(label=_("Password"), strip=False, widget=TailwindPasswordInput())
    password2 = forms.CharField(label=_("Confirm Password"), strip=False, widget=TailwindPasswordInput())
    captcha = forms.CharField(widget=forms.HiddenInput(), required=False)

    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data
    
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'username', 'email', 'password1', 'password2')
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError(_("A user with that email already exists."))
        return email
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if not username:
            return None
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError(_("A user with that username already exists."))
        return username

class LoginForm(AuthenticationForm):
    username = forms.EmailField(label=_("Email"), widget=TailwindEmailInput(attrs={'autofocus': True}))
    password = forms.CharField(label=_("Password"), strip=False, widget=TailwindPasswordInput())
    
    error_messages = {
        'invalid_login': _("Please enter a correct email and password. Note that both fields may be case-sensitive."),
        'inactive': _("This account is inactive. Please verify your email address."),
        'not_verified': _("Please verify your email address before logging in."),
        'pending_deletion': _("Your account is scheduled for deletion. Enter your password to reactivate it."),
    }
    captcha = forms.CharField(widget=forms.HiddenInput(), required=False)
    
    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data
    
    def confirm_login_allowed(self, user):
        if user.is_pending_deletion:
            return
        if not user.is_active:
            raise forms.ValidationError(self.error_messages['inactive'], code='inactive')
        if not user.is_email_verified:
            raise forms.ValidationError(self.error_messages['not_verified'], code='not_verified')

class CustomPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(label=_("Email"), max_length=254, widget=TailwindEmailInput(attrs={'autocomplete': 'email'}))

class CustomSetPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(label=_("New password"), widget=TailwindPasswordInput(attrs={'autocomplete': 'new-password'}), strip=False)
    new_password2 = forms.CharField(label=_("Confirm new password"), strip=False, widget=TailwindPasswordInput(attrs={'autocomplete': 'new-password'}))

class CustomPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(label=_("Current Password"), strip=False, widget=TailwindPasswordInput(attrs={'autocomplete': 'new-password'}))
    new_password1 = forms.CharField(label=_("New Password"), strip=False, widget=TailwindPasswordInput(attrs={'autocomplete': 'new-password'}), help_text=None)
    new_password2 = forms.CharField(label=_("Confirm New Password"), strip=False, widget=TailwindPasswordInput(attrs={'autocomplete': 'new-password'}))

class ProfileUpdateForm(forms.ModelForm):
    first_name = forms.CharField(max_length=30, required=True, widget=TailwindTextInput())
    last_name = forms.CharField(max_length=30, required=True, widget=TailwindTextInput())
    username = forms.CharField(max_length=150, required=False, widget=TailwindTextInput())
    
    class Meta:
        model = UserProfile
        fields = ('avatar', 'bio', 'location', 'date_of_birth')
        widgets = {
            'avatar': TailwindFileInput(),
            'bio': TailwindTextarea(),
            'location': TailwindTextInput(),
            'date_of_birth': TailwindDateInput(),
        }
    
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            self.fields['first_name'].initial = user.first_name
            self.fields['last_name'].initial = user.last_name
            self.fields['username'].initial = user.username

class EmailChangeForm(forms.Form):
    email = forms.EmailField(label=_("New email address"), max_length=254, widget=TailwindEmailInput(attrs={'autocomplete': 'email'}))
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email == self.user.email:
            raise forms.ValidationError(_("This is already your email address."))
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError(_("A user with that email already exists."))
        return email
