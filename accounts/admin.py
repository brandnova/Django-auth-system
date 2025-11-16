from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import (
    User,
    UserProfile,
    UserSocialAccount,
    MagicLinkToken,
    UserPreferences,
)


class CustomUserAdmin(UserAdmin):
    """
    Custom admin interface for the User model.
    """
    list_display = (
        'email',
        'username',
        'first_name',
        'last_name',
        'is_email_verified',
        'is_staff',
    )
    list_filter = ('is_staff', 'is_superuser', 'is_email_verified', 'is_active')
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('email',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('username', 'first_name', 'last_name')}),
        (_('Permissions'), {
            'fields': (
                'is_active',
                'is_email_verified',
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions',
            ),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2'),
        }),
    )


class UserProfileAdmin(admin.ModelAdmin):
    """
    Admin interface for the UserProfile model.
    """
    list_display = ('user', 'location', 'date_of_birth', 'created_at')
    search_fields = ('user__email', 'user__username', 'location')
    list_filter = ('created_at',)


class UserSocialAccountAdmin(admin.ModelAdmin):
    """
    Admin interface for the UserSocialAccount model.
    """
    list_display = ('user', 'provider', 'created_at')
    list_filter = ('provider', 'created_at')
    search_fields = ('user__email', 'provider', 'provider_id')


class MagicLinkTokenAdmin(admin.ModelAdmin):
    """
    Admin interface for the MagicLinkToken model.
    """
    list_display = ('user', 'token', 'used', 'created_at', 'expires_at')
    list_filter = ('used', 'created_at', 'expires_at')
    search_fields = ('token', 'user__email')
    readonly_fields = ('created_at',)


class UserPreferencesAdmin(admin.ModelAdmin):
    """
    Admin interface for the UserPreferences model.
    """
    list_display = ('user', 'enable_magic_links', 'enable_login_notifications', 'created_at')
    list_filter = ('enable_magic_links', 'enable_login_notifications', 'created_at')
    search_fields = ('user__email',)
    readonly_fields = ('created_at', 'updated_at')


# Register the models with their custom admin classes
admin.site.register(User, CustomUserAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(UserSocialAccount, UserSocialAccountAdmin)
admin.site.register(MagicLinkToken, MagicLinkTokenAdmin)
admin.site.register(UserPreferences, UserPreferencesAdmin)
