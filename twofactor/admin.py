from django.contrib import admin
from .models import UserTwoFactorSettings, EmailOTP


@admin.register(UserTwoFactorSettings)
class UserTwoFactorSettingsAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_enabled', 'method', 'last_verified', 'created_at', 'updated_at')
    list_filter = ('is_enabled', 'method', 'created_at')
    search_fields = ('user__email',)
    readonly_fields = ('created_at', 'updated_at', 'last_verified')
    list_editable = ('is_enabled', 'method')  # Inline editing in list view

    fieldsets = (
        (None, {
            'fields': ('user', 'is_enabled', 'method')
        }),
        ('TOTP Info', {
            'fields': ('totp_secret', 'backup_codes'),
            'classes': ('collapse',),
        }),
        ('Verification Timestamps', {
            'fields': ('last_verified', 'created_at', 'updated_at')
        }),
    )


@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'is_used', 'created_at', 'expires_at')
    list_filter = ('is_used', 'created_at')
    search_fields = ('user__email', 'code')
    readonly_fields = ('created_at',)

    def has_add_permission(self, request):
        # Usually, OTPs are generated through views, not manually.
        return False
