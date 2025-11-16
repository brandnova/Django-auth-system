from django.contrib import admin
from django_ckeditor_5.widgets import CKEditor5Widget
from django import forms
from .models import SiteSettings, StaticPage

@admin.register(SiteSettings)
class SiteSettingsAdmin(admin.ModelAdmin):
    # There should realistically be only one, but fine.
    list_display = ("site_name", "contact_email")
    fieldsets = (
        ("General", {
            "fields": ("site_name", "site_description", "logo", "favicon")
        }),
        ("Contact", {
            "fields": ("contact_email",)
        }),
    )


@admin.register(StaticPage)
class StaticPageAdmin(admin.ModelAdmin):
    list_display = ("title", "slug", "is_active", "created_at", "updated_at")
    list_filter = ("is_active",)
    search_fields = ("title", "slug", "content")
    prepopulated_fields = {"slug": ("title",)}
    readonly_fields = ("created_at", "updated_at")
    ordering = ("title",)