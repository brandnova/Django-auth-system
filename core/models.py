from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.utils.text import slugify
from django_ckeditor_5.fields import CKEditor5Field

class SiteSettings(models.Model):
    site_name = models.CharField(_('site name'), max_length=100, default='CivicLink')
    site_description = models.TextField(_('site description'), blank=True)
    logo = models.ImageField(_('logo'), upload_to='site/', blank=True)
    favicon = models.ImageField(_('favicon'), upload_to='site/', blank=True)
    
    # Email settings
    contact_email = models.EmailField(_('contact email'), blank=True)
    
    class Meta:
        verbose_name = _('site settings')
        verbose_name_plural = _('site settings')
    
    def __str__(self):
        return self.site_name
    
    @classmethod
    def load(cls):
        obj, created = cls.objects.get_or_create(pk=1)
        return obj
 
class StaticPage(models.Model):
    
    title = models.CharField(_('title'), max_length=200)
    slug = models.SlugField(_('slug'), max_length=200, unique=True)
    content = CKEditor5Field(_('content'), config_name='extends')
    is_active = models.BooleanField(_('is active'), default=True)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    meta_title = models.CharField(_('meta title'), max_length=200, blank=True)
    meta_description = models.TextField(_('meta description'), blank=True)

    class Meta:
        verbose_name = _('static page')
        verbose_name_plural = _('static pages')
        ordering = ['title']

    def __str__(self):
        return f"{self.title}"

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('static_page', kwargs={'slug': self.slug})