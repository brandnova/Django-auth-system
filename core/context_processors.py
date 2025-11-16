from .models import SiteSettings, StaticPage

def site_settings(request):
    # Load the singleton settings object
    settings_obj = SiteSettings.load()
    return {
        'site_settings': settings_obj
    }

def static_pages(request):
    # Provide all active static pages, ordered by title
    pages = StaticPage.objects.filter(is_active=True).order_by('title')
    return {
        'static_pages': pages
    }
