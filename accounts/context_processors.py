from django.conf import settings

def magic_link_settings(request):
    """
    Context processor to make magic link settings available in all templates.
    """
    return {
        'MAGIC_LINK_TOKEN_LIFESPAN': getattr(settings, 'MAGIC_LINK_TOKEN_LIFESPAN', 10),
        'MAGIC_LINK_VERIFY_IP': getattr(settings, 'MAGIC_LINK_VERIFY_IP', False),
    }