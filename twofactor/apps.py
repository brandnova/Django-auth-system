from django.apps import AppConfig


class TwoFactorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'twofactor'
    verbose_name = 'Two-Factor Authentication'

    def ready(self):
        import twofactor.signals