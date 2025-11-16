from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import UserProfile, UserPreferences

User = get_user_model()

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Create UserProfile and UserPreferences instances when a new User is created.
    """
    if created:
        if not hasattr(instance, 'profile'):
            UserProfile.objects.create(user=instance)
        if not hasattr(instance, 'preferences'):
            UserPreferences.objects.create(user=instance)