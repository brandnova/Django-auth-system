from .models import UserProfile, UserSocialAccount

def create_user_profile(backend, user, response, *args, **kwargs):
    """
    Create a user profile if it doesn't exist.
    Also create a UserSocialAccount entry to store social account details.
    """
    # Create user profile if it doesn't exist
    if not hasattr(user, 'profile'):
        UserProfile.objects.create(user=user)
    
    # Get or create social account
    provider = backend.name
    uid = kwargs.get('uid') or response.get('id')
    
    if provider and uid:
        social_account, created = UserSocialAccount.objects.get_or_create(
            user=user,
            provider=provider,
            provider_id=uid
        )
        
        # Update social account data
        if 'picture' in response:
            social_account.provider_avatar = response['picture']
        elif provider == 'facebook' and 'id' in response:
            social_account.provider_avatar = f"https://graph.facebook.com/{response['id']}/picture?type=large"
        elif provider == 'github' and 'avatar_url' in response:
            social_account.provider_avatar = response['avatar_url']
        
        # Store extra data
        social_account.extra_data = response
        social_account.save()
    
    return {'user': user, 'is_new': kwargs.get('is_new', False)}

def set_email_verified(backend, user, response, *args, **kwargs):
    """
    Set the user's email as verified when they sign up with a social account.
    """
    if not user.is_email_verified:
        user.is_email_verified = True
        user.save()
    
    return None