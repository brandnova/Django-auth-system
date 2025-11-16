from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    # Authentication URLs
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('activate/<uidb64>/<token>/', views.activate_account_view, name='activate'),
    path('verify-email-change/<uidb64>/<token>/', views.verify_email_change_view, name='verify_email_change'),

    # Magic Links URLs
    path('login/magic-link/', views.magic_link_request_view, name='magic_link_request'),
    path('login/magic-link/<str:token>/', views.magic_link_verify_view, name='magic_link_verify'),
    
    # Toggle URLs
    path('toggle-magic-links/', views.toggle_magic_links_view, name='toggle_magic_links'),
    path('toggle-login-notifications/', views.toggle_login_notifications_view, name='toggle_login_notifications'),
    
    # Password management
    path('password-reset/', views.password_reset_view, name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/', 
         views.password_reset_confirm_view, name='password_reset_confirm'),
    path('password-change/', views.password_change_view, name='password_change'),
    
    # Profile management
    path('profile/', views.profile_view, name='profile'),
    path('profile/edit/', views.profile_update_view, name='profile_edit'),
    path('profile/edit/images/', views.profile_images_update_view, name='profile_edit_images'),
    path('email/change/', views.email_change_view, name='email_change'),
    path('security/', views.security_settings, name='security_settings'),
    path('delete-account/', views.delete_account, name='delete_account'),
]