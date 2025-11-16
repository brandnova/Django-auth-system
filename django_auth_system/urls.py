from django.contrib import admin
from django.urls import include, path, re_path 
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve 

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')),
    path('2fa/', include('twofactor.urls')),
    path('accounts/', include('accounts.urls')),
    path('ckeditor5/', include('django_ckeditor_5.urls')),
    path('social-auth/', include('social_django.urls', namespace='social')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
else:
    # Add this for production
    urlpatterns += [
        re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
    ]
