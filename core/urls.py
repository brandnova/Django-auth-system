from django.urls import path
from . import views

urlpatterns = [
    path('', views.HomePageView.as_view(), name='home'),
    path('pages/<slug:slug>/', views.StaticPageView.as_view(), name='static_page'),
]