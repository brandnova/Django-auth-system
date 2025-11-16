from django.views.generic import DetailView
from .models import StaticPage
from django.views.generic import TemplateView
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin

User = get_user_model()

class StaticPageView(DetailView):
    model = StaticPage
    template_name = 'core/static_page.html'
    context_object_name = 'page'
    slug_field = 'slug'
    slug_url_kwarg = 'slug'
    
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True)

class HomePageView(TemplateView):
    template_name = 'core/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['active_users'] = User.objects.filter(is_active=True).count()  # Example stat
        return context
