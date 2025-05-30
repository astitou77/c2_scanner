from django.urls import path
from .views import home

from scanner.views import view_Scraped_C2_Threats

urlpatterns = [
    path('', home, name='home'),
    path('scraped/', view_Scraped_C2_Threats, name='scraped'),
]