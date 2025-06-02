from django.urls import path
from .views import home

from scanner.views import view_Scraped_C2_Threats
from scanner.views import start_scraping

urlpatterns = [
    path('', home, name='home'),
    path('scraped/', view_Scraped_C2_Threats, name='scraped'),  # Final table display
    path('scrape/', start_scraping, name='start_scraping'),   # scrapy testing
]