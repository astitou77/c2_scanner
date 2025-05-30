from django.contrib import admin

# Register your models here.

from .models import SuspiciousIP
from .models import ScanResult

admin.site.register(SuspiciousIP)
admin.site.register(ScanResult)
