from django.contrib import admin

# Customize the Admin Console

admin.site.site_header = "Guild 3 Team 4"
admin.site.site_title = "GeekWeek10"
admin.site.index_title = "Validating cyber threat infrastructure"


# Register your models here. (into the admin)

from .models import SuspiciousIP2
from .models import SuspiciousIP
from .models import ScanResult

admin.site.register(SuspiciousIP2)
admin.site.register(SuspiciousIP)
admin.site.register(ScanResult)


