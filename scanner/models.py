from django.db import models

# Create your models here.

class ScanResult(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField()
    is_threat = models.BooleanField()
    jarm_fingerprint = models.TextField(null=True, blank=True)
    raw_output = models.TextField()