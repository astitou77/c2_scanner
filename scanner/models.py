from django.db import models

class SuspiciousIP2(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    ja4_fingerprint = models.TextField(null=True, blank=True)


### 1. Data Scraped from 'https://tracker.viriback.com/' will be stored in this Table:

class SuspiciousIP(models.Model):
    malware_name = models.CharField(max_length=255)  # Example: SuperShell, HookBot, Chaos...
    url = models.URLField()  # Malicious URLs associated with the malware
    ip_address = models.GenericIPAddressField()  # Suspicious IP address
    first_seen = models.DateTimeField()  # Date when the threat was first detected
    jarm_hash = models.CharField(max_length=64, blank=True, null=True)  # New field for JARM hash
    ja4_hash = models.CharField(max_length=64, blank=True, null=True)  # New field for JARM hash
    c2_decision = models.BooleanField()

    def __str__(self):
        return f"{self.malware_name} - {self.url} - {self.ip_address} - {self.first_seen} - {self.jarm_hash}"


### 2. Results to be displayed for Suspicious IP:Port pairs will be stored in this Table:

class ScanResult(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField()
    is_threat = models.BooleanField()
    jarm_fingerprint = models.TextField(null=True, blank=True)
    raw_output = models.TextField()

    def __str__(self):
        return f"{self.timestamp} - {self.ip} - {self.is_threat} - {self.jarm_fingerprint} - {self.raw_output}"