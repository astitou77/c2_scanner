from django import forms

class IPScanForm(forms.Form):
    ip_address = forms.GenericIPAddressField(label="IP to scan")