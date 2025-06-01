# 1. Validate cyberthreat infrastructure | GW10 Guild 3 Team 4
As malicious actors change and relocate their infrastructure to avoid detection, we need to :
* A. constantly verify that our data and **indicators of compromise (IoCs)** are still valid
* B. regularly browse the Internet to validate existing information about malicious infrastructure
* C. Could we build something similar to Shodan or Censys  ?
* D. that could confirm command and control (C2) information for a specific malware family?

## 1.1 Setup a Django [ Python Framework ] Web Project

```bash
# Create a Python Virtual Environment [ Avoids messing with the Python instance used by your OS ]
> python -m venv .venv
> source .venv/bin/activate
> pip install django requests

# start the 'c2_scanner' Django project
> django-admin startproject c2_scanner
> cd c2_scanner

> ------------------------------------------------

# create a Django application 'scanner'
> python manage.py startapp scanner

# register the 'scanner' app in the 'c2_scanner' project
> vim c2_scanner/settings.py
>> INSTALLED_APPS = [ ..., 'scanner', ]

# define 'scanner' app Django models [ Database, Table Schemas ]
> vim c2_scanner/scanner/models.py

>> class SuspiciousIP(models.Model):
>>     malware_name = models.CharField(max_length=255)  # Example: SuperShell, HookBot, Chaos...
>>     url = models.URLField()  # Malicious URLs associated with the malware
>>     ip_address = models.GenericIPAddressField()  # Suspicious IP address
>>     first_seen = models.DateTimeField()  # Date when the threat was first detected
>> 
>>     def __str__(self): # to print each 'SuspiciousIP' item data back
>>         return f"{self.malware_name} - {self.url} - {self.ip_address} - {self.first_seen}"

# Test the Django Model (database schema) in a Shell
> python manage.py shell

>>> from scanner.models import SuspiciousIP
>>> from datetime import datetime
>>> test_entry = SuspiciousIP.objects.create(
      malware_name="Supershellza", 
      url="http://38.12.252.74:8888/supershellza/login/", 
      ip_address="38.12.252.74", 
      first_seen=datetime.strptime("30-05-2025", "%d-%m-%Y")    )
>>> print(f"Added: {test_entry}")

# List current contents of the database
> python manage.py dbshell
>>sqlite> SELECT * FROM scanner_suspiciousip;

# migrate (update) the Django sqlite database [ c2_scanner/db.sqlite3 ]
> python manage.py makemigrations
> python manage.py migrate

> ------------------------------------------------

# setup URL rootings from the 'c2_scanner' project into the 'scanner' app 
> vim c2_scanner/urls.py
>> urlpatterns = [ path('', include('scanner.urls')), ]

> vim c2_scanner/scanner/urls.py
>> urlpatterns = [ path('scraped/', view_BLAH_BLAH, name='scraped'), ]

> ------------------------------------------------

# create a Django 'View' to display Table/Model (ex.: SuspiciousIP) items in a webpage 'Template'
> vim scanner/views.py

>> def view_BLAH_BLAH(request):
>>     threats = .models.SuspiciousIP.objects.all()
>>     return render(request, 'scanner/<myTemplate>.html', {'threatsss': threats})

> ------------------------------------------------

# create a HTML webpage to display Table (ex.: 'SuspiciousIP') items
> vim c2_scanner/scanner/templates/scanner/<myTemplate>.html

>> {% for threat in threatsss %}
>>     {{ threat.malware_name }}
>>     {{ threat.url }}
>>     {{ threat.ip_address }}
>>     {{ threat.first_seen }}
>> {% endfor %}

> ------------------------------------------------

# Set Allowed server(s) (ex.: AWS VM, or localhost machine, or all '*'...etc)
> vim c2_scanner/settings.py

>> DEBUG = True
>> ALLOWED_HOSTS = ['16.52.13.252', '*']

# Run the project [ start service ]
> python manage.py runserver 0.0.0.0:8000 &

# Browse the web application
> [Web Browser] http://127.0.0.1:8000
```

## 1.2 Setup the Django Admin Console

```bash
# Register the Models (database schemas) into the admin console
> vim c2_scanner/scanner/admin.py

>> from .models import SuspiciousIP
>> admin.site.register(SuspiciousIP)

# Create Django Admin Console superuser
> python manage.py createsuperuser

# Login to the Django Admin console
> [Web Browser Login] http://127.0.0.1:8000/admin          # adnane / I..1
```

# 2. C2 Threats Databases : Censys + Shodan.io + VirusTotal

* B. regularly browse the Internet to validate existing information about malicious infrastructure
    - Scrape threat databases online...
* C. Could we build something similar to
    - Shodan or Censys  ?

## 2.1 Scrapy : scrape list of IPs/Ports

1.1 'Start SCAN' Button
1.2 DISPLAY IPs:Ports in a Bootstrap Formatted List
// instead of an IP Scan form, how to scrape IP:port pairs from online sites like 'https://tracker.viriback.com/' and use those values

### 2.1.1 https://tracker.viriback.com/

```bash
Test a '' input to the Table in the Django shell
    python manage.py shell
        > from scanner.models import SuspiciousIP
        > from datetime import datetime
        > test_entry = SuspiciousIP.objects.create(
            malware_name="Supershell", 
            url="http://38.12.252.74:8888/supershell/login/", 
            ip_address="38.12.252.74", 
            first_seen=datetime.strptime("30-05-2025", "%d-%m-%Y")
            )
        > print(f"Added: {test_entry}")
    python manage.py dbshell
        > SELECT * FROM scanner_suspiciousip;
```

# 3. Nuclei vs. Zgrab2

Zgrab2 = scans locally
JA4+ = Fingerprint Servers independent of IP:Port used

# 4. Django Decision : Block / Allow

- Create a fake C2 server VM in AWS |
    - Site Admin declares threat  
- Add fingerprint to Django DB manually ?
- Run 2nd instance of the fake C2 VM on a separate IP address
    - Check if the incoming fingerprint gets blocked by
        - the VPN ??

# 5. Deploy to an AWS Virtual Machine (VM)

<h2> AWS VM </h2>

ssh -i "/Users/adnane/Downloads/VM-Key-Mullvad_VPN.pem" ubuntu@15.157.114.18

<h1> Running the app </h1>

nohup python manage.py runserver 0.0.0.0:8000 &
