<h1> Threat identification : Command & Control (C2) Servers </h1>

0. Setup Django Project
    # Create a Python Virtual Environment
    python -m venv .venv
    source .venv/bin/activate
    pip install django requests

    # start the 'c2_scanner' Django project
    django-admin startproject c2_scanner
    cd c2_scanner

    # add the 'scanner' Django application
    python manage.py startapp scanner
    # under 'c2_scanner/settings.py', register the 'scanner' app in the 'c2_scanner' project
    INSTALLED_APPS = [ ..., 'scanner', ]

    # under 'scanner/models.py:' Define the Django models (Database/Tables)
    Table 'models.Model.<myTable>' - [ ex.: store IPs from Viriback C2 Tracker ]
        models.Model.<myTable>.malware_name
        models.Model.<myTable>.url
        models.Model.<myTable>.ip_address
        models.Model.<myTable>.first_seen
    # migrate (update) the Django sqlite databases
    python manage.py makemigrations
    python manage.py migrate

    # under '/c2_scanner/urls.py' ---> '/scanner/urls.py' setup URL rootings
    urlpatterns = [ path('', include('scanner.urls')), ]
    urlpatterns = [ path('scraped/', view_BLAH_BLAH, name='scraped'), ]

    # under 'scanner/views.py' setup the ***DJANGO MAGIC***
    def view_BLAH_BLAH(request): 
        threats = .models.<myTable>.objects.all()
        return render(request, 'scanner/<scraped>.html', {'threatsss': threats})

    # under 'scanner/templates/scanner/<myTemplate>.html' create the HTML dynamic template page & display results
    {% for threat in threatsss %}
        <p>{{ threat.malware_name }}</p>
        <p><a href="{{ threat.url }}" target="_blank">{{ threat.url }}</a></p>
        <p>{{ threat.ip_address }}</p>
        <p>{{ threat.first_seen }}</p>
    {% endfor %}

    # Run the project
    python manage.py runserver 0.0.0.0:8000     # start service ; Open ---> http://127.0.0.1:8000

    # Create Django Admin Console superuser
    python manage.py createsuperuser            # adnane / I..1    |  Login --->  http://127.0.0.1:8000/admin


1. Scrapy : scrape list of IPs/Ports
    1.0 Create 'SuspiciousIP' Table in models.py
            1.0.0 Migrate changes
                python manage.py makemigrations scanner
                python manage.py migrate
            1.0.1 Test a 'https://tracker.viriback.com/' input to the Table in the Django shell
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


    1.1 'Start SCAN' Button
    1.2 DISPLAY IPs:Ports in a Bootstrap Formatted List
        // instead of an IP Scan form, how to scrape IP:port pairs from online sites like 'https://tracker.viriback.com/' and use those values

2. C2 Threats Databases : Censys + Shodan.io + VirusTotal
3. Zgrab2 : Scan locally | JA4+ = Fingerprint Servers independent of IP:Port used
4. Django : Block / Allow 

<h2> AWS VM </h2>

ssh -i "/Users/adnane/Downloads/VM-Key-Mullvad_VPN.pem" ubuntu@15.157.114.18

<h1> Running the app </h1>

nohup python manage.py runserver 0.0.0.0:8000 &
