<h1> Threat identification : Command & Control (C2) Servers </h1>

## 0. Setup Django Project
    <b> Create a Python Virtual Environment </b>
    python -m venv .venv </br>
    source .venv/bin/activate </br>
    pip install django requests </br>

    <b> start the 'c2_scanner' Django project </b>
    django-admin startproject c2_scanner </br>
    cd c2_scanner </br>

    <b> add the 'scanner' Django application </b>
    python manage.py startapp scanner </br>
    ### under 'c2_scanner/settings.py', register the 'scanner' app in the 'c2_scanner' project
    INSTALLED_APPS = [ ..., 'scanner', ] </br>

    <b> under 'scanner/models.py:' Define the Django models (Database/Tables) </b>
    Table 'models.Model.<myTable>' - [ ex.: store IPs from Viriback C2 Tracker ] </br>
        &nbsp;&nbsp;&nbsp;&nbsp; models.Model.<myTable>.malware_name </br>
        &nbsp;&nbsp;&nbsp;&nbsp; models.Model.<myTable>.url </br>
        &nbsp;&nbsp;&nbsp;&nbsp; models.Model.<myTable>.ip_address </br>
        &nbsp;&nbsp;&nbsp;&nbsp; models.Model.<myTable>.first_seen </br>
    <b> migrate (update) the Django sqlite databases </b>
    python manage.py makemigrations </br>
    python manage.py migrate </br>

    <b> under '/c2_scanner/urls.py' ---> '/scanner/urls.py' setup URL rootings </b>
    urlpatterns = [ path('', include('scanner.urls')), ] </br>
    urlpatterns = [ path('scraped/', view_BLAH_BLAH, name='scraped'), ] </br>

    <b> under 'scanner/views.py' setup the ***DJANGO MAGIC*** </b>
    def view_BLAH_BLAH(request):  </br>
        &nbsp;&nbsp;&nbsp;&nbsp; threats = .models.<myTable>.objects.all() </br>
        &nbsp;&nbsp;&nbsp;&nbsp; return render(request, 'scanner/<scraped>.html', {'threatsss': threats})

    <b> under 'scanner/templates/scanner/<myTemplate>.html' create the webpage to display </b>
    {% for threat in threatsss %} </br>
        &nbsp;&nbsp;&nbsp;&nbsp; {{ threat.malware_name }} </br>
        &nbsp;&nbsp;&nbsp;&nbsp; {{ threat.url }} </br>
        &nbsp;&nbsp;&nbsp;&nbsp; {{ threat.ip_address }} </br>
        &nbsp;&nbsp;&nbsp;&nbsp; {{ threat.first_seen }} </br>
    {% endfor %}

    <b> Run the project </b>
    python manage.py runserver 0.0.0.0:8000     # start service ; Open ---> http://127.0.0.1:8000

    <b> Create Django Admin Console superuser </b>
    python manage.py createsuperuser            # adnane / I..1    |  Login --->  http://127.0.0.1:8000/admin



 </br> </br> </br> </br>

 
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
