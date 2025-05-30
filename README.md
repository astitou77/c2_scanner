<h1> Threat identification : Command & Control (C2) Servers </h1>

0. Setup Django Project

    django-admin startproject c2_scanner
    python venv .venv
    source .venv/bin/activate

    # Create Django Admin Console superuser
    python manage.py createsuperuser    # adnane / Ib..1
    python manage.py runserver          


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
