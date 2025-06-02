from django.shortcuts import render

# Create your views here.

from .forms import IPScanForm
from .models import ScanResult

from .models import SuspiciousIP  # items scaped from 'ViriBack C2 Tracker' 
from django.http import JsonResponse
import subprocess, requests
from .scraper import run_scraper

def start_scraping(request):
    run_scraper()
    return JsonResponse({"status": "Scraping started"})

def view_Scraped_C2_Threats(request):
    # print('Displaying Threats Scraped from https://tracker.viriback.com/')
    # entries = SuspiciousIP.objects.all().values("malware_name", "url", "ip_address", "first_seen")
    
    # return render(request, "scanner/scraped.html", context)
    # return JsonResponse(list(entries), safe=False)

    threats = SuspiciousIP.objects.all()
    return render(request, 'scanner/scraped.html', {'threats': threats})

def check_threatfox(ip):
    url = "https://threatfox.abuse.ch/api/v1/"
    resp = requests.post(url, json={"query": "search_ioc", "search_term": ip})
    return bool(resp.json().get("data"))

def zgrab2_scan(ip):
    try:
        result = subprocess.run(
            ["zgrab2", "tls", "--port", "443", "--timeout", "5", "--jarm", "--", ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {str(e)}"

def home(request):
    context = {}
    if request.method == "POST":
        form = IPScanForm(request.POST)
        if form.is_valid():
            ip = form.cleaned_data['ip_address']
            is_threat = check_threatfox(ip)
            jarm_output = zgrab2_scan(ip) if not is_threat else "ThreatFox marked as malicious"
            ScanResult.objects.create(ip=ip, is_threat=is_threat, raw_output=jarm_output)
            context.update({
                'ip': ip,
                'is_threat': is_threat,
                'jarm_output': jarm_output,
                'form': form,
            })
    else:
        form = IPScanForm()
    context['form'] = form
    context['results'] = ScanResult.objects.order_by('-timestamp')[:10]
    return render(request, "scanner/home.html", context)