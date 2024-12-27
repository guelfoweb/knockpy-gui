from django.core.management.base import BaseCommand
from gui.models import Domain, Subdomain, Apikey
from django.utils import timezone
from datetime import datetime

from knock import KNOCKPY
import string
import random
import time
import os

class Command(BaseCommand):
    help = 'Knockpy Subdomain Scan'

    def add_arguments(self, parser):
        parser.add_argument('domain_id', type=int)

    def handle(self, *args, **kwargs):
        start_time = time.time() 

        def wildcard(domain):
            return ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(10, 15))) + '.' + domain

        def create_subdomain(object, domain):
            if Subdomain.objects.filter(name=object['domain'], domain=domain).exists():
                return None

            if object['cert'][1]:
                cert_expiration_date = object['cert'][1]
                cert_expiration_date = datetime.strptime(cert_expiration_date, '%Y-%m-%d')
                cert_expiration_date = timezone.make_aware(cert_expiration_date)
            else:
                cert_expiration_date = None

            subdomain = Subdomain(
                name=object['domain'],
                ip={"ip": object['ip']},
                http_status=object['http'][0],
                http_redirect=object['http'][1],
                http_server=object['http'][2],
                https_status=object['https'][0],
                https_redirect=object['https'][1],
                https_server=object['https'][2],
                cert_status=object['cert'][0],
                cert_expiration_date=cert_expiration_date,
                cert_common_name=object['cert'][2],
                domain=domain
            )
            
            subdomain.save()
            return subdomain
        
        if Apikey.objects.exists():
            apikey = Apikey.objects.first()
            os.environ['API_KEY_VIRUSTOTAL'] = apikey.virustotal
            os.environ['API_KEY_SHODAN'] = apikey.shodan

        domain_id = kwargs['domain_id']

        domain = Domain.objects.get(id=domain_id)

        wildcard = KNOCKPY(wildcard(domain.name))
        messages = {"wildcard": True} if wildcard else {"wildcard": False}
        messages.update({"finished": False})
        messages.update({"count": 0})
        messages.update({"time": 0})
        domain.messages = messages

        if domain.wildcard and wildcard:
            create_subdomain(wildcard, domain)
            messages.update({"count": 1})
        else:
            results = KNOCKPY(
                domain.name, 
                dns=domain.dns, 
                useragent=domain.useragent, 
                timeout=domain.timeout, 
                threads=domain.threads, 
                recon=domain.recon, 
                bruteforce=domain.bruteforce, 
                wordlist=domain.wordlist,
                #silent=True
            )

            if results:
                for result in results:
                    create_subdomain(result, domain)
                messages.update({"count": len(results)})
            messages.update({"finished": True})

        end_time = time.time()
        execution_time = end_time - start_time
        formatted_execution_time = f"{execution_time:.2f}"

        messages.update({"time": formatted_execution_time})

        domain.messages = messages
        domain.completed = True
        domain.save()
        