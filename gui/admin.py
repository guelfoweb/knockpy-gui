from django.contrib import admin
from .models import Domain, Subdomain, Tag, Apikey
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.urls import path
from django.shortcuts import render
from django.core.management import call_command
import threading

class ApikeyAdmin(admin.ModelAdmin):
    list_display = ('virustotal', 'shodan')
    actions = None

    def has_add_permission(self, request):
        return not Apikey.objects.exists()

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context['title'] = "Apikeys"
        return super().changelist_view(request, extra_context=extra_context)

    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        context.update({
            'show_save': True,
            'show_save_and_continue': False,
            'show_save_and_add_another': False,
            'show_delete': True
        })
        return super().render_change_form(request, context, add, change, form_url, obj)

class TagAdmin(admin.ModelAdmin):
    list_display = ('name', 'assigned_domain')
    search_fields = ('name',)
    ordering = ('name',)
    actions = None

    def assigned_domain(self, obj):
        results = ""
        domains = Domain.objects.filter(tag=obj.id)
        if domains:
            for domain in domains:
                results += f"<a href='/admin/gui/subdomain/?domain={domain.id}'>{domain.name}</a><br>"

        return format_html(results)

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context['title'] = "Tags"
        return super().changelist_view(request, extra_context=extra_context)

    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        context.update({
            'show_save': True,
            'show_save_and_continue': False,
            'show_save_and_add_another': False,
            'show_delete': True
        })
        return super().render_change_form(request, context, add, change, form_url, obj)

class DomainAdmin(admin.ModelAdmin):
    def add_view(self, request, form_url='', extra_context=None):
        messages.info(request, "Remember, clicking Save will initiate the scan.")
        return super().add_view(request, form_url, extra_context)

    def change_view(self, request, object_id, form_url='', extra_context=None):
        messages.info(request, "Remember, clicking Save will initiate the scan.")
        return super().change_view(request, object_id, form_url, extra_context)

    list_display = ('name', 'recon', 'bruteforce', 'wildcard', 'configuration', 'status', 'result', 'tag_name', 'created_at')
    search_fields = ('name',)
    ordering = ('created_at',)

    fields = ('name', ('recon', 'bruteforce', 'wildcard'), 'tag')

    def get_fieldsets(self, request, obj=None):
        if not Apikey.objects.exists(): # message alert
            add_apikey = '/admin/gui/apikey/add/'
            messages.warning(request, format_html(f"""
                API Key not found. Set up <a href='{add_apikey}'><b>API keys</b></a> to maximize your scan results.
                """))

        fieldsets = super().get_fieldsets(request, obj)
        advanced_fieldset = (
            'Advanced',
            {
                'fields': ('wordlist', 'useragent', 'dns', 'timeout', 'threads'),
                'classes': ('collapse',),
            },
        )
   
        return list(fieldsets) + [advanced_fieldset]

    def tag_name(self, obj):
        return format_html(
            f"""
                <a href='/admin/gui/domain/?tag__id__exact={obj.tag.id}'>{obj.tag}</a>
            """
        )

    def configuration(self, obj):
        def format_status(value):
            if value:
                return '<span style="color: orangered; font-style: italic;">custom</span>'
            return '<span style="color: green;">default</span>'

        dns = format_status(obj.dns)
        useragent = format_status(obj.useragent)
        wordlist = format_status(obj.wordlist) if obj.bruteforce else ''

        config = format_html(f"""
            <b>dns</b>: {dns}<br>
            <b>useragent</b>: {useragent}<br>
            {f'<b>wordlist</b>: {wordlist}<br>' if obj.bruteforce else ''}
            <b>timeout</b>: {obj.timeout}<br>
            <b>threads</b>: {obj.threads}<br>
        """)

        return config

    def result(self, obj):
        if not obj.messages:
            return format_html(
                f'''
                    <span style="color: orangered; font-style: italic; font-size: 18px">0</span>
                ''')
        return format_html(
            f'''
                <a href="/admin/gui/subdomain/?domain={obj.id}" style="color: blue; font-style: bold; font-size: 18px">{obj.messages["count"]}</a>
            ''')


    def status(self, obj):
        if not obj.messages:
            msg = 'The scan is currently in progress.'
            return format_html(
                f'''<span style="color: orangered; font-style: italic;">{msg}</span>'''
            )

        def format_status(value, is_wildcard=False):
            if is_wildcard and value:  # Wildcard exception
                return f'<span style="color: red; font-style: italic;">{value}</span>'
            elif is_wildcard and not value:  # Wildcard exception
                return f'<span style="color: green;">{value}</span>'
            elif not value:
                return f'<span style="color: red; font-style: italic;">{value}</span>'
            return f'<span style="color: green;">{value}</span>'

        messages = {
            'wildcard': obj.messages['wildcard'],
            'finished': obj.messages['finished'],
            'completed': obj.completed,
            'time': obj.messages['time'],
        }

        formatted_messages = {
            'wildcard': format_status(messages['wildcard'], is_wildcard=True),
            'finished': format_status(messages['finished']),
            'completed': format_status(messages['completed'])
        }

        status = format_html(f"""
            <b>wildcard</b>: {formatted_messages['wildcard']}<br>
            <b>finished</b>: {formatted_messages['finished']}<br>
            <b>completed</b>: {formatted_messages['completed']}<br>
            <b>time</b>: {messages['time']} s<br>
        """)

        return status

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context['title'] = "Home"
        return super().changelist_view(request, extra_context=extra_context)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)        

        def run_scan_command():
            call_command('scan', obj.id)

        # Execute the function in a separate thread
        threading.Thread(target=run_scan_command).start()

        return HttpResponseRedirect(reverse('admin:gui_domain_changelist'))

    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        context.update({
            'show_save': True,
            'show_save_and_continue': False,
            'show_save_and_add_another': False,
            'show_delete': True
        })
        return super().render_change_form(request, context, add, change, form_url, obj)

from django.db.models import Q
def filter_queryset(queryset, request, model):
    """
    Filters the queryset dynamically based on the parameters found in the request GET parameters.
    Handles `__exact`, `__isnull`, and other valid lookups dynamically.
    """
    # Get all valid fields from the model
    valid_fields = {field.name for field in model._meta.get_fields()}

    # Iterate over the parameters of the GET request
    for param, value in request.GET.items():
        if not value:  # Skip parameters without value
            continue

        try:
            # Get the base field before the lookup (for example, 'cert_status' from 'cert_status__exact')
            base_field = param.split("__")[0]

            if base_field in valid_fields:
                # Manage '__isnull' lookups separately
                if param.endswith("__isnull"):
                    # Convert the value to boolean for 'isnull'
                    value = value.lower() in ("true", "1", "yes")
                elif param.endswith("__exact"):
                    # For '__exact', the value can remain unchanged
                    pass
                else:
                    # For all other lookups, continue without additional conversions
                    pass

                # Apply the filter to the queryset
                queryset = queryset.filter(**{param: value})

            if param == 'q':
                queryset = queryset.filter(Q(name__icontains=value) | Q(ip__icontains=value))
        except (ValueError, TypeError):
            # Ignore invalid filters or errors
            continue

    return queryset

import json
from django.template.loader import render_to_string
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'domain', 'ip_address', 'http', 'https', 'certificate', 'created_at')
    search_fields = ('name', 'domain__name', 'ip')
    
    
    list_filter = (
        'cert_status',
        'http_status', 'https_status',
        'http_server', 'https_server'
    )
    
    def get_queryset(self, request):
        queryset = super().get_queryset(request)

        # Filter the queryset based on the 'domain' parameter in the URL
        domain_id = request.GET.get('domain')
        if domain_id:
            queryset = queryset.filter(domain=domain_id)  # Assicurati che 'domain' sia il campo corretto

        return queryset

    actions = None

    def has_add_permission(self, request):
        return False

    def changelist_view(self, request, extra_context=None):
        title = "Subdomains"
        if not 'domain' in request.GET:
            extra_context = extra_context or {}
            extra_context['title'] = title
            return super().changelist_view(request, extra_context=extra_context)

        domain_id = request.GET.get('domain')
        domain = Domain.objects.filter(id=domain_id).first()
        title = domain.name

        queryset = self.get_queryset(request)
        queryset = filter_queryset(queryset, request, Subdomain)

        # Prepare data for templates
        domain_ip_data = queryset.values_list('name', 'ip')
        domain_ip_data = [(name, ip['ip']) for name, ip in domain_ip_data]

        nodes = []
        links = []

        for domain, ips in domain_ip_data:
            nodes.append({"id": domain, "group": 1})
            for ip in ips:
                nodes.append({"id": ip, "group": 2})
                links.append({"source": domain, "target": ip})

        # Remove duplicates in nodes
        unique_nodes = {node["id"]: node for node in nodes}.values()
        nodes = list(unique_nodes)
        
        graph_html = render_to_string('admin/domain_ip_graph.html', {
            'nodes': json.dumps(nodes),
            'links': json.dumps(links),
        })

        extra_context = extra_context or {}
        extra_context['title'] = title
        extra_context['graph_html'] = mark_safe(graph_html)
        return super().changelist_view(request, extra_context=extra_context)

    def domain_name(self, obj):
        return format_html(f"<a href='http://{obj.name}' target='_blank'>{obj.name}</a>")

    def ip_address(self, obj):
        if obj.ip:
            return format_html('<br>'.join(obj.ip['ip']))
        return obj.ip

    def http(self, obj):
        http_status = getattr(obj, 'http_status', "") or ""
        http_redirect = getattr(obj, 'http_redirect', "") or ""
        http_server = getattr(obj, 'http_server', "") or ""

        # Default row style
        row_style = ""

        if obj.http_status and not obj.https_status or obj.http_status == 200:
            row_style = "background-color: yellow;"
            http_status = f'<span style="color: red;">{obj.http_status}</span>'
        
        return format_html(
            f"""
            <div style="{row_style}">
                <b>status</b>: {http_status}<br>
                <b>redirect</b>: {http_redirect}<br>
                <b>server</b>: {http_server}
            </div>
            """
        )

    def https(self, obj):
        https_status = getattr(obj, 'https_status', "") or ""
        https_redirect = getattr(obj, 'https_redirect', "") or ""
        https_server = getattr(obj, 'https_server', "") or ""
        
        return format_html(
            f"""
            <b>status</b>: {https_status}<br>
            <b>redirect</b>: {https_redirect}<br>
            <b>server</b>: {https_server}
            """
        )

    def certificate(self, obj):
        cert_status = ""
        cert_expiration_date = ""
        cert_common_name = ""
        
        # Default row style
        row_style = ""

        if obj.https_status:
            # Check if cert_status or cert_expiration_date is invalid and set background color to yellow
            if not obj.cert_status or obj.cert_expiration_date < obj.created_at or \
               (obj.cert_common_name and obj.domain.name not in obj.cert_common_name):
                row_style = "background-color: yellow;"

            # Apply red color to cert_status if it is not set
            cert_status = (
                f'<span style="color: red;">{obj.cert_status}</span>' if not obj.cert_status else obj.cert_status
            )

            # Format expiration date and check if it should be in red
            if obj.cert_expiration_date:
                expiration_date_str = str(obj.cert_expiration_date).split()[0]
                cert_expiration_date = (
                    f'<span style="color: red;">{expiration_date_str}</span>'
                    if not obj.cert_status or obj.cert_expiration_date < obj.created_at
                    else expiration_date_str
                )

            # Apply red color to cert_common_name if it does not contain the domain name
            cert_common_name = (
                f'<span style="color: red;">{obj.cert_common_name}</span>'
                if obj.cert_common_name and obj.domain.name not in obj.cert_common_name
                else obj.cert_common_name
            )

        # Return formatted HTML with the row styling and certificate information
        return format_html(
            f"""
            <div style="{row_style}">
                <b>status</b>: {cert_status}<br>
                <b>expire</b>: {cert_expiration_date}<br>
                <b>common name</b>: {cert_common_name}
            </div>
            """
        )


# Registered models
admin.site.register(Domain, DomainAdmin)
admin.site.register(Subdomain, SubdomainAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(Apikey, ApikeyAdmin)
