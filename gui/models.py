from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv4_address

def validate_timeout(value):
    """
    Timeout for the scanning process

    It is a validator in the 'timeout' field within the Domain table.
    """
    if not (1 < value < 10):
        raise ValidationError(f"The value of timeout must be between 1 and 10 (exclusive). Provided value: {value}.")

def validate_threads(value):
    """
    Number of threads to use during the scanning process

    It is a validator in the 'threads' field within the Domain table.
    """
    if not (9 < value < 31):
        raise ValidationError(f"The value of threads must be between 10 and 30 (exclusive). Provided value: {value}.")

class Tag(models.Model):
    """
    The tag name is used to label one or more scans.
    For example, the tag name 'bugbounty' can be used to scan the following domains:
    bugcrowd.com or hackerone.com

    It is a ForeignKey for Domain.
    """
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name

class Apikey(models.Model):
    # Fill the fields with virustotal and shodan apikey for deep scanning
    virustotal = models.CharField(max_length=255)
    shodan = models.CharField(max_length=255)

    def __str__(self):
        return "Apikey"

class Domain(models.Model):
    """
    It contains all the information about the domain name to be scanned.
    """
    id = models.AutoField(primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=255, verbose_name='domain name')
    recon = models.BooleanField(default=True)
    bruteforce = models.BooleanField(default=False)
    wildcard = models.BooleanField(default=True)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, blank=True, null=True, related_name='domains')
    wordlist = models.CharField(max_length=255, blank=True, null=True)
    dns = models.CharField(max_length=255, blank=True, null=True)
    useragent = models.CharField(max_length=255, blank=True, null=True)
    timeout = models.IntegerField(default=5, blank=True, null=True, validators=[validate_timeout])
    threads = models.IntegerField(default=10, blank=True, null=True, validators=[validate_threads])
    messages = models.JSONField(blank=True, null=True)
    completed = models.BooleanField(default=False)

    def clean(self):
        super().clean()
        # Check that at least one of recon or bruteforce is enabled
        if not self.recon and not self.bruteforce:
            raise ValidationError("At least one of 'recon' or 'bruteforce' must be enabled.")

        # Check that DNS is either empty or a valid IPv4 address
        if self.dns:
            try:
                validate_ipv4_address(self.dns)  # Validate the DNS IP address as IPv4
            except ValidationError:
                raise ValidationError("The 'dns' field must be empty or contain a valid IPv4 address.")

        # Ensure that self.tag is set before saving
        if not self.tag:
            tag, created = Tag.objects.get_or_create(name=self.name)
            self.tag = tag  # Set the tag to the retrieved or created object

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name

class Subdomain(models.Model):
    """
    Show all scanned subdomains, you can filter by:
    cert status
    http status
    https status
    http server
    https server
    """
    id = models.AutoField(primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=255)
    ip = models.JSONField()  # Store IP list
    http_status = models.IntegerField(blank=True, null=True)
    http_redirect = models.CharField(max_length=255, blank=True, null=True)
    http_server = models.CharField(max_length=255, blank=True, null=True)
    https_status = models.IntegerField(blank=True, null=True)
    https_redirect = models.CharField(max_length=255, blank=True, null=True)
    https_server = models.CharField(max_length=255, blank=True, null=True)
    cert_status = models.BooleanField(blank=True, null=True)
    cert_expiration_date = models.DateTimeField(blank=True, null=True)
    cert_common_name = models.CharField(max_length=255, blank=True, null=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='subdomains')

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name
