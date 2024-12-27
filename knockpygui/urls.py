from django.contrib import admin
from django.http import HttpResponseRedirect
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('', lambda request: HttpResponseRedirect('/admin/gui/domain/')),
    path('admin', lambda request: HttpResponseRedirect('/admin/gui/domain/')),
    path('admin/', lambda request: HttpResponseRedirect('/admin/gui/domain/')),
    path('admin/gui/', lambda request: HttpResponseRedirect('/admin/gui/domain/')),
    path('admin/', admin.site.urls),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
