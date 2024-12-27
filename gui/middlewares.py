from django.utils.functional import SimpleLazyObject
from django.contrib import admin
from django.utils.html import format_html

# Customizing admin.site
title = "Knockpy GUI"
menu = """
    <div style="
        display: inline-block;
        background-color: #343a40;
        padding: 0px 20px;
        border-radius: 5px;
    ">
        <a href='/admin/gui/domain/' style="
            color: #ffffff;
            text-decoration: none;
            margin-right: 15px;
            margin-left: 15px;
        ">Home</a>
        |
        <a href='/admin/gui/subdomain/' style="
            color: #ffffff;
            text-decoration: none;
            margin-left: 15px;
            margin-right: 15px;
        ">Subdomain</a>
        |
        <a href='/admin/gui/tag/' style="
            color: #ffffff;
            text-decoration: none;
            margin-left: 15px;
            margin-right: 15px;
        ">Tag</a>
        |
        <a href='/admin/gui/apikey/' style="
            color: #ffffff;
            text-decoration: none;
            margin-left: 15px;
            margin-right: 15px;
        ">API Key</a>
    </div>
"""

class CustomTemplate:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            admin.site.site_header = format_html(f"""
                <div style="
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    background-color: #343a40;
                    padding: 10px 30px;
                    color: #ffffff;
                    border-radius: 5px;
                    font-size: 18px;
                ">
                    <div style="font-size: 18px; font-weight: bold; margin-right: 30px;">
                        {title}
                    </div>
                    {menu}
                </div>
            """)
            admin.site.enable_nav_sidebar = False
            admin.site.site_title = "Knockpy"
            admin.site.index_title = "Dashboard Admin"
        else:
            admin.site.site_header = title
        return self.get_response(request)
