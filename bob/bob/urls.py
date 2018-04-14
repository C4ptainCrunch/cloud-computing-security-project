"""eve URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from bob import views

urlpatterns = [
    path('', views.index),
    path('unsecure', views.unsecure),
    path('chrome_protect', views.chrome_protect),
    path('referer_check', views.referer_check),
    path('source_self', views.source_self),
    path('no_extract', views.no_extract),
    path('escape', views.escape),
    path('crsf', views.crsf),
    path('login', views.login),
    path('admin', views.admin),

]
