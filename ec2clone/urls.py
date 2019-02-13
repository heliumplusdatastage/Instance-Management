"""ec2clone URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin, auth
from instances import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    #url(r'^demo/', views.demo, name="demo"),
    url(r'^create/', views.create_redirect, name="create_redirect"),
    url(r'^createredirect/', views.create_instance, name="create"),
    url(r'^createinstance', views.create_dum, name="create_dum"),
    url(r'^launchinstance', views.launchinstance, name="launch"),
    url(r'^terminateinstance', views.terminateinstance, name="terminate"),
    url(r'accounts/login/$', views.signin_view, name='signin-view'),
    url(r'accounts/logout/$', views.signout_view),
    url(r'accounts/signup/$', views.signup_view),
    url(r'logout/', views.signout_view, name="signout_view"),
    url(r'$', views.home_page_view, name='home-page-view'),
    #url(r'^launchready', views.launchready, name="launchready"),
]


