#!usr/bin/python3.6
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import requests
import json
import uuid
import datetime
from django.shortcuts import render, render_to_response
import re
# Create your views here.
from django.shortcuts import render
# from django.shortcuts import HttpResponse
#from instances import demo

from instances import src2
from instances import stop_to_start
from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden, JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from instances.models import UserProfiles
from instances import checker_db

now = timezone.now

whitelist = [
    'krferrit@unc.edu'
]
body_list = []
def get_auth_redirect():
    # set return_to to be where user is redirected back to upon successful login
    # it needs to be somewhere that will handle the access_token url parameter, which
    # can be the url of the current app, since check_authorization will check for it
    # right now this is restricted to domains matching '*.commonsshare.org'
    return_to = 'https://copdgenejupyterlauncher.commonsshare.org/create/'

    url = 'https://auth.commonsshare.org/authorize?provider=auth0'
    url += '&scope=openid%20profile%20email'
    url += '&return_to=' + return_to
    resp = requests.get(url)
    body = json.loads(resp.content.decode('utf-8'))
    print(body['authorization_url'])
    return redirect(body['authorization_url'])


def check_authorization(request):
    skip_validate = False
    token = None
    r_invalid = get_auth_redirect()
    #print("r_invalid", r_invalid)
    if 'HTTP_AUTHORIZATION' in request.META:
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        print('auth_header: ' + str(auth_header))
        if not auth_header:
            return r_invalid
        terms = auth_header.split()
        if len(terms) != 2:
            return r_invalid
        elif terms[0] == 'Bearer':
            token = terms[1]
        else:
            return r_invalid
    elif 'access_token' in request.GET:
        token = request.GET.get('access_token')
    elif 'session_id' in request.session and request.session.get_expiry_date() >= now():
        print(request.session.get_expiry_date())
        print('session_id valid, expires in: ' + str((request.session.get_expiry_date() - now()).total_seconds()))
        skip_validate = True
    else:
        print('no authorization found')
        print("r_invalid:", r_invalid)
        return r_invalid
    if not skip_validate:
        # need to check the token validity
        validate_url = 'https://auth.commonsshare.org/validate_token?access_token='
        resp = requests.get(validate_url + token)
        request.session['token'] = token
        if resp.status_code == 200:
            body = json.loads(resp.content.decode('utf-8'))
            body_list.append(body)
            if body.get('active', False) == True:
                # the token was valid, set a session
                print('received access token was valid, storing session')
                request.session['session_id'] = str(uuid.uuid4())
                request.session.set_expiry(datetime.timedelta(days=30).total_seconds())
                return JsonResponse(status=200, data={
                    'status_code': 200,
                    'message': 'Successful authentication',
                    'user': body.get('username')})
            print(resp)
            print(resp.content)
            r = JsonResponse(status=403, data={
                'status_code': 403,
                'message': 'Request forbidden'})
            return r
    else:
        # picked up existing valid session, no need to check again
       return JsonResponse(status=200, data={'status_code': 200, 'message': 'session was valid'})

#@login_required(login_url='/accounts/login/')
def create_instance(request):

    token = request.GET.get('access_token')
    validate_url = "https://auth.commonsshare.org/validate_token?access_token="
    resp = requests.get(validate_url + token)
    body = json.loads(resp.content.decode('utf-8'))
    username = body.get("username")
    print("Auth_Resp", username)

    if request.method == "POST":
        type = request.POST.get("type")
        print(type)
        flag = checker_db.instance_check(username, type)

        if flag == "IEUE":
            print("Commencing stop to start")
            instance_ip = stop_to_start.main(username, type)
            if instance_ip != None and instance_ip != "terminated":
                instance_ip = instance_ip + ":8000"
                context = {
                    "instance_ip": instance_ip
                }
                request.session["staticip"] = instance_ip
                return HttpResponseRedirect("/launchinstance/")

            elif instance_ip == "terminated":
                print(instance_ip)
                return HttpResponseRedirect("/terminateinstance/")

            else:
                auth_resp = check_authorization(request)
                UserProfiles.objects.filter(username=username, ins_type=type).delete()
                if auth_resp.status_code != 200:
                    return auth_resp

                else:
                    request.session["ins_type"] = type
                    return HttpResponseRedirect("/createinstance/")

        else:
            url = "/createinstance/"
            request.session["ins_type"] = type

            return HttpResponseRedirect(url)

    else:
        auth_resp = check_authorization(request)
        if auth_resp.status_code != 200:
            return auth_resp

        else:
            #request.session["ins_type"] = type
            #return HttpResponseRedirect("/createinstance/")
            return render(request, "create.html", context={})

def terminateinstance(request):
    return render(request, "terminate.html", context={})

def launchinstance(request):
    context = {
         "instance_ip": request.session["staticip"]
    }
    return render(request, "launch_dum.html", context)

def create_dum(request):
    print(request.META)
    print("SESSION", request.session.items())
    if request.method == "POST":
        token = request.session['token']
        validate_url = 'https://auth.commonsshare.org/validate_token?access_token='
        resp = requests.get(validate_url + token)
        body = json.loads(resp.content.decode('utf-8'))
        username = body.get("username")
        ins_type = request.session["ins_type"]
        instance_ip = src2.main(username, ins_type)
        user_instance1 = UserProfiles.objects.create(username=username, staticip=instance_ip, ins_type=ins_type)
        user_instance1.save()
        context = {
             "instance_ip": instance_ip
        }
        return render(request, 'launch.html', context)
    else:
        return render(request, "create_dum.html", {})

def home_page_view(request):
    auth_resp = check_authorization(request)
    print(auth_resp)
    if auth_resp.status_code != 200:
        return auth_resp
    return render(request, "home.html", {})


def signin_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == str(User.objects.get(username=username)):
            user = authenticate(username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                return redirect('create')
            else:
                message = "User is not active."
                return render(request, "sign_in.html", {'message': message})
        else:
            message = "Invalid login."
            return render(request, "sign_in.html", {'message': message})
    else:
        return render(request, "sign_in.html", {})


def signout_view(request):
    return redirect('/')


def signup_view(request):
    if request.method == 'POST':
        fields_mapping = {}
        fields_mapping["first_name"] = "first_name"
        fields_mapping["last_name"] = "last_name"
        fields_mapping["username"] = "username"
        fields_mapping["email"] = "email"
        fields_mapping["password1"] = "password"

        params = dict()
        for field in fields_mapping:
            _field = fields_mapping[field]
            params[_field] = request.POST[field]

        user = User.objects.create_user(**params)
        user.save()
        return redirect("signin-view")

    else:
        return render(request, "sign_up.html", {})


def dashboard_view(request):
    return render("dashboard.html", {})

