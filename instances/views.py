#!usr/bin/python3.6
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import requests
import json
import uuid
import datetime
from django.shortcuts import render, render_to_response
import re
from urllib.request import Request, urlopen, URLError, HTTPError
from time import sleep
from django.shortcuts import render, render_to_response
from django.shortcuts import render
from instances import src2
from instances import stop_to_start
from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden, JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from instances.models import UserProfile, InstanceType, Instance
from instances import checker_db, get_all_instances
from instances import db

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

    url = 'https://auth.commonsshare.org/authorize?provider=globus'
    url += '&scope=openid%20profile%20email'
    url += '&return_to=' + return_to
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~get_auth_redirect - start~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    resp = requests.get(url)
    print("URL", url)
    print("RESP = REQUEST.GET(URL)", resp)
    body = json.loads(resp.content.decode('utf-8'))
    print("RESP_BODY", body)
    print("AUTHORIZATION_URL", body['authorization_url'])
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~get_auth_redirect - end~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    return redirect(body['authorization_url'])


def check_authorization(request):
    skip_validate = False
    token = None
    r_invalid = get_auth_redirect()
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

def create_redirect(request):
    
    auth_resp = check_authorization(request)
    if auth_resp.status_code != 200:
        return auth_resp

    else:
        username = request.GET.get("username")
        print(username)
        print(request.META)
        request.session["username"] = username
        return HttpResponseRedirect("/createredirect/")

#@login_required(login_url='/accounts/login/')
def create_instance(request):

    if request.method == "POST":
        #print(request.session.items())
        username = request.session['username']
        type = request.POST.get("type")
        print(type)
        request.session["ins_type"] = type

        ip = request.POST.get("ip")
        print(ip)
        id = request.POST.get("id")
        print(id)
        platform1 = request.POST.get("platform1")
        print(platform1)
        platform2 = request.POST.get("platform2")
        print(platform2)
        action = request.POST.get("action")
        print(action)
        ins_name = request.POST.get("ins_name")
        print(ins_name)
        request.session["ins_name"] = ins_name

        if action == "Create":
            return HttpResponseRedirect("/createinstance/")

        elif action == "Stop" or action == "Start":
            if action == "Start":
                print(username, ip, type)
                flag = stop_to_start.main(username, ip, id, action, platform1, type)
                print(flag)
                if flag != "terminated" or flag != None:
                    request.session["staticip"] = flag
                    url = "http://" + flag
                    return HttpResponseRedirect(url)

            if action == "Stop":
                flag = stop_to_start.main(username, ip, id, action, platform1, type)

                if flag != "terminated" or flag != None:
                    request.session["staticip"] = flag
                    return HttpResponseRedirect("/createredirect/")

            return HttpResponseRedirect("/createredirect/")

        else:
            print("Enter the Restart Dragon...")
            flag = stop_to_start.main(username, ip, id, action, platform2, type)
            ip_port = ip + ":8000"
            print(ip_port)
            flag1 = url_status(ip_port)
            print(flag1)
            if flag != "terminated" or flag != None:
                return HttpResponseRedirect("/createredirect/")

    else:
        
        print("Create Redirect Items", request.session.items())
        type = "all"
        username = request.session.get("username")
        print("Create Redirect username", username)
        #auth_resp = check_authorization(request)
        #if auth_resp.status_code != 200:
        #    return auth_resp

        #else:
        #type = "all"
        #request.session["username"] = username
        flag = get_all_instances.main(username, type)
        context = {
             "instances": flag
        }

        return render(request, "create.html", context=context)

def terminateinstance(request):
    return render(request, "terminate.html", context={})

def launchinstance(request):
    print(request.session.items())
    #flag1 = url_status(request.session["staticip"])

    #if flag1 == "HTTP OK":
    context = {
         "instance_ip": request.session["instance_ip_create"]
    }
    return render(request, "launch.html", context={})

def create_dum(request):
    """
    This view is for Instance creation. Saves the instance requested from the Power User and stores the Instance details
    in teh Django database.
    :param request: Takes the request from the "create_instance" view.
    :return: IP Address of the EC2 instance
    """
    print("Dragon", request.session.items())
    if request.method == "POST":
        # token = request.session['token']
        # validate_url = 'https://auth.commonsshare.org/validate_token?access_token='
        # resp = requests.get(validate_url + token)
        # body = json.loads(resp.content.decode('utf-8'))
        # username = body.get("username")
        ins_type = str(request.session["ins_type"])
        username = str(request.session["username"])
        ins_name = str(request.session["ins_name"])
        instance_ip, instance_id = src2.main(username, ins_type, ins_name)
        request.session["instance_ip_create"] = instance_ip
        flag, user_obj, ins_type_obj = db.add_instance(username, type)
        print(flag)
        if flag == "UE-ITE":
            instance1 = Instance.objects.create(user=user_obj, instancetype=ins_type_obj, instanceid=instance_id, staticip=instance_ip)
            instance1.save()

        elif flag == "UE-ITDNE":
            ins_type_obj1 = InstanceType(user=user_obj, instancetype=ins_type)
            ins_type_obj1.save()
            instance1 = Instance.objects.create(user=user_obj, instancetype=ins_type_obj1, instanceid=instance_id, staticip=instance_ip)
            instance1.save()
        else:
            user_obj1 = UserProfile(user=username)
            user_obj1.save()
            ins_type_obj1 = InstanceType(user=user_obj1, instancetype=ins_type)
            ins_type_obj1.save()
            instance1 = Instance.objects.create(user=user_obj1, instancetype=ins_type_obj1, instanceid=instance_id, staticip=instance_ip)
            instance1.save()

        context = {
             "instance_ip": instance_ip
        }

        flag1 = url_status(instance_ip)
        print(flag1)
        if flag1 == "HTTP OK":
            return HttpResponseRedirect("/launchinstance/")
    else:
        return render(request, "create_dum.html", {})

def url_status(instance_ip):
    req = Request("http://" + instance_ip + "/")
    for i in range(0, 200):
        try:
            a = urlopen(req)
            msg = "HTTP OK"
            return msg
            break

        except HTTPError as e:
            print("HTTPERROR", e)
            sleep(1)
            continue

        except URLError as u:
            sleep(1)
            print("URLERROR", u)
            continue

def home_page_view(request):
    #print("HOME PAGE VIEW REQUEST.META", request.META)
    #auth_resp = check_authorization(request)
    #print("HOE PAGE VIEW REQUEST.META", request.META)
    #print("AUTH_RESP", auth_resp)
    #print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~end_home_page_view~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    #if auth_resp.status_code != 200:
    #    return auth_resp
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
    #if request.method == 'POST':
    #    fields_mapping = {}
    #    fields_mapping["first_name"] = "first_name"
    #    fields_mapping["last_name"] = "last_name"
    #    fields_mapping["username"] = "username"
    #    fields_mapping["email"] = "email"
    #    fields_mapping["password1"] = "password"

    #    params = dict()
    #    for field in fields_mapping:
    #        _field = fields_mapping[field]
    #        params[_field] = request.POST[field]

    #    user = User.objects.create_user(**params)
    #    user.save()
    #    return redirect("signin-view")

    #else:
    return render(request, "sign_up.html", {})


def dashboard_view(request):
    return render("dashboard.html", {})

