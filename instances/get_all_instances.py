import sys
import os
from time import sleep
import time
import argparse
import boto3.ec2
from botocore.exceptions import ClientError
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, Http404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
import json
from django.utils import timezone
from instances import config_parser

def main(username, type):
    print(username, type)
    awsaccessid, awssecretkey, sg = config_parser.parser(type)
    region = "us-east-1"
    ec2client = boto3.client('ec2', region_name=region, aws_access_key_id=awsaccessid, aws_secret_access_key=awssecretkey)

    response = ec2client.describe_instances(DryRun=False)["Reservations"]
    ins_list = []
    for ec2 in response:
        for instance in ec2["Instances"]:
            try:
                for tags in instance["Tags"]:
                    if tags['Key'] == "Power User" and tags['Value'] == username:
                        try:
                            for tags in instance["Tags"]:
                                if tags["Key"] == "Instance Name":
                                    instance_name = tags["Value"]
                        except Exception as e:
                            continue
                        if instance["State"]["Name"] != "terminated":
                            try:
                                ins_list.append((instance["InstanceType"], instance["PublicIpAddress"], instance["State"]["Name"],
                                                instance["LaunchTime"], instance["StateTransitionReason"], instance["InstanceId"], instance_name))
                            except Exception as error:
                                ins_list.append((instance["InstanceType"], "IP Not Assigned", instance["State"]["Name"],
                                                instance["LaunchTime"], instance["StateTransitionReason"], instance["InstanceId"], instance_name))
                                continue

            except Exception as e:
                continue

    return ins_list 
