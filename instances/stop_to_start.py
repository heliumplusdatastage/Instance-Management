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
    awsaccessid, awssecretkey, _, _, _, _ = config_parser.parser(type)
    region = "us-east-1"
    ec2client = boto3.client('ec2', region_name=region, aws_access_key_id=awsaccessid, aws_secret_access_key=awssecretkey)
    ec2resourceclient = boto3.resource('ec2', region_name=region,
                                       aws_access_key_id=awsaccessid, aws_secret_access_key=awssecretkey)

    response = ec2client.describe_instances(DryRun=False)["Reservations"]
    for ec2 in response:
        for instance in ec2["Instances"]:
            instance_id = instance["InstanceId"]
            instance_type = instance["InstanceType"]

            for tags in instance["Tags"]:
                if tags['Key'] == "Power User" and tags['Value'] == username:
                    if instance_type == type:
                        instance_state = instance["State"]["Name"]

                        if instance_state == "stopped":
                            launch_url2 = restart_ec2(ec2client, instance_id, instance, ec2resourceclient)

                            return launch_url2

                        elif instance_state == "running":
                            launch_url3 = launch_ec2(instance["PublicIpAddress"])

                            return launch_url3
                   
                        elif instance_state == "terminated":
                            print("**********INSTANCE_STATE*********", instance_state)
                        
                            return instance_state

                        else:
                            return None


def restart_ec2(ec2client, instance_id, instance, ec2resourceclient):
    print("------------------------------")
    print("Try to start the EC2 instance.")
    print("------------------------------")

    try:
        print("Start dry run...")
        ec2client.start_instances(InstanceIds=[instance_id], DryRun=True)
    except ClientError as e:
        if 'DryRunOperation' not in str(e):
            raise

    # Dry run succeeded, run start_instances without dryrun
    try:
        print("Start instance without dry run...")
        response = ec2client.start_instances(InstanceIds=[instance_id], DryRun=False)
        instance = ec2resourceclient.Instance(instance_id)
        instance.wait_until_running()

        if instance.state["Name"] == "running":
            print("The instance is running.")
            launch_url = launch_ec2(instance.public_ip_address)

    except ClientError as e:
        print(e)

    return launch_url

def launch_ec2(static_ip):
    """
    This code is from Amazon's EC2 example.
    Do a dryrun first to verify permissions.
    Try to start the EC2 instance.
    """

    launch_url = static_ip
    return launch_url
