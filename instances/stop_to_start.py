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

platform = {
        "0": "0000",
        "1": "8000",
        "2": "8787",
        "3": "Dicom Viewer",
    }

def main(username, static_ip, ins_id, action, platform_number, type):


    print(type)
    awsaccessid, awssecretkey, _, _, _, _ = config_parser.parser(type)
    print(awsaccessid, awssecretkey)
    region = "us-east-1"
    ec2client = boto3.client('ec2', region_name=region, aws_access_key_id=awsaccessid, aws_secret_access_key=awssecretkey)
    ec2resourceclient = boto3.resource('ec2', region_name=region,
                                       aws_access_key_id=awsaccessid, aws_secret_access_key=awssecretkey)

    response = ec2client.describe_instances(DryRun=False)["Reservations"]
    for ec2 in response:
        for instance in ec2["Instances"]:
            try:
                instance_ip = instance["PublicIpAddress"]
            except Exception as e:
                instance_id = instance["InstanceId"]
                pass
            instance_type = instance["InstanceType"]

            try:
                for tags in instance["Tags"]:
                    if tags['Key'] == "Power User" and tags['Value'] == username:
                        if instance_ip == static_ip or instance_id == ins_id:
                            print("Enter the Dragon 1")
                            instance_id = instance["InstanceId"]
                            instance_state = instance["State"]["Name"]

                            if instance_state == "stopped":
                                print("Enter the dragon")
                                launch_url2 = restart_ec2(ec2client, instance_id, ec2resourceclient)

                                return launch_url2

                            elif instance_state == "running" and action == "Start":
                                print("Running", instance_ip, platform_number)
                                launch_url3 = launch_ec2(static_ip, platform[platform_number])

                                return launch_url3

                            elif instance_state == "running" and action == "Stop":
                                launch_url4 = stop_ec2(ec2client, instance_id, ec2resourceclient, platform_number)
                   
                            elif instance_state == "terminated":
                                print("**********INSTANCE_STATE*********", instance_state)
                        
                                return instance_state

                            else:
                                return None

            except Exception as e:
                  continue


def restart_ec2(ec2client, instance_id, ec2resourceclient):
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
            print(instance.public_ip_address)
            platform_number = "0"
            launch_url = launch_ec2(instance.public_ip_address, platform_number)

    except ClientError as e:
        print(e)

    return launch_url

def stop_ec2(ec2client, instance_id, ec2resourceclient, platform_number):
    try:
        print("Stopping instance without dry run...")
        response = ec2client.stop_instances(InstanceIds=[instance_id], DryRun=False)
        instance = ec2resourceclient.Instance(instance_id)
        instance.wait_until_stopped()

        if instance.state["Name"] == "stopped":
            print("The instance is stopped.")
            try:
                launch_url = launch_ec2(instance.public_ip_address, platform[platform_number])
            except Exception as e:
                launch_url = launch_ec2("IP Not Available", platform[platform_number])

    except ClientError as e:
        print("Error", e)
        pass

def launch_ec2(static_ip, platform_number):
    """
    This code is from Amazon's EC2 example.
    Do a dryrun first to verify permissions.
    Try to start the EC2 instance.
    """

    launch_url = static_ip + ":" + platform_number
    return launch_url
