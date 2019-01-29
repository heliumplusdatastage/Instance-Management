#!/usr/bin/python3.6
import argparse
import logging
from time import sleep
import sys
import boto.ec2.networkinterface
from boto.ec2 import connect_to_region
from boto.ec2.blockdevicemapping import EBSBlockDeviceType
from boto.ec2.blockdevicemapping import BlockDeviceMapping
from boto.exception import EC2ResponseError
import names
from datetime import datetime
import boto3
import yaml
from instances import config_parser

def run_instance(connection, target_image_id, block_device_map, security_group, username, ins_type, unit):

    ''' 
        Resources: 
        Netwrork Interface Specification: http://boto.cloudhackers.com/en/latest/ref/ec2.html#module-boto.ec2.networkinterface
        Run Instances: http://boto.cloudhackers.com/en/latest/ref/ec2.html [search for run_instances]
        Get Elastic IP's: http://boto.cloudhackers.com/en/latest/ref/ec2.html [search for get_all_addresses]
        Associate Elastic IP: http://boto.cloudhackers.com/en/latest/ref/ec2.html#boto.ec2.connection.EC2Connection.associate_address
    '''

    user_data = '''#!bin/bash
     sudo jupyterhub -f /home/ubuntu/jupyterhub_config.py'''

    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id='subnet-bf4498d8',
                                                                        groups=[security_group],
                                                                        associate_public_ip_address=True)
    print("INTERFACE", interface)
    interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
    print("INTERFACES", interfaces)
    reservation = connection.run_instances(image_id=target_image_id,
                                           instance_type=ins_type,
                                           key_name="tfjpnbserv",
                                           network_interfaces=interfaces,
                                           block_device_map=block_device_map,
                                           user_data=user_data
                                           )
    instance = reservation.instances[0]
    print("INSTANCE", instance)
    for _ in range(0, 600):
        instance.update()
        if str(instance.state) == "running":
            instance_ip = instance.ip_address
            exit
        else:
            sleep(1)

    instance.add_tag("Power User", username)
    instance.add_tag("Name", "JupyterHub-"+unit+"-Deep Learning-Instance")
    instance.add_tag("Project", "STAGE_CommonsShare")
    instance.add_tag("POC", "Murali Karthik Kothapalli")

    elastic_ips = connection.get_all_addresses()
    print(elastic_ips)

    for eip in elastic_ips:
        print(eip.public_ip, eip.instance_id, eip.private_ip_address)
        if eip.instance_id is None:
            if eip.private_ip_address is None:
                print(eip.public_ip)
                allocation_id = eip.allocation_id
                connection.associate_address(instance_id=instance.id, public_ip=instance.ip_address, allocation_id=allocation_id)
                break

    return eip.public_ip


def copy_snapshot(connection, source_volume_id, username, unit):
    while True:
          try:
              descrip = username + "-for " + unit + " instance"
              target_snapshot = connection.create_snapshot(source_volume_id, description=descrip)
              for _ in range(0, 600):
                  target_snapshot.update()
                  if str(target_snapshot.status) == "completed":
                      target_snapshot_id = target_snapshot.id
                      break
                  else:
                      sleep(1)

          except EC2ResponseError as _:
              continue
          snapshot_id = connection.get_all_snapshots(filters={"snapshot_id": target_snapshot_id})
          print(snapshot_id)
          return target_snapshot_id
          break


def build_block_device_map(source_image, target_snapshot_id, source_volume_size):
    """Create a block device map which is used for the copied AMI.
    The created block device map contains a root volumes with 8GB of storage
    on general purpose SSD (gp2).
    """

    root_device_name = source_image.root_device_name

    del_root_volume = source_image.block_device_mapping[root_device_name].delete_on_termination
    print("DEL_ROOT_VOLUME", del_root_volume)

    block_device_map = BlockDeviceMapping()
    print("BLOCK_DEVICE_MAP", block_device_map)
    block_device_map[root_device_name] = EBSBlockDeviceType(snapshot_id=target_snapshot_id,
                                                            size=source_volume_size,
                                                            volume_type='gp2',
                                                            delete_on_termination=True)
    print("BLOCK_DEVICE_MAP_LATEST", block_device_map)

    return block_device_map


def create_image(connection, source_image, block_device_map, username, target_snapshot_id, source_volume_size, unit):
    
    """Create a new AMI out of the copied snapshot and the pre-defined block device map."""
    name_raw = username + "-for "+ unit +" instance"
    target_image_id = connection.register_image(
        name=name_raw,
        architecture=source_image.architecture,
        kernel_id=source_image.kernel_id,
        ramdisk_id=source_image.ramdisk_id,
        root_device_name=source_image.root_device_name,
        block_device_map=block_device_map,
        virtualization_type=source_image.virtualization_type,
        sriov_net_support="simple")
    
    #except EC2ResponseError as exc:
    #    logging.critical('The creation of the copied AMI failed: %s', exc.error_message)
    #    sys.exit(1)

    while connection.get_all_images(image_ids=target_image_id)[0].state == 'pending':
        logging.debug('Waiting for completion of the AMI creation.')
        sleep(5)

    if connection.get_all_images(image_ids=target_image_id)[0].state == 'failed':
        logging.critical('The creation of the copied AMI failed. The new AMI (%s) is broken.', target_image_id)
        sys.exit(1)
    return target_image_id

def main(username, ins_type):
    target_images = []
    block_device_maps = []

    awsaccessid, awssecretkey, ami_id, instance_id, unit, sg = config_parser.parser()

    connection = connect_to_region('us-east-1',
                                   aws_access_key_id=awsaccessid,
                                   aws_secret_access_key=awssecretkey)

    print("CONNECTION", connection)

    # get information about the image which should be copied

    source_image = connection.get_all_images(image_ids=[ami_id])[0]
    print("SOURCE_IMAGE", source_image)
    #except EC2ResponseError as exc:
    #    logging.critical('Getting the source AMI failed: %s', exc.error_message)
    #    sys.exit(1)

    # copy the snapshot representing the root file system of the AMI
    root_device_name = source_image.root_device_name
    print("ROOT_DEVICE_NAME", root_device_name)

    source_securitygroup = connection.get_all_security_groups(group_ids=["sg])
    print("SOURCE_SECURITYGROUP", source_securitygroup)
    for sg in source_securitygroup:
        source_sg = sg.id


    volume_id = connection.get_all_volumes(filters={'attachment.instance_id': [ins_id]})
    print("VOLUME_ID", volume_id)
    for vol in volume_id:
        source_volume_id = vol.id
        source_volume_size = vol.size
        print(source_volume_id)
        # print(source_volume_size)

    target_snapshot_id = copy_snapshot(connection, source_volume_id, username, unit)
    print("TARGET_SNAPSHOT_ID", target_snapshot_id)
    #logging.info("The target snapshot is available as: %s", target_snapshot_id)

    block_device_map = build_block_device_map(source_image,
                                              target_snapshot_id,
                                              source_volume_size)
    print("BLOCK_DEVICE_MAP", block_device_map)

    block_device_maps.append(block_device_map)

    target_image_id = create_image(connection,
                                   source_image,
                                   block_device_map, username, target_snapshot_id, source_volume_size, unit)
    print("TARGET_IMAGE_ID", target_image_id)

    target_images.append(target_image_id)

    #logging.info('The new image is available as: %s', target_image_id)

    instance_ip = run_instance(connection, target_images[0], block_device_maps[0], source_sg, username, ins_type, unit)

    #logging.info('The new instance is available as: %s', instance_ip)
    #print("Time taken to create the instance: {}".format(datetime.now()-start_time))
    
    #Delete the AMI and snapshot after creating the instance.
    snapshot_id = connection.get_all_snapshots(filters={"snapshot_id": target_snapshot_id})[0]
    ami_id = connection.get_all_images(filters={"image_id": target_images[0]})[0]
    connection.deregister_image(ami_id.id)
    connection.delete_snapshot(snapshot_id.id)
    instance_ip = instance_ip + ":8000"

    return instance_ip
