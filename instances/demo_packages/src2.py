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


def run_instance(connection, target_image_id, block_device_map, security_group):
    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id='subnet-bf4498d8',
                                                                        groups=[security_group],
                                                                        associate_public_ip_address=True)
    interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
    reservation = connection.run_instances(image_id=target_image_id,
                                           instance_type="t2.medium",
                                           key_name="tfjpnbserv",
                                           network_interfaces=interfaces,
                                           block_device_map=block_device_map
                                           )
    instance = reservation.instances[0]
    for _ in range(0, 600):
        instance.update()
        if str(instance.state) == "running":
            instance_ip = instance.ip_address
            exit
        else:
            sleep(1)

    return instance_ip


def copy_snapshot(connection, source_volume_id):
    while True:
        try:
            target_snapshot = connection.create_snapshot(source_volume_id)
            for _ in range(0, 600):
                target_snapshot.update()
                if str(target_snapshot.status) == "completed":
                    target_snapshot_id = target_snapshot.id
                    break
                else:
                    sleep(1)

        except EC2ResponseError as _:
            continue
        return target_snapshot_id
        break


def build_block_device_map(source_image, target_snapshot_id, source_volume_size):
    """Create a block device map which is used for the copied AMI.
    The created block device map contains a root volumes with 8GB of storage
    on general purpose SSD (gp2).
    """

    root_device_name = source_image.root_device_name

    del_root_volume = source_image.block_device_mapping[root_device_name].delete_on_termination

    block_device_map = BlockDeviceMapping()
    block_device_map[root_device_name] = EBSBlockDeviceType(snapshot_id=target_snapshot_id,
                                                            size=source_volume_size,
                                                            volume_type='gp2',
                                                            delete_on_termination=del_root_volume)

    return block_device_map


def create_image(connection, source_image, block_device_map):
    """Create a new AMI out of the copied snapshot and the pre-defined block device map."""

    target_image_id = connection.register_image(
        name=names.get_full_name(),
        architecture=source_image.architecture,
        kernel_id=source_image.kernel_id,
        ramdisk_id=source_image.ramdisk_id,
        root_device_name=source_image.root_device_name,
        block_device_map=block_device_map,
        virtualization_type=source_image.virtualization_type)
    #except EC2ResponseError as exc:
    #    logging.critical('The creation of the copied AMI failed: %s', exc.error_message)
    #    sys.exit(1)

    #while connection.get_all_images(image_ids=target_image_id)[0].state == 'pending':
    #    logging.debug('Waiting for completion of the AMI creation.')
    #    sleep(5)

    #if connection.get_all_images(image_ids=target_image_id)[0].state == 'failed':
    #    logging.critical('The creation of the copied AMI failed. The new AMI (%s) is broken.', target_image_id)
    #    sys.exit(1)

    return target_image_id


def main():
    target_images = []
    block_device_maps = []
    #parser = argparse.ArgumentParser(description='Script to copy public AMIs to the own account.')
    #parser.add_argument('-a', '--aws-access-key', dest='aws_access_key', default='AKIAJ7WYPWEAQAS6XSLA')
    #parser.add_argument('-s', '--aws-secret-key', dest='aws_secret_key',
    #                    default='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')
    #parser.add_argument('-r', '--region', dest='region', default='us-east-1',
    #                    help='The AWS region which contains the source AMI and will contain the ' +
    #                         'target AMI as well.')
    #parser.add_argument('-i', '--ami-id', dest='ami_id', default='ami-0ac019f4fcb7cb7e6',
    #                    help='The ID of the AMI to copy.')
    #parser.add_argument('-l', '--log-level', dest='log_level', default='INFO',
    #                    help='Sets the log level of the script. Defaults to INFO.')

    #args = parser.parse_args()
    #logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=args.log_level)
    #logging.getLogger('boto').setLevel(logging.CRITICAL)

    connection = connect_to_region('us-east-1',
                                   aws_access_key_id='AKIAJ7WYPWEAQAS6XSLA',
                                   aws_secret_access_key='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')

    print(connection)

    # get information about the image which should be copied

    source_image = connection.get_all_images(image_ids=['ami-06727c8339777cf95'])[0]
    #except EC2ResponseError as exc:
    #    logging.critical('Getting the source AMI failed: %s', exc.error_message)
    #    sys.exit(1)

    # copy the snapshot representing the root file system of the AMI
    root_device_name = source_image.root_device_name

    source_securitygroup = connection.get_all_security_groups(group_ids=["sg-01d534f8c50c893ad"])
    for sg in source_securitygroup:
        source_sg = sg.id

    volume_id = connection.get_all_volumes(filters={'attachment.instance_id': ["i-06b8eb0f10cd01b79"]})
    for vol in volume_id:
        source_volume_id = vol.id
        source_volume_size = vol.size
        print(source_volume_id)
        # print(source_volume_size)

    target_snapshot_id = copy_snapshot(connection, source_volume_id)
    #logging.info("The target snapshot is available as: %s", target_snapshot_id)

    block_device_map = build_block_device_map(source_image,
                                              target_snapshot_id,
                                              source_volume_size)

    block_device_maps.append(block_device_map)

    target_image_id = create_image(connection,
                                   source_image,
                                   block_device_map)

    target_images.append(target_image_id)

    #logging.info('The new image is available as: %s', target_image_id)

    instance_ip = run_instance(connection, target_images[0], block_device_maps[0], source_sg)

    #logging.info('The new instance is available as: %s', instance_ip)
    #print("Time taken to create the instance: {}".format(datetime.now()-start_time))

    return instance_ip
