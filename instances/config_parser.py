import yaml

def parser(type):
    with open("/home/ubuntu/ec2clone-kyle/instances/config.yaml", 'r') as cred:
        data_loaded = yaml.load(cred)

        aws_access_id = data_loaded["awscredentials"]["awsaccessid"]
        aws_secret_key = data_loaded["awscredentials"]["awssecretkey"]
        sg = data_loaded["secuirtygroup"]["sg"]

        if type == "p2.xlarge":
            ami_id = data_loaded["gpuinstanceattributes"]["amiid"]
            ins_id = data_loaded["gpuinstanceattributes"]["instanceid"]
            unit = data_loaded["gpuinstanceattributes"]["unit"]
            print(ami_id, ins_id, unit)
            return aws_access_id, aws_secret_key, ami_id, ins_id, unit, sg
        elif type == "t2.2xlarge" or type == "t2.large":
            ami_id = data_loaded["cpuinstanceattributes"]["amiid"]
            ins_id = data_loaded["cpuinstanceattributes"]["instanceid"]
            unit = data_loaded["cpuinstanceattributes"]["unit"]
            print(ami_id, ins_id, unit)
            return aws_access_id, aws_secret_key, ami_id, ins_id, unit, sg

        else:
            return aws_access_id, aws_secret_key, sg
