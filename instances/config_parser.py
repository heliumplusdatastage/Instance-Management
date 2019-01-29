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
        else:
            ami_id = data_loaded["cpuinstanceattributes"]["amiid"]
            ins_id = data_loaded["gpuinstanceattributes"]["instanceid"]
            unit = data_loaded["gpuinstanceattributes"]["unit"]
            print(ami_id, ins_id, unit)

        return aws_access_id, aws_secret_key, ami_id, ins_id, unit, sg
