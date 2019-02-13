from instances.models import UserProfile, InstanceType, Instance
from django.core.exceptions import ObjectDoesNotExist

#To add users to the database.

def add_instance(username, type):

    try:
        user_obj = UserProfile.objects.all().filter(user=username)
        if user_obj.exists():
            ins_type_obj = InstanceType.objects.filter(user=user_obj, instancetype=type)
            if ins_type_obj.exists():
                return "UE-ITE", user_obj, ins_type_obj

            raise Exception("UE-ITDNE")
        raise Exception("UDNE-ITDNE")

    except Exception as error:
        if error == "UE-ITDNE":
            return error, user_obj, "None"

        else:
            return error, "None", "None"

