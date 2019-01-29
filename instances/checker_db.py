from instances.models import UserProfiles

def instance_check(username, type):
    try:
        user_objs = UserProfiles.objects.all().filter(username=username)
        print(user_objs)
        counter = user_objs.count()
        for user_obj in user_objs.iterator():
            obj_user = user_obj.username
            obj_type = user_obj.ins_type

            if obj_user == username:
                if obj_type != type:
                    counter -= 1
                    if counter != 0:
                        continue
                    else:
                        message = "IDNE"
                        print("MESSAGE", message)
                        return message

                elif obj_type == type:
                    ins_user = username
                    ins_type = type
                    message = "IEUE"
                    print("MESSAGE", message)
                    return message

                else:
                    message = "IDNE"
                    print("MESSAGE", message)
                    return message

    except UserProfiles.DoesNotExist:
        message = "UDNE"
        print("MESSAGE", message)
        return message
