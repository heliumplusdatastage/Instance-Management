from instances.models import UserProfile

def instance_check(username, type):
    try:
        #*****
        user_obj = UserProfile.objects.filter(user=username)
        ins_type_obj = InstanceType.objects.filter(instancetype=type, user=user_obj)
        if user_obj.exists():
            if ins_type_obj.exists():
                print("Passes Instance type")
                counter1 = user_obj.count()
                ins_objs = Instance.objects.all().filter(instancetype=ins_type_obj)
                print(ins_objs)
                counter2 = ins_objs.count()
                print(counter2)
                ins_obj_list = []
                for ins_obj in ins_objs.iterator():
                    print(ins_obj)
                    ins_staticip = ins_obj.staticip
                    ins_id = ins_obj.instanceid
                    print(counter2)
                    ins_obj_list.append(ins_staticip)
                    counter2 = counter2 - 1

                return ins_obj_list

            raise Exception("UE-IDNE")
        raise Exception("UDNE-IDNE")

    except Exception as error:
        return error
        #*****

#       user_objs = UserProfile.objects.all().filter(username=username)
#        print(user_objs)
#        counter = user_objs.count()
#        for user_obj in user_objs.iterator():
#            obj_user = user_obj.username
#            obj_type = user_obj.ins_type

#            if obj_user == username:
#                if obj_type != type:
#                    counter -= 1
#                    if counter != 0:
#                        continue
#                    else:
#                        message = "IDNE"
#                        print("MESSAGE", message)
#                        return message

#                elif obj_type == type:
#                    ins_user = username
#                    ins_type = type
#                    message = "IEUE"
#                    print("MESSAGE", message)
#                    return message

#                else:
#                    message = "IDNE"
#                    print("MESSAGE", message)
#                    return message

#    except UserProfile.DoesNotExist:
#        message = "UDNE"
#        print("MESSAGE", message)
#        return message
