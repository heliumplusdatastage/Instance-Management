# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from instances.models import UserProfile, InstanceType, Instance


 # Register your models here.	# Register your models here.
admin.site.register(UserProfile)
admin.site.register(InstanceType)
admin.site.register(Instance)

