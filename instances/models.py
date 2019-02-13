# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models

# Create your models here.

from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organizations = models.TextField(blank=True, null=True)


class UserProfile(models.Model):
    user = models.CharField(max_length=255, blank=True, null=True, default="user")

    def __str__(self):
        value = str(self.user)
        return value


class InstanceType(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    instancetype = models.CharField(max_length=255, blank=True, null=True, default="instance type")

    def __str__(self):
        value = str(self.instancetype) + "~" + str(self.user)
        return value


class Instance(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    instancetype = models.ForeignKey(InstanceType, on_delete=models.CASCADE)
    instanceid = models.CharField(max_length=255, blank=True, null=True, default="instance id")
    staticip = models.CharField(max_length=255, blank=True, null=True, default="static ip")

    def __str__(self):
        value = str(self.instanceid) + "-" + str(self.staticip)
        return value


