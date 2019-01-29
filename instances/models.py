# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.

from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organizations = models.TextField(blank=True, null=True)


class CSApp(models.Model):
    name = models.CharField(max_length=255)
    url = models.TextField()
    logo = models.TextField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)

class UserProfiles(models.Model):
    username = models.CharField(max_length=255, blank=True, null=True, default="username")
    staticip = models.CharField(max_length=255, blank=True, null=True, default="staticip")
    ins_type = models.CharField(max_length=255, blank=True, null=True, default="type")

    def __str__(self):
        value = self.ins_type + "-" + self.username
        return value


