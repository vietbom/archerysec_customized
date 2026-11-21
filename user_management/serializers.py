# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.hashers import identify_hasher
from rest_framework import serializers

from user_management.models import Organization, UserProfile, UserRoles


class UserCreatReqSerializers(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    organization = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)
    role = serializers.CharField(max_length=255)
    name = serializers.CharField(max_length=255)


class UserProfileSerializers(serializers.Serializer):
    uu_id = serializers.CharField(max_length=255)
    email = serializers.EmailField(max_length=255)
    organization = serializers.CharField(max_length=255)
    name = serializers.CharField(max_length=255)
    role = serializers.CharField(max_length=255)
    image = serializers.CharField(max_length=255)
    is_active = serializers.BooleanField()
    is_staff = serializers.BooleanField()
    password_updt_time = serializers.DateTimeField()


class UserProfilePutReqSerializers(serializers.Serializer):
    password = serializers.CharField(required=False, allow_blank=True, write_only=True, trim_whitespace=False)
    name = serializers.CharField(max_length=255, required=False)
    image = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True)

    def validate_password(self, value):
        if value and value != self.instance.password:
            raise serializers.ValidationError("Use Change password with your current password and confirmation.")
        return value


ROLE_CHOICES = (
    ("1", "Admin"),
    ("2", "Analyst"),
    ("3", "Viewer"),
)

B_CHOICES = (("True", "Active"), ("Flase", "Deactive"))


class UserPutReqSerializers(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(
        required=False, allow_blank=True, write_only=True, trim_whitespace=False,
        style={"input_type": "password", "placeholder": "New password (optional)"}
    )
    password_confirm = serializers.CharField(required=False, allow_blank=True, write_only=True, trim_whitespace=False)
    name = serializers.CharField(max_length=255)
    # role = serializers.ChoiceField(choices=ROLE_CHOICES)
    image = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True)
    role = serializers.PrimaryKeyRelatedField(queryset=UserRoles.objects.all(), required=False)
    organization = serializers.PrimaryKeyRelatedField(queryset=Organization.objects.all(), required=False)
    is_active = serializers.BooleanField(required=False)
    is_staff = serializers.BooleanField(required=False)
    pass_token = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    def validate(self, attrs):
        password = attrs.pop("password", "")
        confirmation = attrs.pop("password_confirm", "")
        # An already-open old form may still submit the stored hash. Treat it
        # exactly like an omitted password; never hash a stored hash again.
        if not password or password == self.instance.password:
            return attrs
        try:
            identify_hasher(password)
        except ValueError:
            pass
        else:
            raise serializers.ValidationError({"password": "Enter a new password, not an encoded password hash."})
        form = SetPasswordForm(self.instance, {"new_password1": password, "new_password2": confirmation})
        if not form.is_valid():
            names = {"new_password1": "password", "new_password2": "password_confirm"}
            raise serializers.ValidationError({names.get(key, key): value for key, value in form.errors.items()})
        self.new_password = password
        return attrs

    def update(self, instance, validated_data):
        fields = list(validated_data)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        if hasattr(self, "new_password"):
            instance.set_password(self.new_password)
            fields.extend(["password", "password_updt_time"])
        if fields:
            instance.save(update_fields=fields)
        return instance


class UserRoleSerializers(serializers.Serializer):
    role = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=255)
    uu_id = serializers.CharField(max_length=255)


class OrganizationSerializers(serializers.Serializer):
    uu_id = serializers.CharField(max_length=255)
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=255)
    logo = serializers.CharField(max_length=255)
    contact = serializers.CharField(max_length=255)
    address = serializers.CharField(max_length=255)


class CreateOrganizationSerializers(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=255)
