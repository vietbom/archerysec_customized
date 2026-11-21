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

from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from rest_framework import serializers

User = get_user_model()

from user_management.models import UserProfile


class UserSettingsSerializers(serializers.ModelSerializer):
    landing_page = serializers.SerializerMethodField()
    logintime = serializers.SerializerMethodField()

    def get_landing_page(self, obj):
        # compute the extra field value here
        # print(obj)
        return "test"

    def get_logintime(self, obj):
        return "time"

    class Meta:
        model = User
        fields = [
            "uu_id",
            "role",
            "image",
            "email",
            "name",
            "landing_page",
            "logintime",
        ]

    uu_id = serializers.UUIDField()
    email = serializers.EmailField(max_length=255)
    name = serializers.CharField(max_length=255)
    role = serializers.CharField(max_length=255)
    image = serializers.ImageField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["uu_id", "image", "email", "name"]

    def update(self, instance, validated_data):
        instance.email = validated_data.get("email", instance.email)
        instance.name = validated_data.get("name", instance.name)
        instance.image = validated_data.get("image", instance.image)
        instance.save()
        return instance


class ForgotPassReqSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)


class ResetPassReqSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)


class UpdtPassReqSerializer(serializers.Serializer):
    user_id = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)


class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True, trim_whitespace=False)
    new_password1 = serializers.CharField(required=True, write_only=True, trim_whitespace=False)
    new_password2 = serializers.CharField(required=True, write_only=True, trim_whitespace=False)

    def validate(self, attrs):
        self.password_form = PasswordChangeForm(self.context["request"].user, attrs)
        if not self.password_form.is_valid():
            raise serializers.ValidationError(self.password_form.errors)
        return attrs

    def save(self):
        request = self.context["request"]
        # Validation, including Django's password policy, must finish before
        # saving. A rejected form previously returned an unbound `user` (500).
        self.validated_data
        user = self.password_form.save()
        if hasattr(request, "session"):
            update_session_auth_hash(request, user)
        return user
