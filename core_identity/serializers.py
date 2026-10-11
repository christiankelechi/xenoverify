"""
REST API Serializers for Xenoverify Core Identity Platform
"""

from rest_framework import serializers
from .models import DIDRegistry, IssuedCredential, EvaluationLog


class DIDRegistrySerializer(serializers.ModelSerializer):
    class Meta:
        model = DIDRegistry
        fields = '__all__'


class IssuedCredentialSerializer(serializers.ModelSerializer):
    issuer_name = serializers.CharField(source='issuer.entity_name', read_only=True)

    class Meta:
        model = IssuedCredential
        fields = '__all__'


class EvaluationLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = EvaluationLog
        fields = '__all__'
