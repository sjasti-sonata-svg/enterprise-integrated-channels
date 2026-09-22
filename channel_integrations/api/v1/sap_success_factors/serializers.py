"""
Serializer for Success Factors configuration.
"""

from rest_framework import serializers

from channel_integrations.api.serializers import (
    EnterpriseCustomerPluginConfigSerializer,
)
from channel_integrations.sap_success_factors.models import (
    SAPSuccessFactorsEnterpriseCustomerConfiguration,
)
from channel_integrations.utils import is_valid_pem_private_key


class SAPSuccessFactorsConfigSerializer(EnterpriseCustomerPluginConfigSerializer):
    class Meta:
        model = SAPSuccessFactorsEnterpriseCustomerConfiguration
        extra_fields = (
            "key",
            "sapsf_base_url",
            "sapsf_company_id",
            "sapsf_user_id",
            "secret",
            "auth_type",
            "private_key",
            "private_key_passphrase",
            "saml_assertion_audience",
            "user_type",
            "additional_locales",
            "show_course_price",
            "transmit_total_hours",
            "prevent_self_submit_grades",
        )
        fields = EnterpriseCustomerPluginConfigSerializer.Meta.fields + extra_fields

    key = serializers.CharField(required=False, allow_blank=False, read_only=False)
    secret = serializers.CharField(required=False, allow_blank=False, read_only=False)
    private_key = serializers.CharField(
        required=False, allow_blank=False, write_only=True
    )
    private_key_passphrase = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        private_key = attrs.get("private_key")
        if private_key is not None:
            passphrase = attrs.get("private_key_passphrase")
            if not is_valid_pem_private_key(private_key, passphrase):
                raise serializers.ValidationError(
                    {"private_key": "Must be a PEM-encoded private key."}
                )
        return attrs

    def _handle_credentials(
        self, instance, key=None, secret=None, private_key=None, private_key_passphrase=None
    ):
        """
        Helper to update credentials consistently.
        """
        if key is not None:
            instance.encrypted_key = key
        if secret is not None:
            instance.encrypted_secret = secret
        if private_key is not None:
            instance.encrypted_private_key = private_key
        if private_key_passphrase is not None:
            instance.encrypted_private_key_passphrase = private_key_passphrase

    def create(self, validated_data):
        key = validated_data.pop("key", None)
        secret = validated_data.pop("secret", None)
        private_key = validated_data.pop("private_key", None)
        private_key_passphrase = validated_data.pop("private_key_passphrase", None)

        instance = super().create(validated_data)
        self._handle_credentials(instance, key, secret, private_key, private_key_passphrase)
        instance.save()
        return instance

    def update(self, instance, validated_data):
        key = validated_data.pop("key", None)
        secret = validated_data.pop("secret", None)
        private_key = validated_data.pop("private_key", None)
        private_key_passphrase = validated_data.pop("private_key_passphrase", None)

        instance = super().update(instance, validated_data)
        self._handle_credentials(instance, key, secret, private_key, private_key_passphrase)
        instance.save()
        return instance
