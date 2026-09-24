"""
Django admin integration for configuring sap_success_factors app to communicate with SAP SuccessFactors systems.
"""

from config_models.admin import ConfigurationModelAdmin
from django import forms
from django.contrib import admin, messages
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect
from django_object_actions import DjangoObjectActions
from requests import RequestException

from channel_integrations.exceptions import ClientError
from channel_integrations.integrated_channel.admin import BaseLearnerDataTransmissionAuditAdmin
from channel_integrations.sap_success_factors.client import SAPSuccessFactorsAPIClient
from channel_integrations.sap_success_factors.models import (
    SAPAuthType,
    SAPSuccessFactorsEnterpriseCustomerConfiguration,
    SAPSuccessFactorsGlobalConfiguration,
    SapSuccessFactorsLearnerDataTransmissionAudit,
)
from channel_integrations.utils import is_valid_pem_private_key

LEGACY_AUTH_FIELDS = ("decrypted_key", "decrypted_secret")
MODERN_AUTH_FIELDS = (
    "decrypted_private_key",
    "decrypted_private_key_passphrase",
    "saml_assertion_audience",
)


class WriteOnlySecretWidgetMixin:
    """
    Never render a value, so a stored secret isn't exposed in the page HTML on a change form,
    and a newly submitted-but-rejected value isn't echoed back either when a *different* field
    on the same form fails validation and Django re-renders this one bound to the submitted data.
    """

    def format_value(self, value):
        return ""


class WriteOnlySecretTextarea(WriteOnlySecretWidgetMixin, forms.Textarea):
    pass


class WriteOnlySecretTextInput(WriteOnlySecretWidgetMixin, forms.TextInput):
    pass


class SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(forms.ModelForm):
    """
    Admin form that validates credentials required for the selected ``auth_type``.
    """

    class Meta:
        model = SAPSuccessFactorsEnterpriseCustomerConfiguration
        fields = "__all__"
        widgets = {
            "decrypted_private_key": WriteOnlySecretTextarea,
            "decrypted_private_key_passphrase": WriteOnlySecretTextInput,
        }

    def clean_decrypted_private_key(self):
        """
        A blank submission means "leave the stored key unchanged", not "clear it" -- the field
        never displays the current value (see ``WriteOnlySecretTextarea``), so an admin has no
        way to notice, let alone intentionally resubmit, whatever key is already stored.
        """
        value = self.cleaned_data.get("decrypted_private_key")
        if not value and self.instance.pk:
            return self.instance.decrypted_private_key
        return value

    def clean_decrypted_private_key_passphrase(self):
        """
        Same "blank means unchanged" behavior as ``clean_decrypted_private_key``, for the same
        reason: this field is also write-only, so a blank submission can't be distinguished from
        "I want to keep what's already stored" by the admin filling out the form.
        """
        value = self.cleaned_data.get("decrypted_private_key_passphrase")
        if not value and self.instance.pk:
            return self.instance.decrypted_private_key_passphrase
        return value

    def clean(self):
        cleaned_data = super().clean()
        auth_type = cleaned_data.get("auth_type")
        is_switching_to_self_signed = (
            auth_type == SAPAuthType.SELF_SIGNED_ASSERTION
            and "decrypted_private_key" in self.fields
        )
        if is_switching_to_self_signed:
            private_key = cleaned_data.get("decrypted_private_key")
            passphrase = cleaned_data.get("decrypted_private_key_passphrase")
            if not private_key:
                self.add_error(
                    "decrypted_private_key",
                    "A private key is required when the auth type is self-signed.",
                )
            elif not is_valid_pem_private_key(private_key, passphrase):
                self.add_error(
                    "decrypted_private_key",
                    "Must be a PEM-encoded private key.",
                )
        return cleaned_data


@admin.register(SAPSuccessFactorsGlobalConfiguration)
class SAPSuccessFactorsGlobalConfigurationAdmin(ConfigurationModelAdmin):
    """
    Django admin model for SAPSuccessFactorsGlobalConfiguration.
    """
    list_display = (
        "completion_status_api_path",
        "course_api_path",
        "oauth_api_path",
        "saml_assertion_api_path",
        "oauth_token_api_path",
        "provider_id",
        "search_student_api_path",
    )

    class Meta:
        model = SAPSuccessFactorsGlobalConfiguration


@admin.register(SAPSuccessFactorsEnterpriseCustomerConfiguration)
class SAPSuccessFactorsEnterpriseCustomerConfigurationAdmin(DjangoObjectActions, admin.ModelAdmin):
    """
    Django admin model for SAPSuccessFactorsEnterpriseCustomerConfiguration.
    """
    form = SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm

    fields = (
        "enterprise_customer",
        "idp_id",
        "active",
        "sapsf_base_url",
        "sapsf_company_id",
        "decrypted_key",
        "decrypted_secret",
        "auth_type",
        "decrypted_private_key",
        "decrypted_private_key_passphrase",
        "saml_assertion_audience",
        "sapsf_user_id",
        "user_type",
        "has_access_token",
        "prevent_self_submit_grades",
        "show_course_price",
        "dry_run_mode_enabled",
        "disable_learner_data_transmissions",
        "transmit_total_hours",
        "transmit_course_hours",
        "transmission_chunk_size",
        "additional_locales",
        "catalogs_to_transmit",
        "display_name",
    )

    list_display = (
        "enterprise_customer_name",
        "active",
        "sapsf_base_url",
        "modified",
    )
    ordering = ("enterprise_customer__name",)

    readonly_fields = ("has_access_token",)

    raw_id_fields = ("enterprise_customer",)

    list_filter = ("active",)
    search_fields = ("enterprise_customer__name",)
    change_actions = ("force_content_metadata_transmission",)

    class Meta:
        model = SAPSuccessFactorsEnterpriseCustomerConfiguration

    def get_fields(self, request, obj=None):
        """
        Show only the credential fields relevant to the configuration's ``auth_type``.

        A new (unsaved) configuration defaults to SAP-signed auth, so the self-signed fields
        stay hidden until an admin has explicitly switched it, avoiding a wall of unused inputs.
        """
        fields = list(super().get_fields(request, obj))
        auth_type = getattr(obj, "auth_type", SAPAuthType.SAP_SIGNED_ASSERTION)
        if auth_type == SAPAuthType.SELF_SIGNED_ASSERTION:
            hidden_fields = LEGACY_AUTH_FIELDS
        else:
            hidden_fields = MODERN_AUTH_FIELDS
        return [field for field in fields if field not in hidden_fields]

    def enterprise_customer_name(self, obj):
        """
        Returns: the name for the attached EnterpriseCustomer.

        Args:
            obj: The instance of SAPSuccessFactorsEnterpriseCustomerConfiguration
                being rendered with this admin form.
        """
        return obj.enterprise_customer.name

    @admin.display(
        description="Has Access Token?",
        boolean=True,
    )
    def has_access_token(self, obj):
        """
        Confirms the presence and validity of the access token for the SAP SuccessFactors client instance

        Returns: a bool value indicating the presence of the access token

        Args:
            obj: The instance of SAPSuccessFactorsEnterpriseCustomerConfiguration
                being rendered with this admin form.
        """
        try:
            access_token, expires_at = SAPSuccessFactorsAPIClient.get_oauth_access_token(
                obj.sapsf_base_url,
                obj.decrypted_key,
                obj.decrypted_secret,
                obj.sapsf_company_id,
                obj.sapsf_user_id,
                obj.user_type,
                obj.enterprise_customer.uuid
            )
        except (RequestException, ClientError):
            return False
        return bool(access_token and expires_at)

    @admin.action(
        description="Force content metadata transmission for this Enterprise Customer"
    )
    def force_content_metadata_transmission(self, request, obj):
        """
        Updates the modified time of the customer record to retransmit courses metadata
        and redirects to configuration view with success or error message.
        """
        try:
            obj.enterprise_customer.save()
            messages.success(
                request,
                f'''The sap success factors enterprise customer content metadata
                “<SAPSuccessFactorsEnterpriseCustomerConfiguration for Enterprise
                {obj.enterprise_customer.name}>” was updated successfully.''',
            )
        except ValidationError:
            messages.error(
                request,
                f'''The sap success factors enterprise customer content metadata
                “<SAPSuccessFactorsEnterpriseCustomerConfiguration for Enterprise
                {obj.enterprise_customer.name}>” was not updated successfully.''',
            )
        return HttpResponseRedirect(
            "/admin/sap_success_factors_channel/sapsuccessfactorsenterprisecustomerconfiguration"
        )
    force_content_metadata_transmission.label = "Force content metadata transmission"


@admin.register(SapSuccessFactorsLearnerDataTransmissionAudit)
class SapSuccessFactorsLearnerDataTransmissionAuditAdmin(
    BaseLearnerDataTransmissionAuditAdmin
):
    """
    Django admin model for SapSuccessFactorsLearnerDataTransmissionAudit.
    """

    list_display = (
        "enterprise_course_enrollment_id",
        "course_id",
        "status",
        "modified",
    )

    readonly_fields = (
        "sapsf_user_id",
        "progress_status",
        "content_title",
        "enterprise_customer_name",
        "friendly_status_message",
        "api_record",
    )

    search_fields = (
        "sapsf_user_id",
        "enterprise_course_enrollment_id",
        "course_id",
        "content_title",
        "friendly_status_message"
    )

    list_per_page = 1000

    class Meta:
        model = SapSuccessFactorsLearnerDataTransmissionAudit
