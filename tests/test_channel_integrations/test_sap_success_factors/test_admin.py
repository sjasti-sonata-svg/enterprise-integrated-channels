"""
Tests for the SAP Success Factors admin module.
"""

from unittest.mock import MagicMock, patch

from django import forms
from django.contrib.admin.sites import AdminSite
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponseRedirect
from django.test import TestCase
from pytest import mark

from channel_integrations.sap_success_factors.admin import (
    SAPSuccessFactorsEnterpriseCustomerConfigurationAdmin,
    SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm,
)
from channel_integrations.sap_success_factors.models import SAPAuthType, SAPSuccessFactorsEnterpriseCustomerConfiguration
from test_utils import factories, generate_test_private_key_pem


@mark.django_db
class TestSAPSuccessFactorsEnterpriseCustomerConfigurationAdmin(TestCase):
    """
    Tests for the ``SAPSuccessFactorsEnterpriseCustomerConfigurationAdmin`` admin class.
    """

    def setUp(self):
        """
        Set up test data.
        """
        super().setUp()
        self.admin_site = AdminSite()
        self.admin_instance = SAPSuccessFactorsEnterpriseCustomerConfigurationAdmin(
            SAPSuccessFactorsEnterpriseCustomerConfiguration, self.admin_site
        )
        self.sap_config = factories.SAPSuccessFactorsEnterpriseCustomerConfigurationFactory()
        self.request = HttpRequest()
        self.request.session = {}
        self.request._messages = MagicMock()  # pylint:disable=protected-access

    def test_force_content_metadata_transmission_success(self):
        """
        Test force_content_metadata_transmission method with successful save.
        """
        with patch.object(self.sap_config.enterprise_customer, 'save') as mock_save:
            response = self.admin_instance.force_content_metadata_transmission(
                self.request, self.sap_config
            )

            # Verify the enterprise customer save was called
            mock_save.assert_called_once()

            # Verify the response is a redirect to the correct URL
            assert isinstance(response, HttpResponseRedirect)
            assert response.url == "/admin/sap_success_factors_channel/sapsuccessfactorsenterprisecustomerconfiguration"

    def test_force_content_metadata_transmission_validation_error(self):
        """
        Test force_content_metadata_transmission method with ValidationError.
        """
        with patch.object(
            self.sap_config.enterprise_customer, 'save',
            side_effect=ValidationError("Test validation error")
        ) as mock_save:
            response = self.admin_instance.force_content_metadata_transmission(
                self.request, self.sap_config
            )

            # Verify the enterprise customer save was called
            mock_save.assert_called_once()

            # Verify the response is a redirect to the correct URL
            assert isinstance(response, HttpResponseRedirect)
            assert response.url == "/admin/sap_success_factors_channel/sapsuccessfactorsenterprisecustomerconfiguration"

    def test_force_content_metadata_transmission_label(self):
        """
        Test that the force_content_metadata_transmission method has the correct label.
        """
        assert self.admin_instance.force_content_metadata_transmission.label == "Force content metadata transmission"

    def test_get_fields_hides_self_signed_fields_for_sap_signed_auth_type(self):
        """
        Test that self-signed auth fields are hidden when the configuration uses SAP-signed auth.
        """
        self.sap_config.auth_type = SAPAuthType.SAP_SIGNED_ASSERTION
        fields = self.admin_instance.get_fields(self.request, self.sap_config)

        assert "decrypted_key" in fields
        assert "decrypted_secret" in fields
        assert "decrypted_private_key" not in fields
        assert "decrypted_private_key_passphrase" not in fields
        assert "saml_assertion_audience" not in fields

    def test_get_fields_hides_legacy_fields_for_self_signed_auth_type(self):
        """
        Test that legacy auth fields are hidden when the configuration uses self-signed auth.
        """
        self.sap_config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION
        fields = self.admin_instance.get_fields(self.request, self.sap_config)

        assert "decrypted_key" not in fields
        assert "decrypted_secret" not in fields
        assert "decrypted_private_key" in fields
        assert "decrypted_private_key_passphrase" in fields
        assert "saml_assertion_audience" in fields

    def test_get_fields_defaults_to_sap_signed_for_new_configuration(self):
        """
        Test that a new (unsaved) configuration shows the SAP-signed fields by default.
        """
        fields = self.admin_instance.get_fields(self.request, obj=None)

        assert "decrypted_key" in fields
        assert "decrypted_private_key" not in fields


@mark.django_db
class TestSAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(TestCase):
    """
    Tests for the ``SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm``.
    """

    def setUp(self):
        super().setUp()
        self.sap_config = factories.SAPSuccessFactorsEnterpriseCustomerConfigurationFactory()

    def _form_data(self, **overrides):
        data = {
            "enterprise_customer": self.sap_config.enterprise_customer_id,
            "sapsf_base_url": "http://sapsf.example.com",
            "sapsf_company_id": "company",
            "sapsf_user_id": "user",
            "user_type": SAPSuccessFactorsEnterpriseCustomerConfiguration.USER_TYPE_USER,
            "auth_type": SAPAuthType.SAP_SIGNED_ASSERTION,
            "transmission_chunk_size": 1,
        }
        data.update(overrides)
        return data

    def test_self_signed_auth_requires_private_key(self):
        form = SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(
            data=self._form_data(auth_type=SAPAuthType.SELF_SIGNED_ASSERTION),
            instance=self.sap_config,
        )
        assert not form.is_valid()
        assert "decrypted_private_key" in form.errors

    def test_self_signed_auth_rejects_malformed_private_key(self):
        form = SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(
            data=self._form_data(
                auth_type=SAPAuthType.SELF_SIGNED_ASSERTION,
                decrypted_private_key="not-a-pem-key",
            ),
            instance=self.sap_config,
        )
        assert not form.is_valid()
        assert "decrypted_private_key" in form.errors

    def test_self_signed_auth_accepts_valid_private_key(self):
        form = SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(
            data=self._form_data(
                auth_type=SAPAuthType.SELF_SIGNED_ASSERTION,
                decrypted_private_key=generate_test_private_key_pem(),
            ),
            instance=self.sap_config,
        )
        assert form.is_valid(), form.errors

    def test_sap_signed_auth_does_not_require_private_key(self):
        form = SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(
            data=self._form_data(auth_type=SAPAuthType.SAP_SIGNED_ASSERTION),
            instance=self.sap_config,
        )
        assert form.is_valid(), form.errors

    def test_switching_to_self_signed_auth_does_not_crash_when_private_key_field_not_bound(self):
        """
        Reproduces a bug where the admin ``ModelAdmin.get_form()`` builds this form with a
        restricted field set (via ``get_fields()``), excluding ``decrypted_private_key`` for a
        config that was still SAP-signed when the page was rendered. Validating that field with
        ``self.add_error()`` in that situation used to raise ``ValueError`` ("has no field named
        ...") instead of a normal validation error, crashing the save with a 500 error the first
        time an admin switched a SAP-signed config to self-signed auth.
        """
        RestrictedForm = forms.modelform_factory(
            SAPSuccessFactorsEnterpriseCustomerConfiguration,
            form=SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm,
            fields=[
                "enterprise_customer", "auth_type", "sapsf_base_url", "sapsf_company_id",
                "sapsf_user_id", "user_type", "decrypted_key", "decrypted_secret",
            ],
        )
        form = RestrictedForm(
            data=self._form_data(auth_type=SAPAuthType.SELF_SIGNED_ASSERTION),
            instance=self.sap_config,
        )
        assert form.is_valid(), form.errors

    def test_stored_private_key_never_rendered_on_change_form(self):
        """
        Opening a change form for a config that already has a private key must not put that
        key's plaintext anywhere in the rendered HTML -- rendering the stored value defeats the
        write-only guarantee just as surely as returning it from the API would.
        """
        self.sap_config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION
        self.sap_config.decrypted_private_key = generate_test_private_key_pem()
        self.sap_config.save()

        form = SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(instance=self.sap_config)
        rendered = str(form)

        assert self.sap_config.decrypted_private_key not in rendered
        assert "BEGIN RSA PRIVATE KEY" not in rendered

    def test_rejected_submission_does_not_echo_private_key_back(self):
        """
        If a *different* field fails validation, Django re-renders this one bound to the
        submitted POST data. A plain Textarea would echo the newly typed private key straight
        back into the page HTML on that error page -- exactly as risky as exposing a stored one.
        """
        submitted_key = generate_test_private_key_pem()
        form = SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(
            data=self._form_data(
                auth_type=SAPAuthType.SELF_SIGNED_ASSERTION,
                decrypted_private_key=submitted_key,
                transmission_chunk_size="not-a-number",
            ),
            instance=self.sap_config,
        )
        assert not form.is_valid()
        assert "transmission_chunk_size" in form.errors
        rendered = str(form)

        assert submitted_key not in rendered
        assert "BEGIN RSA PRIVATE KEY" not in rendered

    def test_blank_private_key_submission_preserves_stored_value(self):
        """
        The field never displays the current value, so an admin can't tell what's stored and
        can't intentionally resubmit it. A blank submission must therefore mean "leave it as is",
        not "clear the key" -- otherwise every edit to an unrelated field risks silently wiping
        the customer's credentials.
        """
        stored_key = generate_test_private_key_pem()
        self.sap_config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION
        self.sap_config.decrypted_private_key = stored_key
        self.sap_config.save()

        form = SAPSuccessFactorsEnterpriseCustomerConfigurationAdminForm(
            data=self._form_data(
                auth_type=SAPAuthType.SELF_SIGNED_ASSERTION,
                decrypted_private_key="",
            ),
            instance=self.sap_config,
        )
        assert form.is_valid(), form.errors
        saved = form.save()
        assert saved.decrypted_private_key.strip() == stored_key.strip()
