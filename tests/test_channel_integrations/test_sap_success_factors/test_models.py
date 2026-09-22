"""
Tests for the `channel_integrations.sap_success_factors.models` models module.
"""

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.db import connection
from pytest import mark

from channel_integrations.sap_success_factors.models import (
    SAPAuthType,
    SAPSuccessFactorsEnterpriseCustomerConfiguration,
)
from test_utils.factories import EnterpriseCustomerFactory, SAPSuccessFactorsGlobalConfigurationFactory

MALFORMED_PRIVATE_KEY = (
    '-----BEGIN PRIVATE KEY-----\n'
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDfakeKeyMaterial\n'
    '-----END PRIVATE KEY-----\n'
)


def _generate_private_key():
    """
    Build a throwaway RSA key, so validation runs against real key material rather than a stub.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode('utf-8')


PRIVATE_KEY = _generate_private_key()

PASSPHRASE = 'correct-horse'


def _generate_passphrase_protected_private_key(passphrase):
    """
    Build a throwaway RSA key encrypted under ``passphrase``, as SAP's key export would be.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode('utf-8')),
    ).decode('utf-8')


PASSPHRASE_PROTECTED_PRIVATE_KEY = _generate_passphrase_protected_private_key(PASSPHRASE)


@mark.django_db
class TestSAPSuccessFactorsEnterpriseCustomerConfiguration(unittest.TestCase):
    """
    Tests of the ``SAPSuccessFactorsEnterpriseCustomerConfiguration`` model.
    """

    def setUp(self):
        self.enterprise_customer = EnterpriseCustomerFactory()
        self.config = SAPSuccessFactorsEnterpriseCustomerConfiguration(
            enterprise_customer=self.enterprise_customer,
            active=True,
            sapsf_base_url='https://sap.example.com',
            sapsf_company_id='COMP1',
            sapsf_user_id='user-1',
            decrypted_key='a-key',
            decrypted_secret='a-secret',
        )
        self.config.save()
        super().setUp()

    def test_auth_type_defaults_to_sap_signed_assertion(self):
        """
        A freshly created configuration keeps asking SAP's OAuth IdP API to mint the assertion.
        """
        assert self.config.auth_type == SAPAuthType.SAP_SIGNED_ASSERTION
        assert self.config.uses_self_signed_assertion is False

    def test_uses_self_signed_assertion(self):
        """
        ``uses_self_signed_assertion`` follows the configured auth type.
        """
        self.config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION
        assert self.config.uses_self_signed_assertion is True

    def test_saml_assertion_audience_default(self):
        """
        The SAML assertion audience defaults to SAP's standard audience and is overridable per customer.
        """
        assert self.config.saml_assertion_audience == 'www.successfactors.com'

        self.config.saml_assertion_audience = 'tenant.successfactors.eu'
        self.config.save()
        self.config.refresh_from_db()

        assert self.config.saml_assertion_audience == 'tenant.successfactors.eu'

    def test_global_endpoint_path_defaults(self):
        """
        The SAML assertion / OAuth token endpoint paths are global, defaulting to SAP's standard paths.
        """
        global_config = SAPSuccessFactorsGlobalConfigurationFactory()
        assert global_config.saml_assertion_api_path == '/oauth/idp'
        assert global_config.oauth_token_api_path == '/oauth/token'

        global_config.saml_assertion_api_path = '/global/assertion'
        global_config.oauth_token_api_path = '/global/token'
        global_config.save()
        global_config.refresh_from_db()

        assert global_config.saml_assertion_api_path == '/global/assertion'
        assert global_config.oauth_token_api_path == '/global/token'

    def test_encrypted_private_key(self):
        """
        Test the encrypted_private_key property getter and setter.
        """
        assert self.config.encrypted_private_key == ''

        self.config.decrypted_private_key = PRIVATE_KEY
        encrypted_value = self.config.encrypted_private_key
        assert encrypted_value != PRIVATE_KEY
        assert isinstance(encrypted_value, str)

        self.config.encrypted_private_key = encrypted_value
        assert self.config.decrypted_private_key == encrypted_value

    def test_private_key_is_encrypted_at_rest(self):
        """
        The private key is stored encrypted in the database but reads back as plaintext through the ORM.
        """
        self.config.decrypted_private_key = PRIVATE_KEY
        self.config.save()

        table = SAPSuccessFactorsEnterpriseCustomerConfiguration._meta.db_table
        with connection.cursor() as cursor:
            cursor.execute(
                f'SELECT decrypted_private_key FROM {table} WHERE id = %s',
                [self.config.id],
            )
            stored_value = cursor.fetchone()[0]

        assert stored_value
        assert PRIVATE_KEY not in str(stored_value)

        self.config.refresh_from_db()
        assert self.config.decrypted_private_key == PRIVATE_KEY

    def _switch_to_self_signed_assertion(self):
        """
        Put the configuration into self-signed mode with the credentials that mode requires.
        """
        self.config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION
        self.config.decrypted_private_key = PRIVATE_KEY

    def test_is_valid_sap_signed_requires_client_secret(self):
        """
        A SAP-signed configuration still has to carry a Client Secret.
        """
        missing, _ = self.config.is_valid
        assert not missing['missing']

        self.config.decrypted_secret = ''
        missing, _ = self.config.is_valid
        assert 'secret' in missing['missing']

    def test_is_valid_sap_signed_does_not_require_private_key(self):
        """
        A SAP-signed configuration is complete without any SAML bearer credentials.
        """
        self.config.decrypted_private_key = ''
        self.config.saml_assertion_audience = ''

        missing, incorrect = self.config.is_valid
        assert 'private_key' not in missing['missing']
        assert 'saml_assertion_audience' not in missing['missing']
        assert 'private_key' not in incorrect['incorrect']

    def test_is_valid_self_signed_requires_private_key(self):
        """
        A self-signed configuration reports the private key as missing until one is stored.
        """
        self.config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION

        missing, _ = self.config.is_valid
        assert 'private_key' in missing['missing']

        self.config.decrypted_private_key = PRIVATE_KEY
        missing, _ = self.config.is_valid
        assert 'private_key' not in missing['missing']

    def test_is_valid_self_signed_does_not_require_client_secret(self):
        """
        A migrated customer authenticates with a signed assertion, so a Client Secret is not required.

        Reporting the secret as missing here would mark every migrated customer as INVALID_CONFIG on
        the health check even though their syncs succeed.
        """
        self._switch_to_self_signed_assertion()
        self.config.decrypted_secret = ''

        missing, incorrect = self.config.is_valid
        assert not missing['missing']
        assert not incorrect['incorrect']

    def test_is_valid_self_signed_requires_assertion_audience(self):
        """
        SAP rejects an assertion with an audience it does not recognise, so it must be configured.
        """
        self._switch_to_self_signed_assertion()
        self.config.saml_assertion_audience = ''

        missing, _ = self.config.is_valid
        assert 'saml_assertion_audience' in missing['missing']

    def test_is_valid_self_signed_requires_token_path(self):
        """
        The signed assertion has nowhere to go without a (global) token endpoint path.
        """
        self._switch_to_self_signed_assertion()
        SAPSuccessFactorsGlobalConfigurationFactory(oauth_token_api_path='')

        missing, _ = self.config.is_valid
        assert 'oauth_token_api_path' in missing['missing']

    def test_is_valid_self_signed_requires_company_and_user_identifiers(self):
        """
        The assertion identifies the learner to SAP by company and user, so both must be set.
        """
        self._switch_to_self_signed_assertion()
        self.config.sapsf_company_id = ''
        self.config.sapsf_user_id = ''

        missing, _ = self.config.is_valid
        assert 'sapsf_company_id' in missing['missing']
        assert 'sapsf_user_id' in missing['missing']

    def test_is_valid_reports_malformed_private_key_as_incorrect(self):
        """
        A key that cannot be parsed is a configuration error, not a missing value.

        It is reported separately from a missing key so an operator can tell "paste a key" apart from
        "the key you pasted is truncated".
        """
        self.config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION
        self.config.decrypted_private_key = MALFORMED_PRIVATE_KEY

        missing, incorrect = self.config.is_valid
        assert 'private_key' not in missing['missing']
        assert 'private_key' in incorrect['incorrect']

    def test_is_valid_accepts_a_passphrase_protected_private_key(self):
        """
        A passphrase-protected key is validated against its stored passphrase.

        The key cannot be parsed without it, so ignoring the passphrase would report a correctly
        configured customer as having a malformed key.
        """
        self.config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION
        self.config.decrypted_private_key = PASSPHRASE_PROTECTED_PRIVATE_KEY
        self.config.decrypted_private_key_passphrase = PASSPHRASE

        missing, incorrect = self.config.is_valid
        assert 'private_key' not in missing['missing']
        assert 'private_key' not in incorrect['incorrect']

    def test_is_valid_reports_passphrase_protected_key_without_passphrase_as_incorrect(self):
        """
        An encrypted key whose passphrase was never configured cannot sign, so it is a config error.
        """
        self.config.auth_type = SAPAuthType.SELF_SIGNED_ASSERTION
        self.config.decrypted_private_key = PASSPHRASE_PROTECTED_PRIVATE_KEY

        missing, incorrect = self.config.is_valid
        assert 'private_key' not in missing['missing']
        assert 'private_key' in incorrect['incorrect']

    def test_is_valid_does_not_require_key_and_secret_for_self_signed_assertion(self):
        """
        Neither OAuth client credential is reported as missing for a self-signed assertion.

        This pins current behaviour rather than endorsing it. Dropping the Client Secret is
        clearly right: SAP's IdP API is what authenticated with it, and self-signing replaces
        that call. The Client ID is less clear-cut -- it is the assertion's ``Issuer`` and is
        sent with the token request -- so a self-signed config almost certainly still needs one.
        That check lives in ENT-12301; see the note on that PR before relying on this.
        """
        self._switch_to_self_signed_assertion()
        self.config.decrypted_key = ''
        self.config.decrypted_secret = ''

        missing, _ = self.config.is_valid
        assert 'key' not in missing['missing']
        assert 'secret' not in missing['missing']
        assert not missing['missing']

    def test_is_valid_requires_key_and_secret_for_sap_signed_assertion(self):
        """
        A SAP-signed assertion still authenticates with the OAuth client credentials, so both stay
        mandatory.
        """
        assert self.config.auth_type == SAPAuthType.SAP_SIGNED_ASSERTION
        self.config.decrypted_key = ''
        self.config.decrypted_secret = ''

        missing, _ = self.config.is_valid
        assert 'key' in missing['missing']
        assert 'secret' in missing['missing']
        # The self-signed-only fields must not leak into a SAP-signed config's requirements.
        assert 'private_key' not in missing['missing']
        assert 'saml_assertion_audience' not in missing['missing']

    def test_encrypted_private_key_passphrase(self):
        """
        Test the encrypted_private_key_passphrase property getter and setter.
        """
        assert self.config.encrypted_private_key_passphrase == ''

        self.config.decrypted_private_key_passphrase = 'a-passphrase'
        encrypted_value = self.config.encrypted_private_key_passphrase
        assert encrypted_value != 'a-passphrase'
        assert isinstance(encrypted_value, str)

        self.config.encrypted_private_key_passphrase = encrypted_value
        assert self.config.decrypted_private_key_passphrase == encrypted_value
