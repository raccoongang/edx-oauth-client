"""Tests for the custom OAuth pipeline security checks."""

from mock import Mock, patch

from django.test import SimpleTestCase
from third_party_auth.pipeline import AuthEntryError

from edx_oauth_client.backends.edx_oauth_client import DEFAULT_AUTH_PIPELINE
from edx_oauth_client.pipeline import (
    _validate_existing_oauth_links,
    prevent_authenticated_user_association,
)


class PreventAuthenticatedUserAssociationTests(SimpleTestCase):
    """Verify that an authenticated LMS session cannot acquire a new UID."""

    def setUp(self):
        super(PreventAuthenticatedUserAssociationTests, self).setUp()
        self.backend = Mock(name='backend')
        self.backend.name = 'edx-oauth2'
        self.pipeline_user = Mock(id=10)
        self.strategy = Mock(name='strategy')
        self.strategy.request.user = Mock(id=10)

    def test_rejects_new_association_for_authenticated_request(self):
        self.strategy.request.user.is_authenticated.return_value = True

        with self.assertRaises(AuthEntryError):
            prevent_authenticated_user_association(
                self.strategy,
                self.backend,
                user=self.pipeline_user,
                social=None,
            )

    def test_rejects_new_association_with_property_style_authentication(self):
        self.strategy.request.user.is_authenticated = True

        with self.assertRaises(AuthEntryError):
            prevent_authenticated_user_association(
                self.strategy,
                self.backend,
                user=self.pipeline_user,
                social=None,
            )

    def test_allows_anonymous_registration(self):
        self.strategy.request.user.is_authenticated.return_value = False

        prevent_authenticated_user_association(
            self.strategy,
            self.backend,
            user=self.pipeline_user,
            social=None,
        )

    def test_allows_existing_association(self):
        self.strategy.request.user.is_authenticated.return_value = True

        prevent_authenticated_user_association(
            self.strategy,
            self.backend,
            user=self.pipeline_user,
            social=Mock(name='social'),
        )

    def test_guard_runs_immediately_before_social_auth_association(self):
        guard = 'edx_oauth_client.pipeline.prevent_authenticated_user_association'
        associate = 'social.pipeline.social_auth.associate_user'

        self.assertEqual(DEFAULT_AUTH_PIPELINE.index(guard) + 1, DEFAULT_AUTH_PIPELINE.index(associate))


class ExistingOAuthLinksValidationTests(SimpleTestCase):
    """Verify that every conflicting UID is rejected, including damaged accounts."""

    def setUp(self):
        super(ExistingOAuthLinksValidationTests, self).setUp()
        self.user = Mock(id=10)

    @patch('edx_oauth_client.pipeline.UserSocialAuth.objects.filter')
    def test_rejects_conflict_when_incoming_uid_is_one_of_multiple_links(self, oauth_filter):
        oauth_filter.return_value.values_list.return_value = ['expected-uid', 'foreign-uid']

        with self.assertRaises(AuthEntryError):
            _validate_existing_oauth_links(self.user, 'edx-oauth2', 'expected-uid')

    @patch('edx_oauth_client.pipeline.UserSocialAuth.objects.filter')
    def test_allows_only_the_matching_uid(self, oauth_filter):
        oauth_filter.return_value.values_list.return_value = ['expected-uid']

        _validate_existing_oauth_links(self.user, 'edx-oauth2', 'expected-uid')

    @patch('edx_oauth_client.pipeline.UserSocialAuth.objects.filter')
    def test_allows_account_without_an_oauth_link(self, oauth_filter):
        oauth_filter.return_value.values_list.return_value = []

        _validate_existing_oauth_links(self.user, 'edx-oauth2', 'expected-uid')
