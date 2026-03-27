"""
edx-oauth-client custom pipelines.
"""

import logging
import json

from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.urls import reverse
from edxmako.shortcuts import render_to_response
from social_core.pipeline import partial
from social_django.models import UserSocialAuth
from third_party_auth.pipeline import AuthEntryError, is_api, get_complete_url

from openedx.core.djangoapps.dark_lang import DARK_LANGUAGE_KEY
from openedx.core.djangoapps.user_authn import cookies as user_authn_cookies
from openedx.core.djangoapps.user_authn.views.registration_form import AccountCreationForm
from openedx.core.djangoapps.user_authn.utils import generate_password
from openedx.core.djangoapps.user_api.preferences.api import set_user_preference
from student.helpers import do_create_account


log = logging.getLogger(__name__)


@partial.partial
def ensure_user_information(
        strategy, auth_entry, backend=None, user=None, social=None, allow_inactive_user=False, *args, **kwargs
):
    """
    Ensure that we have the necessary information about a user to proceed with the pipeline.

    Either an existing account or registration data.
    """

    data = {}
    try:
        if 'data' in kwargs['response']:
            user_data = kwargs['response']['data'][0]
        else:
            user_data = kwargs['response']
        log.info('Get user data')

        data['access_token'] = kwargs['response']['access_token']

        data['country'] = user_data.get('country', 'UA')

        for key, value in backend.setting('USER_DATA_KEY_VALUES').items():
            data[key] = user_data.get(value)

        data['email'] = strategy.session_get('email', "")
        data['username'] = data['email']

        if not data['name']:
            data['name'] = ' '.join(
                [user_data.get('lastname', ''), user_data.get('givenname', ''), user_data.get('middlename', '')]
            )

        if kwargs.get('is_new') and not all((data['username'], data['email'])):
            raise AuthEntryError(
                backend,
                "One of the required parameters (username or email) is not received with the user data."
            )
    except AuthEntryError as e:
        log.exception(e)
        raise
    except Exception as e:
        log.exception(e)
        raise AuthEntryError(backend, "Cannot receive user's data")

    if not user:
        data['terms_of_service'] = 'True'
        data['honor_code'] = 'True'
        data['password'] = generate_password()
        data['provider'] = backend.name

        input_drfocode = str(user_data.get('drfocode') or '').strip()
        if not input_drfocode:
            raise AuthEntryError(backend, 'DRFO code is not received from the provider.')

        try:
            user = User.objects.get(profile__meta__contains='"drfcode": "{}"'.format(input_drfocode))
        except User.DoesNotExist:
            form = AccountCreationForm(
                data=data,
                extra_fields={},
                extended_profile_fields={},
                tos_required=False,
            )

            (user, profile, registration) = do_create_account(form)
            user.is_active = True
            user.first_name = user_data.get('givenname')
            user.last_name = user_data.get('lastname')
            user.set_unusable_password()
            user.profile.second_name = user_data.get('middlename')
            user.profile.meta = json.dumps({"drfcode": input_drfocode})
            user.profile.save()
            user.save()

            set_user_preference(user, DARK_LANGUAGE_KEY, 'uk')

        else:
            existing_drfocode = _get_profile_drfocode(user)
            if existing_drfocode != input_drfocode:
                log.error(
                    'Profile DRFO mismatch for user_id=%s existing_drfocode=%s input_drfocode=%s',
                    user.id, existing_drfocode, input_drfocode
                )
                raise AuthEntryError(
                    backend,
                    'This identity conflicts with an existing account. Please contact support.'
                )

            _validate_existing_oauth_links(user, backend.name, input_drfocode)

    return {'user': user}


def _get_profile_drfocode(user) -> str:
    """
    Return DRFO code from user profile.meta.

    :param user: User instance
    :return: DRFO code or empty string
    """
    raw_meta = getattr(user.profile, 'meta', '') or ''
    try:
        meta = json.loads(raw_meta)
    except (TypeError, ValueError):
        log.warning('Invalid profile.meta for user_id=%s', user.id)
        return ''

    return str(meta.get('drfcode') or '').strip()


def _validate_existing_oauth_links(user: User, provider: str, drfocode: str) -> None:
    """
    Validate existing social auth links for provider and DRFO code.

    :param user: User instance
    :param provider: OAuth provider name
    :param drfocode: Input DRFO code
    :raise AuthEntryError: If provider UID conflicts with account
    """
    existing_uids = set(
        str(uid) for uid in UserSocialAuth.objects.filter(
            user=user,
            provider=provider,
        ).values_list('uid', flat=True)
    )

    if existing_uids and drfocode not in existing_uids:
        log.error(
            'OAuth UID conflict for user_id=%s provider=%s existing_uids=%s input_uid=%s',
            user.id, provider, sorted(existing_uids), drfocode
        )
        raise AuthEntryError(
            None,
            'This identity conflicts with an existing account. Please contact support.'
        )


@partial.partial
def fill_in_email(
        strategy, auth_entry, backend=None, user=None, social=None, allow_inactive_user=False, *args, **kwargs
):
    """
    Additional pipeline for checking user email from the provider on registration step.

    Checks if email is received from the provider and render the email form to the user if it is not.
    After successful adding the email, registration process continues.
    """
    if kwargs.get('is_new'):
        request = kwargs.get('request')
        email = strategy.request_data().get('email', strategy.session_get('email', None))

        if not email:
            return render_to_response(
                'register_email_form.html',
                {
                    'path': request.path,
                    'state': request.GET.get('state'),
                    'code': request.GET.get('code'),
                    'partial_token': kwargs.get('current_partial').token,
                }
            )
        else:
            if request.method == 'POST':
                request.session['email'] = email
                partial_token = request.POST.get('partial_token')
                partial = strategy.partial_load(partial_token)
                return {'partial_backend_name': partial.backend, 'partial_token': partial_token}
