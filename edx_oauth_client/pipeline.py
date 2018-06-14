from logging import getLogger

from django.contrib.auth.models import User
from django.http import HttpResponseBadRequest
from social_core.pipeline.partial import partial
from student.models import UserProfile
from student.views import create_account_with_params, reactivation_email_for_user
from third_party_auth.pipeline import (AuthEntryError, make_random_password)

log = getLogger(__name__)

# The following are various possible values for the AUTH_ENTRY_KEY.
AUTH_ENTRY_LOGIN = 'login'
AUTH_ENTRY_REGISTER = 'register'
AUTH_ENTRY_ACCOUNT_SETTINGS = 'account_settings'

AUTH_ENTRY_LOGIN_2 = 'account_login'
AUTH_ENTRY_REGISTER_2 = 'account_register'

# Entry modes into the authentication process by a remote API call (as opposed to a browser session).
AUTH_ENTRY_LOGIN_API = 'login_api'
AUTH_ENTRY_REGISTER_API = 'register_api'


@partial.partial
def ensure_user_information(
        strategy, auth_entry, backend=None, user=None, social=None, allow_inactive_user=False, *args, **kwargs
):
    """
    Ensure that we have the necessary information about a user to proceed with the pipeline.

    Either an existing account or registration data.
    """

    response = {}
    data = {}
    try:
        if 'data' in kwargs['response']:
            user_data = kwargs['response']['data'][0]
        else:
            user_data = kwargs['response']
        log.info('Get user data: %s', str(user_data))
        access_token = kwargs['response']['access_token']

        country = user_data.get('country')
        if not country:
            log.info('No country in response.')

        # Received fields could be pretty different from the expected, mandatory are only 'username' and 'email'
        data['username'] = user_data.get('username', user_data.get('name'))
        data['first_name'] = user_data.get('firstName', user_data.get('first_name'))
        data['last_name'] = user_data.get('lastName', user_data.get('last_name'))
        data['email'] = user_data.get('email')
        data['country'] = country
        data['access_token'] = access_token
        if any((data['first_name'], data['last_name'])):
            data['name'] = '{} {}'.format(['first_name'], data['last_name']).strip()
        else:
            data['name'] = user_data.get('username')
        if not all((data['username'], data['email'])):
            raise AuthEntryError(
                backend,
                "One of the required parameters (username or email) is not received with the user data."
            )
    except Exception as e:
        log.exception(e)
        raise

    def dispatch_to_register():
        """
        Force user creation on login or register.
        """

        request = strategy.request
        data['terms_of_service'] = "True"
        data['honor_code'] = 'True'
        data['password'] = make_random_password()

        data['provider'] = backend.name

        if request.session.get('ExternalAuthMap'):
            del request.session['ExternalAuthMap']

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            create_account_with_params(request, data)
            user = request.user
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.is_active = True
            user.save()
        return {'user': user}

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
            response = dispatch_to_register()
        elif auth_entry in [AUTH_ENTRY_REGISTER, AUTH_ENTRY_REGISTER_2]:
            response = dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(backend, 'auth_entry is wrong. Settings requires a user.')
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')
    else:
        if user.id != 1:
            user.email = data['email']
            user.username = data['username']
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.save()

        try:
            user_profile = UserProfile.objects.get(user=user)
        except User.DoesNotExist:
            user_profile = None
        except User.MultipleObjectsReturned:
            user_profile = UserProfile.objects.filter(user=user).first()

        if user_profile:
            user_profile.name = user.get_full_name()
            user_profile.save()

    user = user or response.get('user')
    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            reactivation_email_for_user(user)
            raise AuthEntryError(backend, user.email)

    return {'user': user}
