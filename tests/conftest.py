import django
import pytest
import requests_mock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from django.conf import settings
from django.http import HttpResponse
from collections import namedtuple

from propelauth_django_rest_framework import init_auth
from propelauth_py.api import BACKEND_API_BASE_URL as BASE_INTERNAL_API_URL
from propelauth_py.validation import _validate_and_extract_auth_hostname


# Need to configure settings before we import APIView
if not settings.configured:
    settings.configure(INSTALLED_APPS=[
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'rest_framework',
        "propelauth_django_rest_framework",
    ], DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    })
    django.setup()

from rest_framework.views import APIView

TestRsaKeys = namedtuple("TestRsaKeys", ["public_pem", "private_pem"])

BASE_AUTH_URL = "https://test.propelauth.com"
HTTP_BASE_AUTH_URL = "http://test.propelauth.com"


@pytest.fixture(scope='function')
def rsa_keys():
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return TestRsaKeys(public_pem=public_key_pem, private_pem=private_key_pem)


@pytest.fixture(scope='function')
def auth(rsa_keys):
    return mock_api_and_init_auth(BASE_AUTH_URL, 200, {
        "verifier_key_pem": rsa_keys.public_pem
    })


@pytest.fixture(scope='function')
def require_user_route(auth):
    class RequireUserView(APIView):
        permission_classes = [auth.IsUserAuthenticated]

        def get(self, request):
            return HttpResponse(request.propelauth_user.user_id)

    return RequireUserView.as_view()


@pytest.fixture(scope='function')
def optional_user_route(auth):
    class OptionalUserView(APIView):
        permission_classes = [auth.AllowAny]

        def get(self, request):
            if request.propelauth_user is None:
                return HttpResponse("none")
            return HttpResponse(request.propelauth_user.user_id)

    return OptionalUserView.as_view()


def mock_api_and_init_auth(auth_url, status_code, json):
    with requests_mock.Mocker() as m:
        api_key = "api_key"
        m.get(BASE_INTERNAL_API_URL + "/api/v1/token_verification_metadata",
              request_headers={
                  'Authorization': 'Bearer ' + api_key,
                  'X-Propelauth-url': _validate_and_extract_auth_hostname(auth_url)
              },
              json=json,
              status_code=status_code)
        return init_auth(auth_url, api_key)
