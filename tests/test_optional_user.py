from datetime import timedelta

from tests.auth_helpers import create_access_token, random_user_id
from tests.conftest import HTTP_BASE_AUTH_URL
from rest_framework.test import APIRequestFactory


def test_optional_user_without_auth(optional_user_route, rsa_keys):
    request = APIRequestFactory().request()
    response = optional_user_route(request)
    assert response.status_code == 200
    assert response.content.decode("utf-8") == "none"


def test_optional_user_with_auth(optional_user_route, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = optional_user_route(request)

    assert response.status_code == 200
    assert response.content.decode("utf-8") == user_id


def test_optional_user_with_bad_header(optional_user_route, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)

    request = APIRequestFactory(HTTP_AUTHORIZATION='token ' + access_token).request()
    response = optional_user_route(request)

    assert response.status_code == 200
    assert response.content.decode("utf-8") == "none"


def test_optional_user_with_wrong_token(optional_user_route, rsa_keys):
    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer whatisthis').request()
    response = optional_user_route(request)
    assert response.status_code == 200
    assert response.content.decode("utf-8") == "none"


def test_optional_user_with_expired_token(optional_user_route, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem, expires_in=timedelta(minutes=-1))

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = optional_user_route(request)

    assert response.status_code == 200
    assert response.content.decode("utf-8") == "none"


def test_optional_user_with_bad_issuer(optional_user_route, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = optional_user_route(request)

    assert response.status_code == 200
    assert response.content.decode("utf-8") == "none"
