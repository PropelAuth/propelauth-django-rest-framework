from datetime import timedelta
from uuid import uuid4

from django.http import HttpResponse
from propelauth_py.user import UserRole
from rest_framework.views import APIView

from tests.auth_helpers import create_access_token, orgs_to_org_id_map, random_org, random_user_id
from tests.conftest import HTTP_BASE_AUTH_URL
from rest_framework.test import APIRequestFactory


def test_require_org_member_without_auth(auth, rsa_keys):
    org_id = str(uuid4())
    route = create_route_expecting_user_and_org(auth, None, None, None, lambda r: org_id)

    request = APIRequestFactory(GET_org_id=org_id).request()
    response = route(request)
    assert response.status_code == 401


def test_require_org_member_with_auth_but_no_org_membership(auth, rsa_keys):
    org_id = str(uuid4())
    route = create_route_expecting_user_and_org(auth, None, None, None, lambda r: org_id)

    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)

    request = APIRequestFactory(GET_org_id=org_id, HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = route(request)

    assert response.status_code == 403


def test_require_org_member_with_auth_and_org_member(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    route = create_route_expecting_user_and_org(auth, user_id, org, UserRole.Owner, lambda r: org["org_id"])

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = route(request)

    assert response.status_code == 200
    assert response.content.decode("utf-8") == "ok"


def test_require_org_member_with_auth_but_wrong_org_id(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    wrong_org_id = str(uuid4())

    # Pass wrong org_id in
    route = create_route_expecting_user_and_org(auth, user_id, org, UserRole.Owner, lambda r: wrong_org_id)

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = route(request)
    assert response.status_code == 403


def test_require_org_member_with_auth_but_no_permission(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Member")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    # Create a route where the min required role is Admin
    class RequireUserInOrgView(APIView):
        permission_classes = [auth.IsUserInOrg(req_to_org_id=lambda r: org["org_id"],
                                               minimum_required_role=UserRole.Admin)]

        def get(self, request):
            return HttpResponse("ok")

    route = RequireUserInOrgView.as_view()

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = route(request)
    assert response.status_code == 403


def test_require_org_member_with_auth_with_permission(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    # Create a route where the min required role is Admin
    class RequireUserInOrgView(APIView):
        permission_classes = [auth.IsUserInOrg(req_to_org_id=lambda r: org["org_id"],
                                               minimum_required_role=UserRole.Admin)]

        def get(self, request):
            assert request.propelauth_user.user_id == user_id
            assert request.propelauth_org.org_id == org["org_id"]
            assert request.propelauth_org.org_name == org["org_name"]
            assert request.propelauth_org.user_role == UserRole.Admin
            return HttpResponse("ok")

    route = RequireUserInOrgView.as_view()

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = route(request)
    assert response.content.decode("utf-8") == "ok"


def test_require_org_member_with_bad_header(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    route = create_route_expecting_user_and_org(auth, None, None, None, lambda r: org["org_id"])

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    request = APIRequestFactory(HTTP_AUTHORIZATION='token ' + access_token).request()
    response = route(request)
    assert response.status_code == 401


def test_require_org_member_with_wrong_token(auth, rsa_keys):
    org_id = str(uuid4())
    route = create_route_expecting_user_and_org(auth, None, None, None, lambda r: org_id)

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer whatisthis ').request()
    response = route(request)
    assert response.status_code == 401


def test_require_org_member_with_expired_token(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    route = create_route_expecting_user_and_org(auth, user_id, org, UserRole.Owner, lambda r: org["org_id"])

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem, expires_in=timedelta(minutes=-1))

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = route(request)
    assert response.status_code == 401


def test_require_user_with_bad_issuer(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    route = create_route_expecting_user_and_org(auth, user_id, org, UserRole.Owner, lambda r: org["org_id"])

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)

    request = APIRequestFactory(HTTP_AUTHORIZATION='Bearer ' + access_token).request()
    response = route(request)
    assert response.status_code == 401


def create_route_expecting_user_and_org(auth, user_id, org, user_role, req_to_org_id):
    class RequireUserInOrgView(APIView):
        permission_classes = [auth.IsUserInOrg(req_to_org_id=req_to_org_id)]

        def get(self, request):
            assert request.propelauth_user.user_id == user_id
            assert request.propelauth_org.org_id == org["org_id"]
            assert request.propelauth_org.org_name == org["org_name"]
            assert request.propelauth_org.user_role == user_role
            return HttpResponse("ok")

    return RequireUserInOrgView.as_view()


