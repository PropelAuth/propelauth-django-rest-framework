from propelauth_py import UnauthorizedException
from propelauth_py.errors import UnexpectedException, ForbiddenException
from rest_framework import permissions
from rest_framework.exceptions import APIException


def _is_authenticated_permission_wrapper(validate_access_token_and_get_user, require_user, debug_mode):
    validate_user = _validate_user_wrapper(validate_access_token_and_get_user, require_user, debug_mode)

    class IsUserAuthenticated(permissions.BasePermission):
        def has_permission(self, request, view):
            request.propelauth_user = validate_user(request)

            # We can return true because validate_user will raise a 401 if require_user is true
            return True

    return IsUserAuthenticated


def _is_user_in_org(validate_access_token_and_get_user_with_org, debug_mode):
    validate_user_and_org = _validate_user_and_org_wrapper(validate_access_token_and_get_user_with_org, debug_mode)

    def is_user_in_org_wrapper(req_to_org_id=_default_req_to_org_id, minimum_required_role=None):
        class IsUserInOrg(permissions.BasePermission):

            def has_permission(self, request, view):
                required_org_id = req_to_org_id(request)
                user_and_org = validate_user_and_org(request, required_org_id, minimum_required_role)

                request.propelauth_user = user_and_org.user
                request.propelauth_org = user_and_org.org_member_info

                # We can return true because validate_user_and_org will raise a 401/403 if they don't have permission
                return True

        return IsUserInOrg

    return is_user_in_org_wrapper


def _validate_user_wrapper(validate_access_token_and_get_user, require_user, debug_mode):
    def validate_user(request):
        try:
            authorization_header = request.headers.get("Authorization")
            return validate_access_token_and_get_user(authorization_header)
        except UnauthorizedException as e:
            _handle_unauthorized_exception(e, require_user, debug_mode)
            return None

    return validate_user


def _validate_user_and_org_wrapper(validate_access_token_and_get_user_with_org, debug_mode):
    def validate_user_and_org(request, required_org_id, minimum_required_role=None):
        try:
            authorization_header = request.headers.get("Authorization")
            return validate_access_token_and_get_user_with_org(authorization_header, required_org_id,
                                                               minimum_required_role)
        except UnauthorizedException as e:
            _handle_unauthorized_exception(e, True, debug_mode)

        except UnexpectedException as e:
            _handle_unexpected_exception(e, debug_mode)

        except ForbiddenException as e:
            _handle_forbidden_exception(e, debug_mode)

    return validate_user_and_org


class Http401(APIException):
    status_code = 401


class Http403(APIException):
    status_code = 403


class Http500(APIException):
    status_code = 500


def _handle_unauthorized_exception(e, require_user, debug_mode):
    if require_user and debug_mode:
        raise Http401(detail=e.message)
    elif require_user:
        raise Http401()


def _handle_forbidden_exception(e, debug_mode):
    if debug_mode:
        raise Http403(detail=e.message)
    raise Http403()


def _handle_unexpected_exception(e, debug_mode):
    if debug_mode:
        raise Http500(detail=e.message)
    raise Http500()


def _default_req_to_org_id(request):
    return request.GET.get('org_id', '')
