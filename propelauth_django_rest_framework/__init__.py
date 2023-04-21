from collections import namedtuple

from propelauth_py import TokenVerificationMetadata, init_base_auth

from propelauth_django_rest_framework.auth_helpers import _validate_user_wrapper, _validate_user_and_org_wrapper, \
    _is_authenticated_permission_wrapper, _is_user_in_org, _is_user_in_org_with_minimum_role, \
    _is_user_in_org_with_exact_role, _is_user_in_org_with_permission, _is_user_in_org_with_all_permissions

Auth = namedtuple("Auth", [
    "IsUserAuthenticated", "AllowAny",
    "IsUserInOrg",
    "IsUserInOrgWithMinimumRole",
    "IsUserInOrgWithRole",
    "IsUserInOrgWithPermission",
    "IsUserInOrgWithAllPermissions",
    "request_to_user", "request_to_user_or_none", "request_to_user_and_org",
    "fetch_user_metadata_by_user_id", "fetch_user_metadata_by_email", "fetch_user_metadata_by_username",
    "fetch_batch_user_metadata_by_user_ids",
    "fetch_batch_user_metadata_by_emails",
    "fetch_batch_user_metadata_by_usernames",
    "fetch_org", "fetch_org_by_query", "fetch_users_by_query", "fetch_users_in_org",
    "create_user",
    "update_user_email",
    "update_user_metadata",
    "update_user_password",
    "create_magic_link", "create_access_token",
    "migrate_user_from_external_source", "create_org", "add_user_to_org",
    "update_org_metadata",
    "delete_user", "disable_user", "enable_user",
    "allow_org_to_setup_saml_connection", "disallow_org_to_setup_saml_connection"
])


def init_auth(auth_url: str, api_key: str, token_verification_metadata: TokenVerificationMetadata = None,
              debug_mode=False):
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""

    auth = init_base_auth(auth_url, api_key, token_verification_metadata)
    return Auth(
        IsUserAuthenticated=_is_authenticated_permission_wrapper(auth.validate_access_token_and_get_user, True,
                                                                 debug_mode),
        AllowAny=_is_authenticated_permission_wrapper(auth.validate_access_token_and_get_user, False, debug_mode),
        IsUserInOrg=_is_user_in_org(auth.validate_access_token_and_get_user_with_org, debug_mode),
        IsUserInOrgWithMinimumRole=_is_user_in_org_with_minimum_role(
            auth.validate_access_token_and_get_user_with_org_by_minimum_role,
            debug_mode),
        IsUserInOrgWithRole=_is_user_in_org_with_exact_role(
            auth.validate_access_token_and_get_user_with_org_by_exact_role, debug_mode),
        IsUserInOrgWithPermission=_is_user_in_org_with_permission(
            auth.validate_access_token_and_get_user_with_org_by_permission,
            debug_mode),
        IsUserInOrgWithAllPermissions=_is_user_in_org_with_all_permissions(
            auth.validate_access_token_and_get_user_with_org_by_all_permissions, debug_mode),
        request_to_user=_validate_user_wrapper(auth.validate_access_token_and_get_user, True, debug_mode),
        request_to_user_or_none=_validate_user_wrapper(auth.validate_access_token_and_get_user, False, debug_mode),
        request_to_user_and_org=_validate_user_and_org_wrapper(auth.validate_access_token_and_get_user_with_org,
                                                               debug_mode),
        fetch_user_metadata_by_user_id=auth.fetch_user_metadata_by_user_id,
        fetch_user_metadata_by_email=auth.fetch_user_metadata_by_email,
        fetch_user_metadata_by_username=auth.fetch_user_metadata_by_username,
        fetch_batch_user_metadata_by_user_ids=auth.fetch_batch_user_metadata_by_user_ids,
        fetch_batch_user_metadata_by_emails=auth.fetch_batch_user_metadata_by_emails,
        fetch_batch_user_metadata_by_usernames=auth.fetch_batch_user_metadata_by_usernames,
        fetch_org=auth.fetch_org,
        fetch_org_by_query=auth.fetch_org_by_query,
        fetch_users_by_query=auth.fetch_users_by_query,
        fetch_users_in_org=auth.fetch_users_in_org,
        create_user=auth.create_user,
        update_user_email=auth.update_user_email,
        update_user_metadata=auth.update_user_metadata,
        update_user_password=auth.update_user_password,
        create_magic_link=auth.create_magic_link,
        create_access_token=auth.create_access_token,
        migrate_user_from_external_source=auth.migrate_user_from_external_source,
        create_org=auth.create_org,
        add_user_to_org=auth.add_user_to_org,
        update_org_metadata=auth.update_org_metadata,
        enable_user=auth.enable_user,
        disable_user=auth.disable_user,
        delete_user=auth.delete_user,
        allow_org_to_setup_saml_connection=auth.allow_org_to_setup_saml_connection,
        disallow_org_to_setup_saml_connection=auth.disallow_org_to_setup_saml_connection,
    )
