from collections import namedtuple

from propelauth_py import TokenVerificationMetadata, init_base_auth

from propelauth_django_rest_framework.auth_helpers import _validate_user_wrapper, _validate_user_and_org_wrapper, \
    _is_authenticated_permission_wrapper, _is_user_in_org

Auth = namedtuple("Auth", [
    "IsUserAuthenticated", "AllowAny", "IsUserInOrg",
    "request_to_user", "request_to_user_or_none", "request_to_user_and_org",
    "fetch_user_metadata_by_user_id", "fetch_user_metadata_by_email", "fetch_user_metadata_by_username",
    "fetch_batch_user_metadata_by_user_ids",
    "fetch_batch_user_metadata_by_emails",
    "fetch_batch_user_metadata_by_usernames",
    "fetch_org", "fetch_org_by_query", "fetch_users_by_query", "fetch_users_in_org",
    "create_user",
    "update_user_email",
    "update_user_metadata",
    "create_magic_link", "migrate_user_from_external_source", "create_org", "add_user_to_org"
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
        create_magic_link=auth.create_magic_link,
        migrate_user_from_external_source=auth.migrate_user_from_external_source,
        create_org=auth.create_org,
        add_user_to_org=auth.add_user_to_org,
    )
