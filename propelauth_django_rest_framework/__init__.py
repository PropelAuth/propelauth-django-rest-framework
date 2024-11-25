from typing import Any, Dict, Optional, List
from propelauth_py import TokenVerificationMetadata, init_base_auth, SamlIdpMetadata
from propelauth_py.api import (
    OrgQueryOrderBy,
    UserQueryOrderBy,
)
from propelauth_py.user import User
from propelauth_django_rest_framework.auth_helpers import (
    _validate_user_wrapper,
    _validate_user_and_org_wrapper,
    _is_authenticated_permission_wrapper,
    _is_user_in_org,
    _is_user_in_org_with_minimum_role,
    _is_user_in_org_with_exact_role,
    _is_user_in_org_with_permission,
    _is_user_in_org_with_all_permissions,
)
from rest_framework.request import Request

class RequiredRequest(Request):
    propelauth_user: User

class OptionalRequest(Request):
    propelauth_user: Optional[User] = None

class DjangoAuth:
    def __init__(self, auth_url: str, integration_api_key: str, token_verification_metadata: Optional[TokenVerificationMetadata], debug_mode: bool):
        self.auth_url = auth_url
        self.integration_api_key = integration_api_key
        self.token_verification_metadata = token_verification_metadata
        self.debug_mode = debug_mode
        self.auth = init_base_auth(auth_url, integration_api_key, token_verification_metadata)
    
    @property    
    def IsUserAuthenticated(self):
        return _is_authenticated_permission_wrapper(self.auth.validate_access_token_and_get_user, True, self.debug_mode)
    
    @property
    def AllowAny(self):
        return _is_authenticated_permission_wrapper(self.auth.validate_access_token_and_get_user, False, self.debug_mode)
    
    @property
    def IsUserInOrg(self):
        return _is_user_in_org(self.auth.validate_access_token_and_get_user_with_org, self.debug_mode)
    
    @property
    def IsUserInOrgWithMinimumRole(self):
        return _is_user_in_org_with_minimum_role(self.auth.validate_access_token_and_get_user_with_org_by_minimum_role, self.debug_mode)
    
    @property
    def IsUserInOrgWithRole(self):
        return _is_user_in_org_with_exact_role(self.auth.validate_access_token_and_get_user_with_org_by_exact_role, self.debug_mode)
    
    @property
    def IsUserInOrgWithPermission(self):
        return _is_user_in_org_with_permission(self.auth.validate_access_token_and_get_user_with_org_by_permission, self.debug_mode)
    
    @property
    def IsUserInOrgWithAllPermissions(self):
        return _is_user_in_org_with_all_permissions(self.auth.validate_access_token_and_get_user_with_org_by_all_permissions, self.debug_mode)
    
    def request_to_user(self):
        return _validate_user_wrapper(self.auth.validate_access_token_and_get_user, True, self.debug_mode)
    
    def request_to_user_or_none(self):
        return _validate_user_wrapper(self.auth.validate_access_token_and_get_user, False, self.debug_mode)
    
    def request_to_user_and_org(self):
        return _validate_user_and_org_wrapper(self.auth.validate_access_token_and_get_user_with_org, self.debug_mode)
    
    def validate_access_token_and_get_user(self, authorization_header: str) -> User:
        return self.auth.validate_access_token_and_get_user(authorization_header=authorization_header)
        
    def fetch_user_metadata_by_user_id(self, user_id: str, include_orgs: bool = False):
        return self.auth.fetch_user_metadata_by_user_id(user_id, include_orgs)
    
    def fetch_user_metadata_by_email(self, email: str, include_orgs: bool = False):
        return self.auth.fetch_user_metadata_by_email(email, include_orgs)

    def fetch_user_metadata_by_username(self, username: str, include_orgs: bool = False):
        return self.auth.fetch_user_metadata_by_username(username, include_orgs)

    def fetch_user_signup_query_params_by_user_id(self, user_id: str):
        return self.auth.fetch_user_signup_query_params_by_user_id(user_id)

    def fetch_batch_user_metadata_by_user_ids(self, user_ids: List[str], include_orgs: bool = False):
        return self.auth.fetch_batch_user_metadata_by_user_ids(user_ids, include_orgs)

    def fetch_batch_user_metadata_by_emails(self, emails: List[str], include_orgs: bool = False):
        return self.auth.fetch_batch_user_metadata_by_emails(emails, include_orgs)

    def fetch_batch_user_metadata_by_usernames(self, usernames: List[str], include_orgs: bool = False):
        return self.auth.fetch_batch_user_metadata_by_usernames(usernames, include_orgs)

    def fetch_org(self, org_id: str):
        return self.auth.fetch_org(org_id)

    def fetch_org_by_query(
        self, page_size: int = 10, page_number: int = 0, order_by: OrgQueryOrderBy = OrgQueryOrderBy.CREATED_AT_ASC, 
        name: Optional[str] = None, legacy_org_id: Optional[str] = None, domain: Optional[str] = None
    ):
        return self.auth.fetch_org_by_query(page_size, page_number, order_by, name, legacy_org_id, domain)

    def fetch_custom_role_mappings(self):
        return self.auth.fetch_custom_role_mappings()

    def fetch_pending_invites(self, page_number: int = 0, page_size: int = 10, org_id: Optional[str] = None):
        return self.auth.fetch_pending_invites(page_number, page_size, org_id)

    def fetch_users_by_query(
        self, page_size: int = 10, page_number: int = 0, order_by: UserQueryOrderBy = UserQueryOrderBy.CREATED_AT_ASC,
        email_or_username: Optional[str] = None, include_orgs: bool = False, legacy_user_id: Optional[str] = None
    ):
        return self.auth.fetch_users_by_query(page_size, page_number, order_by, email_or_username, include_orgs, legacy_user_id)

    def fetch_users_in_org(
        self, org_id: str, page_size: int = 10, page_number: int = 0, include_orgs: bool = False, role: Optional[str] = None
    ):
        return self.auth.fetch_users_in_org(org_id, page_size, page_number, include_orgs, role)

    def create_user(
        self, email: str, email_confirmed: bool = False, send_email_to_confirm_email_address: bool = True,
        ask_user_to_update_password_on_login: bool = False, password: Optional[str] = None, username: Optional[str] = None,
        first_name: Optional[str] = None, last_name: Optional[str] = None, properties: Optional[Dict[str, Any]] = None
    ):
        return self.auth.create_user(
            email, email_confirmed, send_email_to_confirm_email_address, ask_user_to_update_password_on_login,
            password, username, first_name, last_name, properties
        )

    def invite_user_to_org(self, email: str, org_id: str, role: str, additional_roles: List[str] = []):
        return self.auth.invite_user_to_org(email, org_id, role, additional_roles)

    def resend_email_confirmation(self, user_id: str):
        return self.auth.resend_email_confirmation(user_id)

    def logout_all_user_sessions(self, user_id: str):
        return self.auth.logout_all_user_sessions(user_id)

    def update_user_email(self, user_id: str, new_email: str, require_email_confirmation: bool):
        return self.auth.update_user_email(user_id, new_email, require_email_confirmation)
    
    def update_user_metadata(
        self,
        user_id: str,
        username: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        properties: Optional[Dict[str, Any]] = None,
        picture_url: Optional[str] = None,
        update_password_required: Optional[bool] = None,
    ):
        return self.auth.update_user_metadata(
            user_id, username, first_name, last_name, metadata, properties, picture_url, update_password_required
        )

    def clear_user_password(self, user_id: str):
        return self.auth.clear_user_password(user_id)

    def update_user_password(self, user_id: str, password: str, ask_user_to_update_password_on_login: bool = False):
        return self.auth.update_user_password(user_id, password, ask_user_to_update_password_on_login)

    def create_magic_link(
        self,
        email: str,
        redirect_to_url: Optional[str] = None,
        expires_in_hours: Optional[str] = None,
        create_new_user_if_one_doesnt_exist: Optional[bool] = None,
        user_signup_query_parameters: Optional[Dict[str, Any]] = None,
    ):
        return self.auth.create_magic_link(
            email, redirect_to_url, expires_in_hours, create_new_user_if_one_doesnt_exist, user_signup_query_parameters
        )

    def create_access_token(self, user_id: str, duration_in_minutes: int):
        return self.auth.create_access_token(user_id, duration_in_minutes)

    def migrate_user_from_external_source(
        self,
        email: str,
        email_confirmed: bool,
        existing_user_id: Optional[str] = None,
        existing_password_hash: Optional[str] = None,
        existing_mfa_base32_encoded_secret: Optional[str] = None,
        ask_user_to_update_password_on_login: bool = False,
        enabled: Optional[bool] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None,
        picture_url: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ):
        return self.auth.migrate_user_from_external_source(
            email, email_confirmed, existing_user_id, existing_password_hash,
            existing_mfa_base32_encoded_secret, ask_user_to_update_password_on_login,
            enabled, first_name, last_name, username, picture_url, properties
        )

    def create_org(
        self,
        name: str,
        enable_auto_joining_by_domain: bool = False,
        members_must_have_matching_domain: bool = False,
        domain: Optional[str] = None,
        max_users: Optional[str] = None,
        custom_role_mapping_name: Optional[str] = None,
        legacy_org_id: Optional[str] = None,
    ):
        return self.auth.create_org(
            name, enable_auto_joining_by_domain, members_must_have_matching_domain,
            domain, max_users, custom_role_mapping_name, legacy_org_id
        )

    def update_org_metadata(
        self,
        org_id: str,
        name: Optional[str] = None,
        can_setup_saml: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
        max_users: Optional[str] = None,
        can_join_on_email_domain_match: Optional[bool] = None,
        members_must_have_email_domain_match: Optional[bool] = None,
        domain: Optional[str] = None,
    ):
        return self.auth.update_org_metadata(
            org_id, name, can_setup_saml, metadata, max_users,
            can_join_on_email_domain_match, members_must_have_email_domain_match, domain
        )

    def subscribe_org_to_role_mapping(self, org_id: str, custom_role_mapping_name: str):
        return self.auth.subscribe_org_to_role_mapping(org_id, custom_role_mapping_name)

    def delete_org(self, org_id: str):
        return self.auth.delete_org(org_id)

    def revoke_pending_org_invite(self, org_id: str, invitee_email: str):
        return self.auth.revoke_pending_org_invite(org_id, invitee_email)

    def add_user_to_org(self, user_id: str, org_id: str, role: str, additional_roles: List[str] = []):
        return self.auth.add_user_to_org(user_id, org_id, role, additional_roles)

    def remove_user_from_org(self, user_id: str, org_id: str):
        return self.auth.remove_user_from_org(user_id, org_id)

    def change_user_role_in_org(self, user_id: str, org_id: str, role: str, additional_roles: List[str] = []):
        return self.auth.change_user_role_in_org(user_id, org_id, role, additional_roles)

    def delete_user(self, user_id: str):
        return self.auth.delete_user(user_id)

    def disable_user(self, user_id: str):
        return self.auth.disable_user(user_id)

    def enable_user(self, user_id: str):
        return self.auth.enable_user(user_id)

    def disable_user_2fa(self, user_id: str):
        return self.auth.disable_user_2fa(user_id)

    def enable_user_can_create_orgs(self, user_id: str):
        return self.auth.enable_user_can_create_orgs(user_id)

    def disable_user_can_create_orgs(self, user_id: str):
        return self.auth.disable_user_can_create_orgs(user_id)

    def allow_org_to_setup_saml_connection(self, org_id: str):
        return self.auth.allow_org_to_setup_saml_connection(org_id)

    def disallow_org_to_setup_saml_connection(self, org_id: str):
        return self.auth.disallow_org_to_setup_saml_connection(org_id)

    def fetch_api_key(self, api_key_id: str):
        return self.auth.fetch_api_key(api_key_id)

    def fetch_current_api_keys(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        page_size: Optional[int] = None,
        page_number: Optional[int] = None,
        api_key_type: Optional[str] = None,
    ):
        return self.auth.fetch_current_api_keys(
            org_id, user_id, user_email, page_size, page_number, api_key_type
        )

    def fetch_archived_api_keys(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        page_size: Optional[int] = None,
        page_number: Optional[int] = None,
        api_key_type: Optional[str] = None,
    ):
        return self.auth.fetch_archived_api_keys(
            org_id, user_id, user_email, page_size, page_number, api_key_type
        )

    def create_api_key(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        expires_at_seconds: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        return self.auth.create_api_key(org_id, user_id, expires_at_seconds, metadata)

    def update_api_key(self, api_key_id: str, expires_at_seconds: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        return self.auth.update_api_key(api_key_id, expires_at_seconds, metadata)

    def delete_api_key(self, api_key_id: str):
        return self.auth.delete_api_key(api_key_id)

    def validate_personal_api_key(self, api_key_token: str):
        return self.auth.validate_personal_api_key(api_key_token)

    def validate_org_api_key(self, api_key_token: str):
        return self.auth.validate_org_api_key(api_key_token)

    def validate_api_key(self, api_key_token: str):
        return self.auth.validate_api_key(api_key_token)
    
    def fetch_saml_sp_metadata(self, org_id: str):
        return self.auth.fetch_saml_sp_metadata(org_id)
    
    def set_saml_idp_metadata(self, org_id: str, saml_idp_metadata: SamlIdpMetadata):
        return self.auth.set_saml_idp_metadata(org_id=org_id, saml_idp_metadata=saml_idp_metadata)
    
    def saml_go_live(self, org_id: str):
        return self.auth.saml_go_live(org_id)
    
    def delete_saml_connection(self, org_id: str):
        return self.auth.delete_saml_connection(org_id)
    
def init_auth(
    auth_url: str,
    api_key: str,
    token_verification_metadata: Optional[TokenVerificationMetadata] = None,
    debug_mode=False,
) -> DjangoAuth:
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""
    return DjangoAuth(auth_url=auth_url, integration_api_key=api_key, token_verification_metadata=token_verification_metadata, debug_mode=debug_mode)
