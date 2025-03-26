<p align="center">
  <a href="https://www.propelauth.com?ref=github" target="_blank" align="center">
    <img src="https://www.propelauth.com/imgs/lockup.svg" width="200">
  </a>
</p>


# PropelAuth Django Rest Framework Library

A Django Rest Framework library for managing authentication, backed by [PropelAuth](https://www.propelauth.com/?utm_campaign=github-drf).

[PropelAuth](https://www.propelauth.com?ref=github) makes it easy to add authentication and authorization to your B2B/multi-tenant application.

Your frontend gets a beautiful, safe, and customizable login screen. Your backend gets easy authorization with just a few lines of code. You get an easy-to-use dashboard to config and manage everything.

## Documentation

- Full reference this library is [here](https://docs.propelauth.com/reference/backend-apis/drf)
- Getting started guides for PropelAuth are [here](https://docs.propelauth.com/)

## Installation

```bash
pip install propelauth-django-rest-framework
```

## Initialize

`init_auth` performs a one-time initialization of the library. 
It will verify your `api_key` is correct and fetch the metadata needed to verify access tokens in [IsUserAuthenticated and AllowAny](#protect-api-routes).

```py {{ title: "main.py" }}
from propelauth_django_rest_framework import init_auth

auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")
```

## Protect API Routes

Protecting an API route is as simple as adding a Django permission to the route.

None of the Django permissions make a external request to PropelAuth. 
They all are verified locally using the [access token](/guides-and-examples/guides/access-tokens) provided in the request, making it very fast.


### IsUserAuthenticated

A Django permission that will verify the request was made by a valid user. 
If a valid [access token](https://docs.propelauth.com/guides-and-examples/guides/access-tokens) is provided, it will set `request.propelauth_user` to be a [User](https://docs.propelauth.com/reference/backend-apis/drf#user) Class. 
If not, the request is rejected with a 401 status code. While not required, you can use the `RequiredRequest` Class to get full type support.

#### Function-based views

```py
from propelauth_django_rest_framework import init_auth, RequiredRequest

auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")

@api_view(['GET'])
@permission_classes([auth.IsUserAuthenticated])
def whoami(request: RequiredRequest):
    return HttpResponse(request.propelauth_user.user_id)
```

#### Class-based views

```py
class WhoAmIView(APIView):
    permission_classes = [auth.IsUserAuthenticated]

    def get(self, request: RequiredRequest):
        return HttpResponse(request.propelauth_user.user_id)
```

### AllowAny

Similar to `IsUserAuthenticated`, except if an access token is missing or invalid, the request is allowed to continue, but `request.propelauth_user` will be `None`. While not required, you can use the `OptionalRequest` Class to get full type support.

```py
from propelauth_django_rest_framework import OptionalRequest

class OptionalUserView(APIView):
    permission_classes = [auth.AllowAny]

    def get(self, request: OptionalRequest):
        if request.propelauth_user is None:
            return HttpResponse("none")
        return HttpResponse(request.propelauth_user.user_id)
```


## Authorization / Organizations

You can also verify which organizations the user is in, and which roles and permissions they have in each organization all through the [User Class](https://docs.propelauth.com/reference/backend-apis/drf#user).


### Check Org Membership

Verify that the request was made by a valid user **and** that the user is a member of the specified organization. This can be done using the [User](https://docs.propelauth.com/reference/backend-apis/drf#user) Class.

```py
from propelauth_django_rest_framework import RequiredRequest

@api_view(['GET'])
@permission_classes([auth.IsUserAuthenticated])
def org_membership(request: RequiredRequest, org_id):
    org = request.propelauth_user.get_org(org_id)
    if org is None:
        # return 403 error
    return Response(f"You are in org {org.org_name}")
```

### Check Org Membership and Role

Similar to checking org membership, but will also verify that the user has a specific Role in the organization. This can be done using either the [User](https://docs.propelauth.com/reference/backend-apis/drf#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/drf#org-member-info) classes.

A user has a Role within an organization. By default, the available roles are Owner, Admin, or Member, but these can be configured. These roles are also hierarchical, so Owner > Admin > Member.

```py
## Assuming a Role structure of Owner => Admin => Member

@api_view(['GET'])
@permission_classes([auth.IsUserAuthenticated])
def org_owner(request: RequiredRequest, org_id):
    org = request.propelauth_user.get_org(org_id)
    if (org is None) or (org.user_is_role("Owner") == False):
        # return 403 error
    return Response(f"You are an Owner in org {org.org_name}")
```

### Check Org Membership and Permission

Similar to checking org membership, but will also verify that the user has the specified permission in the organization. This can be done using either the [User](https://docs.propelauth.com/reference/backend-apis/drf#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/drf#org-member-info) classes.

Permissions are arbitrary strings associated with a role. For example, `can_view_billing`, `ProductA::CanCreate`, and `ReadOnly` are all valid permissions. 
You can create these permissions in the PropelAuth dashboard.

```py
@api_view(['GET'])
@permission_classes([auth.IsUserAuthenticated])
def org_billing(request: RequiredRequest, org_id):
    org = request.propelauth_user.get_org(org_id)
    if (org is None) or (org.user_has_permission("can_view_billing") == False):
        # return 403 error
    return Response(f"You can view billing information for org {org.org_name}")
```

## Calling Backend APIs

You can also use the library to call the PropelAuth APIs directly, allowing you to fetch users, create orgs, and a lot more. 
See the [API Reference](https://docs.propelauth.com/reference) for more information.

```py
from propelauth_django_rest_framework import init_auth

auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")

magic_link = auth.create_magic_link(email="test@example.com")
```

## Questions?

Feel free to reach out at support@propelauth.com
