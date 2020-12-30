import base64
import json
import os

from cone.app import ugm_backend, security
from cone.app.authenticators.firebase import FirebaseAuthenticator
from cone.app.model import AppRoot
from firebase_admin import auth
from node.ext.ugm.interfaces import IAuthenticator, IUsers
from node.tests import NodeTestCase

# from cone.app import testing, ugm_backend

from cone.app.security import authenticate, authenticated_user
from zope import component

from cone.sql import testing

FIREBASE_WEB_API_KEY = "AIzaSyDqQThSScLrwBybYW5m22rZSYILELPsDz8"
FIREBASE_API_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"

certkey_raw = b'eyJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsICJwcm9qZWN0X2lkIjogIndpbGxob2x6ZW4tMjkzMjA4IiwgInByaXZhdGVfa2V5X2lkIjogIjZlZjNiODE4MzJlNTdkMjdmZjNkODQ1ODkzYzUyNjA2ODg2MmJmZmIiLCAicHJpdmF0ZV9rZXkiOiAiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG5NSUlFdlFJQkFEQU5CZ2txaGtpRzl3MEJBUUVGQUFTQ0JLY3dnZ1NqQWdFQUFvSUJBUUR0WW5Nb091TVQ1NW1aXG5ldXFwdWhCSGhDcEpVdkJ0YkNHaXAycnh4YkNoUEVnQUdWRjI3Z1JibWlYRXFvczFxcGlzcmtZY3BXSXM3ZXNrXG5PU2xHanJzQ3J5cjJaTVFtbFdzeFVYWFpnMHllZTR2OXpZWHZOczh1dldJYjVmVWlOZEZKZDdYR3N6Z2VvSTdSXG5LWCsrcUhZUTFjUnJ6VFNLUVg2YVQ3RnpiTDdnaUNmNXl6bVdEZlF4QXpMbkhqQ21IbWE1WVkrR2tBeVNMRE8yXG5JZ2lHSlVWZzR5YmZSSVMrY2h2c3owQmpteEIwdGV3aW9zRGlGNVhHU2M2UU1NSGJhb3BTcGtWUVZ2cVJzOXdTXG53VGlEVCtBaXB0NHByK1hZM0ZBOHBYRndWaDlpRzF5UVI0T2NDS0gwdWZMRVg2eE5RYW0rL3JMNUtjR2pyeVB0XG5wZ3NkdWZnTEFnTUJBQUVDZ2dFQVNXNFJRaW9KRVNDc3BrbmI2Zm1vekg2SkdCcGtUZXpMY01XSjh0VGNvTnVGXG5TQ2FNeVJXeVdtV1I5a1pzL29KUmJPVVJ3ZzIwazBKYllONmZzbmczU0FySVp1UmZ1ckd3c1ZaSjlxbERXNmpLXG44bzBQTjZLRUx5aWMveFZBb1Q3MWlOelRhVzRKMTR1QjhoaDhzQXpyVEtUYmVCOUhkOWJ2b3lzd3NJdzhkVGFBXG5acjA0QmorNE9tUUxPTERTTk93c0Q5TE9QbC9YSnduTjdlMXlHVjhXQkpDcWJUSEJZU2lwS0EwOUJMU1NZQTV6XG5ESzhWNGJ0VlFid1V3N1JSckpvQ0tZc3FIb2t0Nm42NG1KcHJnMy8zK3dzSy9oU3NUQnNxOWNoRW90Rm9OQjM3XG5ndGZrcU5IdFFPR3BzengzSXkwYXpkcUdXRlR2NHF3aW9udVJoVDRtQ1FLQmdRRDRtYkp3WHdxY2M1MlpDdHpoXG44R21DbEhqV3pQOXpTdmR4UmNnNmdUMDFuU2p1cEhjRkFaa1F4VmhQcnFTNTQvVnE3d0VOdWhuNzJVbzZHKzZZXG52OGJFZVpqbEFCS2dIcjBmWDNyTXZwZGZCQWZSWkNWK0JCdkdKa0pRb3lSdFlFU211TS96ajlRMmhXT3c5NXBrXG4rRnFKaStldjRwbVdkamZJZjJIN01lalRzd0tCZ1FEMGMwb3U1VUFXK2R6RFlNcUpZRXJ2eGtvZ1dwT05wOWtwXG53NXZBL1V1Nm9hRXc4RmI2ZlJ1V3YwRDY3SEVtYzR1MlZRTU1QZ3JwU1FVdUx1RWtRT2NKMzdweVN3OStUREFmXG5wN09NMlMyZlcybHpPN1JkRExIQVVad0JZM0RjSyt6Z2hyemduN2VOdW4vZ3NUaDl4TmkwZFY2c1VzYWtrekM4XG40UXVGUVk3K1NRS0JnQ2puS1B2aU4xMjhqQjZsTWVpZTVNMU9YbitCSlRxMEIvaUVNY2ltZ1FxMFBBcmYxcEZsXG5UT2o4ZjJaRTV1ZUxBVk5CMWR1TFZrRWc1RnloUWVXeUVDTTltcEY3TEpWWjJXWXpFSUpsallSZHBtZW1ZYURWXG5UamlSRFBJMWxZWEZoQ1ltWEZqSHZuUG1DSndTY1QzUnV4dk1nQ2RwVWpuMlk0RkNyRDFuWGRhUEFvR0FRTzVlXG54aFllNy90dXFIY05WWEErZDNJMFBtUFF6Yy9IMzFBV0R5MDQ4Rm4rZHdGZ0dTa2lLdWlpV2dSMENjS25XY2M3XG5DQVZ5NElTRTI3K1lEZ2t2VlhBWUZrUFoyYkpqRmdWMXEvUUVLbEFkc240cGFvMzBxU0VFVDFvYW9HRUtpcGsvXG5rbXJhVnNzekxIdm1oWUhFRGlzZStxY0NITFQ4UFMrSjM5dUtJQUVDZ1lFQTJwOFByTk56SXV1cFk5K0tBVEZtXG5Nb0xHK0RiS25adWppR0toNEZLNlZaeWJXTDhnM1BFSzNKOUZVK3dzZml6OXE4TDE4Ni8rUUNPZmlKMWpZRU9KXG4rdnhtbnhoNHcvMmpxRUZidVJxOXEzczMrcXRBcjZVZHByV0FHUjNzblRreTlVUkhKRXFjSDBoN1RHWFZmWkxXXG5vVWFQMFFEc2FwVVFZeVFlVVlDSVFXQT1cbi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS1cbiIsICJjbGllbnRfZW1haWwiOiAiZmlyZWJhc2UtYWRtaW5zZGstaWZ6YmFAd2lsbGhvbHplbi0yOTMyMDguaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCAiY2xpZW50X2lkIjogIjExMzMxMzgzNjcwNDU0MDY3MTgxNiIsICJhdXRoX3VyaSI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20vby9vYXV0aDIvYXV0aCIsICJ0b2tlbl91cmkiOiAiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLCAiYXV0aF9wcm92aWRlcl94NTA5X2NlcnRfdXJsIjogImh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL29hdXRoMi92MS9jZXJ0cyIsICJjbGllbnRfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9yb2JvdC92MS9tZXRhZGF0YS94NTA5L2ZpcmViYXNlLWFkbWluc2RrLWlmemJhJTQwd2lsbGhvbHplbi0yOTMyMDguaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20ifQ=='
certkey = json.loads(base64.b64decode(certkey_raw))

UID = "fbdonald"
PWD = "daisy1"
EMAIL = "donald@duck.com"


class FirebaseTest(NodeTestCase):
    layer = testing.sql_layer

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)

    def setUp(self):
        self.layer.setUp()
        self.firebase_init()
        self.user = self.fb_user()

    def tearDown(self):
        super().tearDown()
        self.layer.tearDown()

        # dispose remnants of the ugm setup
        root = AppRoot()
        settings_factories = root['settings'].factories
        for k in settings_factories.keys():
            del settings_factories[k]

        root_factories = root.factories
        for k in ["users", "groups"]:
            del root_factories[k]

    def firebase_init(self):
        import firebase_admin
        from firebase_admin import credentials

        self.cred = credentials.Certificate(certkey)
        if not firebase_admin._apps:
            self.app = firebase_admin.initialize_app(self.cred)

    def fb_user(self):
        from firebase_admin.auth import UserNotFoundError
        try:
            user = auth.get_user(UID)
        except UserNotFoundError:
            user = auth.create_user(
                uid=UID,
                email='donald@duck.com',
                phone_number='+15555550100',
                email_verified=True,
                password='daisy1',
                display_name='Donald Duck',
                photo_url='http://www.example.com/12345678/photo.png',
                disabled=False)

        return user


    def test_auth(self):
        print("schas")
        ugm = ugm_backend.ugm
        d0 = ugm.users.create("donald0")
        d0.passwd(None, "daisy1")
        d1 = ugm.users.create("donald1")
        d1.passwd(None, "daisy1")

        # first lets test the normal authentication
        authenticated0 = ugm.users.authenticate("donald0", "daisy1")

        self.assertEqual(authenticated0, True)


        print(f"done {authenticated0}")

    def test_authenticator_direct(self):
        """
        test the authenticator directly instantiated
        """
        assert "fbdonald" not in ugm_backend.ugm.users
        auth = FirebaseAuthenticator(ugm_backend.ugm.users, FIREBASE_WEB_API_KEY)
        res = auth.authenticate("donald@duck.com", "daisy1")
        self.assertTrue(res, True)

        assert "fbdonald" in ugm_backend.ugm.users

        # now check for the new user's existence in ugm
        local_user = ugm_backend.ugm.users[res["localId"]]
        assert local_user.attributes["email"] == "donald@duck.com"


    def test_authenticator_adapter(self):
        """
        test the authenticator by requesting the adapter
        """
        ugm = ugm_backend.ugm
        users = ugm.users

        component.provideAdapter(
            factory=lambda x:
                FirebaseAuthenticator(ugm.users, FIREBASE_WEB_API_KEY),
            adapts=[IUsers],
            provides=IAuthenticator,
        )

        auti = component.getAdapter(ugm.users, IAuthenticator)
        assert "fbdonald" not in ugm_backend.ugm.users
        res = auti.authenticate("donald@duck.com", "daisy1")

        # now check for the new user's existence in ugm
        assert "fbdonald" in ugm_backend.ugm.users

        # now create a user locally and check if we can log in with a user that does not exist in fb

        users.create("schlumpf")
        users["schlumpf"].passwd(None, "daisy1")
        res = auti.authenticate("schlumpf", "daisy1")

        self.assertTrue(res)

    def test_authenticator_global_authenticate(self):
        """
        test the authenticator by calling security.authenticate()
        """

        ugm = ugm_backend.ugm
        users = ugm.users
        request = self.layer.current_request

        component.provideAdapter(
            factory=lambda users:
                FirebaseAuthenticator(users, FIREBASE_WEB_API_KEY),
            adapts=[IUsers],
            provides=IAuthenticator,
        )

        u = authenticated_user(request)
        # self.assertTrue(request.authenticated_userid) # unfortunately this does not work with the dummy request

        assert "fbdonald" not in ugm_backend.ugm.users
        res = security.authenticate(request, "donald@duck.com", "daisy1")

        # now check for the new user's existence in ugm
        assert "fbdonald" in ugm_backend.ugm.users

        # now create a user locally and check if we can log in with a user that does not exist in fb
        users.create("schlumpf")
        users["schlumpf"].passwd(None, "daisy1")
        security.authenticate(request, "schlumpf", "daisy1")

        # TODO test with unreachable FB server, it should then at least authenticate locally
