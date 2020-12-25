import os

from cone.app import ugm_backend
from firebase_admin import auth
from node.tests import NodeTestCase

# from cone.app import testing, ugm_backend

# TODO: key is hardcoded now, must be fetched from config
from cone.app.security import authenticate

from cone.sql import testing

FIREBASE_WEB_API_KEY = "AIzaSyDqQThSScLrwBybYW5m22rZSYILELPsDz8"
rest_api_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"

certkey = {
    "type": "service_account",
    "project_id": "willholzen-293208",
    "private_key_id": "6ef3b81832e57d27ff3d845893c526068862bffb",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtYnMoOuMT55mZ\neuqpuhBHhCpJUvBtbCGip2rxxbChPEgAGVF27gRbmiXEqos1qpisrkYcpWIs7esk\nOSlGjrsCryr2ZMQmlWsxUXXZg0yee4v9zYXvNs8uvWIb5fUiNdFJd7XGszgeoI7R\nKX++qHYQ1cRrzTSKQX6aT7FzbL7giCf5yzmWDfQxAzLnHjCmHma5YY+GkAySLDO2\nIgiGJUVg4ybfRIS+chvsz0BjmxB0tewiosDiF5XGSc6QMMHbaopSpkVQVvqRs9wS\nwTiDT+Aipt4pr+XY3FA8pXFwVh9iG1yQR4OcCKH0ufLEX6xNQam+/rL5KcGjryPt\npgsdufgLAgMBAAECggEASW4RQioJESCspknb6fmozH6JGBpkTezLcMWJ8tTcoNuF\nSCaMyRWyWmWR9kZs/oJRbOURwg20k0JbYN6fsng3SArIZuRfurGwsVZJ9qlDW6jK\n8o0PN6KELyic/xVAoT71iNzTaW4J14uB8hh8sAzrTKTbeB9Hd9bvoyswsIw8dTaA\nZr04Bj+4OmQLOLDSNOwsD9LOPl/XJwnN7e1yGV8WBJCqbTHBYSipKA09BLSSYA5z\nDK8V4btVQbwUw7RRrJoCKYsqHokt6n64mJprg3/3+wsK/hSsTBsq9chEotFoNB37\ngtfkqNHtQOGpszx3Iy0azdqGWFTv4qwionuRhT4mCQKBgQD4mbJwXwqcc52ZCtzh\n8GmClHjWzP9zSvdxRcg6gT01nSjupHcFAZkQxVhPrqS54/Vq7wENuhn72Uo6G+6Y\nv8bEeZjlABKgHr0fX3rMvpdfBAfRZCV+BBvGJkJQoyRtYESmuM/zj9Q2hWOw95pk\n+FqJi+ev4pmWdjfIf2H7MejTswKBgQD0c0ou5UAW+dzDYMqJYErvxkogWpONp9kp\nw5vA/Uu6oaEw8Fb6fRuWv0D67HEmc4u2VQMMPgrpSQUuLuEkQOcJ37pySw9+TDAf\np7OM2S2fW2lzO7RdDLHAUZwBY3DcK+zghrzgn7eNun/gsTh9xNi0dV6sUsakkzC8\n4QuFQY7+SQKBgCjnKPviN128jB6lMeie5M1OXn+BJTq0B/iEMcimgQq0PArf1pFl\nTOj8f2ZE5ueLAVNB1duLVkEg5FyhQeWyECM9mpF7LJVZ2WYzEIJljYRdpmemYaDV\nTjiRDPI1lYXFhCYmXFjHvnPmCJwScT3RuxvMgCdpUjn2Y4FCrD1nXdaPAoGAQO5e\nxhYe7/tuqHcNVXA+d3I0PmPQzc/H31AWDy048Fn+dwFgGSkiKuiiWgR0CcKnWcc7\nCAVy4ISE27+YDgkvVXAYFkPZ2bJjFgV1q/QEKlAdsn4pao30qSEET1oaoGEKipk/\nkmraVsszLHvmhYHEDise+qcCHLT8PS+J39uKIAECgYEA2p8PrNNzIuupY9+KATFm\nMoLG+DbKnZujiGKh4FK6VZybWL8g3PEK3J9FU+wsfiz9q8L186/+QCOfiJ1jYEOJ\n+vxmnxh4w/2jqEFbuRq9q3s3+qtAr6UdprWAGR3snTky9URHJEqcH0h7TGXVfZLW\noUaP0QDsapUQYyQeUYCIQWA=\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-ifzba@willholzen-293208.iam.gserviceaccount.com",
    "client_id": "113313836704540671816",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-ifzba%40willholzen-293208.iam.gserviceaccount.com"
}

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
        self.layer.tearDown()

    def firebase_init(self):
        import firebase_admin
        from firebase_admin import credentials

        self.cred = credentials.Certificate(certkey)
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


    def test_schas(self):
        print("schas")
        ugm=ugm_backend.ugm
        d0 = ugm.users.create("donald0")
        d0.passwd(None, "daisy1")
        d1 = ugm.users.create("donald1")
        d1.passwd(None, "daisy1")
        authenticated = ugm.users.authenticate("donald2", "daisy1")
        # authenticate(self.layer.current_request, "donald0", "daisy1")

        print(f"done {authenticated}")

    def test_authentication_logging(self):

        self.layer.authenticated("foo", "foo")
        orgin_ugm = ugm_backend.ugm
        ugm_backend.ugm = object()

        authenticate(self.layer.new_request(), 'foo', 'foo1')

        print("ready")
