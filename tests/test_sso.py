from base64 import b64decode

try:  # py26
    import unittest2 as unittest
except ImportError:
    import unittest


try:  # py3
    from urllib.parse import unquote_plus
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs
    from urllib import unquote


from pydiscourse import sso
from pydiscourse.exceptions import DiscourseError


class SSOTestCase(unittest.TestCase):
    def setUp(self):
        # values from https://meta.discourse.org/t/official-single-sign-on-for-discourse/13045
        self.secret = 'd836444a9e4084d5b224a60c208dce14'
        self.nonce = 'cb68251eefb5211e58c00ff1395f0c0b'
        self.payload = 'bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGI%3D%0A'
        self.signature = '2828aa29899722b35a2f191d34ef9b3ce695e0e6eeec47deb46d588d70c7cb56'

        self.name = 'sam'
        self.username = 'samsam'
        self.external_id = 'hello123'
        self.email = 'test@test.com'
        self.name = 'Sam Sam'
        self.avatar_url = 'http://www.gravatar.com/avatar/56ef6e0c7fc2d68d83a6d7ab195da32c.png'
        self.bio = 'Bio example'
        self.redirect_url = '/session/sso_login?sso=bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGImbmFtZT1z%0AYW0mdXNlcm5hbWU9c2Ftc2FtJmVtYWlsPXRlc3QlNDB0ZXN0LmNvbSZleHRl%0Acm5hbF9pZD1oZWxsbzEyMw%3D%3D%0A&sig=1c884222282f3feacd76802a9dd94e8bc8deba5d619b292bed75d63eb3152c0b'

    def test_missing_args(self):
        with self.assertRaises(DiscourseError):
            sso.sso_validate(None, self.signature, self.secret)

        with self.assertRaises(DiscourseError):
            sso.sso_validate('', self.signature, self.secret)

        with self.assertRaises(DiscourseError):
            sso.sso_validate(self.payload, None, self.secret)

    def test_invalid_signature(self):
        with self.assertRaises(DiscourseError):
            sso.sso_validate(self.payload, 'notavalidsignature', self.secret)

    def test_valid_nonce(self):
        nonce = sso.sso_validate(self.payload, self.signature, self.secret)
        self.assertEqual(nonce, self.nonce)

    def test_valid_redirect_url(self):
        url = sso.sso_redirect_url(
            nonce=self.nonce,
            secret=self.secret,
            email=self.email,
            external_id=self.external_id,
            username=self.username,
            name=self.name,
            avatar_url=self.avatar_url,
            bio=self.bio)

        self.assertIn('/session/sso_login', url[:20])

        # check its valid, using our own handy validator
        params = parse_qs(urlparse(url).query)
        payload = params['sso'][0]
        sso.sso_validate(payload, params['sig'][0], self.secret)

        # check the params have all the data we expect
        payload = b64decode(payload.encode('utf-8')).decode('utf-8')
        payload = unquote_plus(payload)
        payload = dict((p.split('=') for p in payload.split('&')))

        self.assertEqual(payload, {
            'username': self.username,
            'nonce': self.nonce,
            'external_id': self.external_id,
            'name': self.name,
            'email': self.email,
            'name': self.name,
            'avatar_url': self.avatar_url,
            'bio': self.bio
        })
