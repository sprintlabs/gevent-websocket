try:
    import unittest2 as unittest
except ImportError:
    import unittest

from geventwebsocket import wsgi


class ResconstructUrlTestCase(unittest.TestCase):
    """
    Tests for `handler.reconstruct_url`
    """

    def assertWSUrl(self, http_url, ws_url):
        environ = self.make_environ(http_url)

        self.assertEqual(
            wsgi.reconstruct_url(environ),
            ws_url
        )

    def make_environ(self, url):
        """
        Return a wsgi compatible environ dict based on the supplied url.
        """
        import urlparse

        parsed_url = urlparse.urlparse(url)
        environ = {
            'wsgi.url_scheme': parsed_url.scheme,
            'SERVER_NAME': parsed_url.hostname,
            'SERVER_PORT': str(parsed_url.port or (
                '80' if parsed_url.scheme == 'http' else '443')),
            'PATH_INFO': parsed_url.path,
            'QUERY_STRING': parsed_url.query,
        }

        return environ

    def test_sanity(self):
        """
        Do a basic check to ensure sanity
        """
        self.assertWSUrl(
            'http://foo.bar/my/path?x=y#z',
            'ws://foo.bar/my/path?x=y'
        )

    def test_secure(self):
        """
        https:// must result in a wss:// url
        """
        self.assertWSUrl(
            'https://localhost/echo',
            'wss://localhost/echo'
        )

    def test_secure_diff_port(self):
        """
        Check the port definition for using https
        """
        self.assertWSUrl(
            'https://localhost:1234/echo',
            'wss://localhost:1234/echo'
        )

    def testdiff_port(self):
        """
        Check the port definition for using http
        """
        self.assertWSUrl(
            'http://localhost:1234/echo',
            'ws://localhost:1234/echo'
        )
