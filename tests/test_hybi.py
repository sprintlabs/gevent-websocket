import unittest

from geventwebsocket import hybi


class MockHandler(object):
    """
    A test compatible WSGI handler
    """

    def __init__(self, environ, request_version):
        self.environ = environ
        self.request_version = request_version

    def log_error(self, msg):
        self.log = msg

    def start_response(self, status, headers):
        self.status = status
        self.headers = headers


class UpgradeConnectionTestCase(unittest.TestCase):
    """
    Tests for `hybi.upgrade_connection`.
    """

    def make_handler(self, method='GET', version='HTTP/1.1', environ=None):
        environ = environ or {}

        if method:
            environ['REQUEST_METHOD'] = method

        return MockHandler(environ, version)

    def test_request_method(self):
        """
        A 400 response must be returned a GET method is not used.
        """
        for request_method in ['POST', 'PUT', 'DELETE', 'FOOBAR']:
            handler = self.make_handler(request_method)

            response = hybi.upgrade_connection(handler)

            self.assertEqual(handler.status, '400 Bad Request')
            self.assertEqual(handler.headers, [])
            self.assertIsNone(response)

        # now check the correct request method
        handler = self.make_handler('GET')

        response = hybi.upgrade_connection(handler)

        self.assertNotEqual(handler.status, '400 Bad Request')
