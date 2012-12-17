import unittest

from geventwebsocket import hybi

from .test_websocket import FakeSocket


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

    def make_handler(self, method='GET', version='HTTP/1.1', environ=None,
                     socket=None):
        environ = environ or {}
        socket = socket or FakeSocket()

        if method:
            environ['REQUEST_METHOD'] = method

        handler = MockHandler(environ, version)
        handler.socket = socket

        return handler

    def test_basic_sanity_check(self):
        """
        Given the example in the docs (Section 1.3), ensure a basic sanity check
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY': 'dGhlIHNhbXBsZSBub25jZQ==',
            'HTTP_SEC_WEBSOCKET_VERSION': '13'
        }

        handler = self.make_handler(environ=environ)

        hybi.upgrade_connection(handler, environ)

        expected_headers = [
            ('Upgrade', 'websocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=')
        ]

        self.assertEqual(handler.status, '101 Switching Protocols')
        self.assertEqual(expected_headers, handler.headers)

        # ensure that the environ dict has been appropriately updated
        ws = environ['wsgi.websocket']
        version = environ['wsgi.websocket_version']

        self.assertEqual(version, 'hybi-13')
        self.assertIsInstance(ws, hybi.WebSocket)

    def test_invalid_version(self):
        """
        An invalid Sec-WebSocket-Version must result in a 400 status
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_VERSION': 'foobar'
        }

        handler = self.make_handler(environ=environ)

        response = hybi.upgrade_connection(handler, environ)

        expected_headers = [
            ('Sec-WebSocket-Version', '13, 8, 7')
        ]

        self.assertEqual('400 Bad Request', handler.status)
        self.assertEqual(expected_headers, handler.headers)
        self.assertEqual(response, ["Unsupported WebSocket Version: 'foobar'"])
