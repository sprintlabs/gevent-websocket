import unittest
import mock

from geventwebsocket import handler as ws_handler

from .util import FakeSocket


class ResconstructUrlTestCase(unittest.TestCase):
    """
    Tests for `handler.reconstruct_url`
    """

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
        environ = self.make_environ('http://foo.bar/my/path?x=y#z')

        self.assertEqual(
            ws_handler.reconstruct_url(environ),
            'ws://foo.bar/my/path?x=y'
        )

    def test_secure(self):
        """
        https:// must result in a wss:// url
        """
        environ = self.make_environ('https://localhost/echo')

        self.assertEqual(
            ws_handler.reconstruct_url(environ),
            'wss://localhost/echo'
        )

    def test_secure_diff_port(self):
        """
        Check the port definition for using https
        """
        environ = self.make_environ('https://localhost:1234/echo')

        self.assertEqual(
            ws_handler.reconstruct_url(environ),
            'wss://localhost:1234/echo'
        )

    def testdiff_port(self):
        """
        Check the port definition for using http
        """
        environ = self.make_environ('http://localhost:1234/echo')

        self.assertEqual(
            ws_handler.reconstruct_url(environ),
            'ws://localhost:1234/echo'
        )


class HandlerTestCase(unittest.TestCase):
    def my_app(self, environ, start_response):
        start_response('200 OK', [])

        return []

    def make_handler(self, environ=None, socket=None):
        socket = socket or FakeSocket()

        my_handler = ws_handler.WebSocketHandler(
            socket, ('localhost', 1010), None)

        my_handler.environ = environ or {}
        my_handler.request_version = 'HTTP/1.1'
        my_handler.application = mock.Mock()
        my_handler.process_result = mock.Mock()
        my_handler.request_version = 'HTTP/1.1'

        return my_handler


class RunApplicationTestCase(HandlerTestCase):
    """
    Tests for `run_application`.
    """

    def test_missing_upgrade(self):
        """
        A request with a missing `HTTP_UPGRADE` header must not create a
        websocket.
        """
        environ = {}
        handler = self.make_handler(environ)

        handler.run_application()

        self.assertIsNone(handler.websocket)
        self.assertNotIn('wsgi.websocket', environ)
        self.assertTrue(handler.application.called)

    def test_missing_connection(self):
        """
        A request with a missing `HTTP_CONNECTION` header must not create a
        websocket.
        """
        environ = {
            'HTTP_UPGRADE': 'WebSocket'
        }
        handler = self.make_handler(environ)

        handler.run_application()

        self.assertIsNone(handler.websocket)
        self.assertNotIn('wsgi.websocket', environ)
        self.assertTrue(handler.application.called)

    def test_failed_upgrade(self):
        """
        If a call to `upgrade_websocket` returns False, a websocket must not be
        created.
        """
        environ = {
            'HTTP_UPGRADE': 'WebSocket',
            'HTTP_CONNECTION': 'Upgrade'
        }
        handler = self.make_handler(environ)

        with mock.patch.object(handler, 'upgrade_websocket') as upgrade:
            handler.status = '404 Not Found'
            upgrade.return_value = False

            handler.run_application()

        self.assertNotIn('wsgi.websocket', environ)
        self.assertTrue(handler.process_result.called)

    def test_failed_upgrade_no_response(self):
        """
        If a call to `upgrade_websocket` returns False but no status is set,
        a websocket must not be created.
        """
        environ = {
            'HTTP_UPGRADE': 'WebSocket',
            'HTTP_CONNECTION': 'Upgrade'
        }
        handler = self.make_handler(environ)

        with mock.patch.object(handler, 'upgrade_websocket') as upgrade:
            upgrade.return_value = False

            handler.run_application()

        self.assertNotIn('wsgi.websocket', environ)
        self.assertTrue(handler.application.called)

    def test_upgrade_successful(self):
        """
        A successful upgrade requires specific attrs to be set
        """
        sentinel = object()
        environ = {
            'HTTP_UPGRADE': 'WebSocket',
            'HTTP_CONNECTION': 'Upgrade',
            'wsgi.websocket': sentinel,
        }
        handler = self.make_handler(environ)

        with mock.patch.object(handler, 'upgrade_websocket') as upgrade:
            upgrade.return_value = True

            handler.code = 101
            handler.status = '101 Switching Protocols'
            handler.response_headers = []
            handler.response_length = 0

            handler.run_application()

        self.assertIs(environ['wsgi.websocket'], sentinel)
        self.assertIs(handler.websocket, sentinel)
        self.assertTrue(handler.provided_content_length)
        self.assertFalse(handler.response_use_chunked)
        self.assertTrue(handler.close_connection)
        self.assertTrue(handler.provided_date)

        self.assertTrue(handler.application.called)

    def test_prevent_wsgi_call(self):
        """
        When `prevent_wsgi_call` is set on the handler, the underlying
        application must not be called.
        """
        sentinel = object()
        environ = {
            'HTTP_UPGRADE': 'WebSocket',
            'HTTP_CONNECTION': 'Upgrade',
            'wsgi.websocket': sentinel,
            }
        handler = self.make_handler(environ)
        handler.prevent_wsgi_call = True

        with mock.patch.object(handler, 'upgrade_websocket') as upgrade:
            upgrade.return_value = True

            handler.code = 101
            handler.status = '101 Switching Protocols'
            handler.response_headers = []
            handler.response_length = 0

            handler.run_application()

        self.assertIs(environ['wsgi.websocket'], sentinel)
        self.assertIs(handler.websocket, sentinel)
        self.assertTrue(handler.provided_content_length)
        self.assertFalse(handler.response_use_chunked)
        self.assertTrue(handler.close_connection)
        self.assertTrue(handler.provided_date)

        self.assertFalse(handler.application.called)


class UpgradeWebsocketTestCase(HandlerTestCase):
    """
    Tests for `upgrade_websocket`
    """

    def test_method(self):
        """
        A request method != GET must result in a 400.
        """
        for request_method in ['POST', 'DELETE', 'PUT', 'OPTIONS', 'HEAD']:
            environ = {
                'REQUEST_METHOD': request_method
            }

            handler = self.make_handler(environ)

            result = handler.upgrade_websocket()

            self.assertFalse(result)
            self.assertEqual(handler.status, '400 Bad Request')

    def test_http_version(self):
        """
        A request method != GET must result in a 400.
        """
        environ = {
            'REQUEST_METHOD': 'GET'
        }

        for version in ['HTTP/0.9', 'HTTP/1.0']:
            handler = self.make_handler(environ)
            handler.request_version = version

            result = handler.upgrade_websocket()

            self.assertFalse(result)
            self.assertEqual(handler.status, '400 Bad Request')

    def test_missing_origin(self):
        """
        A missing HTTP_ORIGIN header must result in a failed upgrade_websocket.
        """
        environ = {
            'REQUEST_METHOD': 'GET',
        }

        handler = self.make_handler(environ)
        result = handler.upgrade_websocket()

        self.assertFalse(result)

    def test_set_status(self):
        """
        Setting a status != 101 in `*.upgrade_connection` must result in a
        failure.
        """
        from geventwebsocket import hixie

        environ = {
            'REQUEST_METHOD': 'GET',
            'HTTP_ORIGIN': '*'
        }

        with mock.patch.object(hixie, 'upgrade_connection') as upgrade:
            handler = self.make_handler(environ)
            handler.status = '400 Bad Request'

            result = handler.upgrade_websocket()

            self.assertFalse(result)

    def test_upgrade(self):
        """
        Given the correct conditions, `upgrade_websocket` should return true.
        """
        from geventwebsocket import hixie

        environ = {
            'REQUEST_METHOD': 'GET',
            'HTTP_ORIGIN': '*'
        }

        with mock.patch.object(hixie, 'upgrade_connection') as upgrade:
            handler = self.make_handler(environ)
            handler.status = '101 Switching Protocol'

            result = handler.upgrade_websocket()

            self.assertTrue(result)
