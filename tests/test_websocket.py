"""
Tests for `geventwebsocket.websocket`
"""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from geventwebsocket import websocket

from .util import StreamStub


class EncodeBytesTestCase(unittest.TestCase):
    """
    Tests for `encode_bytes`
    """

    def test_string(self):
        """
        A simple byte string should be returned intact.
        """
        s = 'foobar'

        self.assertEqual(s, websocket.encode_bytes(s))

    def test_unicode(self):
        """
        A simple unicode object should be returned as a `utf-8` encoded
        byte string.
        """
        u = u'\u0192\xf8\xf8'
        s = u.encode('utf-8')

        self.assertEqual(s, websocket.encode_bytes(u))

    def test_non_string(self):
        """
        An object that acts like a string should be handled gracefully
        """
        class MyString(object):
            def __unicode__(self):
                return u'foobar'

        my_string = MyString()

        self.assertEqual('foobar', websocket.encode_bytes(my_string))

    def test_non_string_bytes(self):
        """
        An object that acts like a bytestring should return its bytes
        """
        class MyByteString(object):
            def __str__(self):
                return 'foobar'

        my_byte_string = MyByteString()

        self.assertEqual('foobar', websocket.encode_bytes(my_byte_string))

    def test_non_string_bad_utf8(self):
        """
        An object that acts like a bytestring but contains bad utf-8 data
        must raise a `UnicodeDecodeError` exception.
        """
        class MyBadUtf8(object):
            def __str__(self):
                return '\xff\x00'

        my_byte_string = MyBadUtf8()

        with self.assertRaises(UnicodeDecodeError):
            websocket.encode_bytes(my_byte_string)

    def test_none(self):
        """
        Encoding `None` must result in an empty string.
        """
        self.assertEqual(websocket.encode_bytes(None), '')


class WebSocketTestCase(unittest.TestCase):
    """
    Tests for `websocket.WebSocket`
    """

    def make_websocket(self, socket=None, environ=None):
        socket = socket or StreamStub()

        return websocket.WebSocket(environ, socket)

    def test_init(self):
        """
        Ensure the correct state when creating a WebSocket object.
        """
        socket = StreamStub()
        environ = object()
        ws = self.make_websocket(socket, environ)

        self.assertIs(environ, ws.environ)
        self.assertFalse(ws.closed)
        self.assertIs(ws.stream, socket)

    def test_close(self):
        """
        Ensure the correct state when closing a WebSocket object.
        """
        ws = self.make_websocket()

        self.assertFalse(ws.closed)
        ws.close()

        self.assertTrue(ws.closed)
        self.assertIsNone(ws.stream)
        self.assertIsNone(ws.raw_read)
        self.assertIsNone(ws.raw_write)

    def test_origin(self):
        """
        Ensure that the `origin` property properly pulls from the environ dict.
        """
        ws = self.make_websocket()
        self.assertIsNone(ws.environ)
        self.assertIsNone(ws.origin)

        environ = {'HTTP_ORIGIN': 'foobar'}
        ws = self.make_websocket(environ=environ)

        self.assertEqual(ws.origin, 'foobar')

    def test_protocol(self):
        """
        Ensure that the `protocol` property properly pulls from the environ
        dict.
        """
        ws = self.make_websocket()
        self.assertIsNone(ws.environ)
        self.assertIsNone(ws.protocol)

        environ = {'HTTP_SEC_WEBSOCKET_PROTOCOL': 'foobar'}
        ws = self.make_websocket(environ=environ)

        self.assertEqual(ws.protocol, 'foobar')

    def test_version(self):
        """
        Ensure that the `version` property properly pulls from the environ
        dict.
        """
        ws = self.make_websocket()
        self.assertIsNone(ws.environ)
        self.assertIsNone(ws.version)

        environ = {'HTTP_SEC_WEBSOCKET_VERSION': 'foobar'}
        ws = self.make_websocket(environ=environ)

        self.assertEqual(ws.version, 'foobar')

    def test_path(self):
        """
        Ensure that the `path` property properly pulls from the environ dict.
        """
        ws = self.make_websocket()
        self.assertIsNone(ws.environ)
        self.assertIsNone(ws.path)

        environ = {'PATH_INFO': '/foobar'}
        ws = self.make_websocket(environ=environ)

        self.assertEqual(ws.path, '/foobar')
