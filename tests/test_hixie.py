# -*- coding: utf-8 -*-

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from mock import patch

from geventwebsocket import hixie, exceptions as exc

from .util import FakeSocket, MockHandler


class UpgradeConnectionHixie75TestCase(unittest.TestCase):
    """
    Tests for `hixie.upgrade_connection` for a hixie-75 websocket.
    """

    def make_handler(self, method='GET', version='HTTP/1.1', environ=None,
                     socket=None):
        environ = environ or {}
        socket = socket or FakeSocket()

        if method:
            environ['REQUEST_METHOD'] = method

        handler = MockHandler(environ, version)
        handler.socket = socket
        handler.rfile = socket.makefile('rb', 0)
        handler.ws_url = None

        return handler

    def test_sanity(self):
        """
        Ensure that given a valid challenge, a `hixie-75` websocket is
        established.
        """
        environ = {}
        handler = self.make_handler(environ=environ)

        result = hixie.upgrade_connection(handler, environ)

        self.assertIsNone(result)
        self.assertEqual('hixie-75', environ['wsgi.websocket_version'])

        ws = environ['wsgi.websocket']

        self.assertIsInstance(ws, hixie.WebSocketHixie75)
        self.assertFalse(ws.closed)
        self.assertEqual(handler.status, '101 WebSocket Protocol Handshake')
        self.assertEqual(handler.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade')
        ])

    def test_protocol(self):
        """
        Ensure that the `Sec-WebSocket-Protocol` header is echoed back.
        """
        environ = {
            'HTTP_WEBSOCKET_PROTOCOL': 'foobar'
        }

        handler = self.make_handler(environ=environ)

        hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('WebSocket-Protocol', 'foobar'),
            ])

    def test_location(self):
        """
        Ensure that the `WebSocket-Location` header is sent.
        """
        handler = self.make_handler()
        handler.ws_url = 'ws://localhost:6666/'

        hixie.upgrade_connection(handler, {})

        self.assertEqual(handler.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('WebSocket-Location', 'ws://localhost:6666/'),
        ])

    def test_origin(self):
        """
        Ensure that the `WebSocket-Origin` header is sent.
        """
        environ = {
            'HTTP_ORIGIN': 'foobar'
        }
        handler = self.make_handler(environ=environ)

        hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('WebSocket-Origin', 'foobar'),
        ])


class UpgradeConnectionHixie76TestCase(unittest.TestCase):
    """
    Tests for `hixie.upgrade_connection`.
    """

    # values taken from
    # http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76 page 8
    key1 = '18x 6]8vM;54 *(5:  {   U1]8  z [  8'
    key2 = '1_ tx7X d  <  nw  334J702) 7]o}` 0'

    def make_handler(self, method='GET', version='HTTP/1.1', environ=None,
                     socket=None):
        environ = environ or {}
        socket = socket or FakeSocket()

        if method:
            environ['REQUEST_METHOD'] = method

        handler = MockHandler(environ, version)
        handler.socket = socket
        handler.rfile = socket.makefile('rb', 0)
        handler.ws_url = None

        return handler

    def make_hixie76(self):
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': self.key1,
            'HTTP_SEC_WEBSOCKET_KEY2': self.key2,
        }

        socket = FakeSocket('\x00' * 8)
        return self.make_handler(environ=environ, socket=socket)

    def test_no_keys(self):
        """
        No keys in the client handshake means `hixie-75` version.
        :return:
        """
        environ = {}

        handler = self.make_handler(environ=environ)

        result = hixie.upgrade_connection(handler, environ)

        self.assertIsNone(result)
        self.assertEqual('hixie-75', environ['wsgi.websocket_version'])

        ws = environ['wsgi.websocket']

        self.assertIsInstance(ws, hixie.WebSocketHixie75)
        self.assertFalse(ws.closed)
        self.assertEqual(handler.status, '101 WebSocket Protocol Handshake')

    def test_empty_key1(self):
        """
        An existing (but empty) Sec-Websocket-Key1 must result in a 400.
        :return:
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': ''
        }

        handler = self.make_handler(environ=environ)

        result = hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.status, '400 Bad Request')
        self.assertEqual(result, ['400: Sec-WebSocket-Key1 header is empty'])
        self.assertEqual(handler.headers, [])

    def test_missing_key2(self):
        """
        A 'valid' key1 but a missing key2 must result in a 400.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': 'foobar'
        }

        handler = self.make_handler(environ=environ)

        result = hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.status, '400 Bad Request')
        self.assertEqual(result,
                         ['400: Sec-WebSocket-Key2 header is missing/empty'])
        self.assertEqual(handler.headers, [])

    def test_empty_key2(self):
        """
        A 'valid' key1 but an empty key2 must result in a 400.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': 'foobar',
            'HTTP_SEC_WEBSOCKET_KEY2': '',
        }

        handler = self.make_handler(environ=environ)

        result = hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.status, '400 Bad Request')
        self.assertEqual(result,
                         ['400: Sec-WebSocket-Key2 header is missing/empty'])
        self.assertEqual(handler.headers, [])

    def test_invalid_key1(self):
        """
        An invalid key1 must result in a 400 status.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': 'foo',
            'HTTP_SEC_WEBSOCKET_KEY2': 'bar',
        }

        handler = self.make_handler(environ=environ)

        result = hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.status, '400 Bad Request')
        self.assertEqual(result, ['Invalid value for key'])
        self.assertEqual(handler.headers, [])

    def test_invalid_key2(self):
        """
        An invalid key2 must result in a 400 status.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': self.key1,
            'HTTP_SEC_WEBSOCKET_KEY2': 'bar',
        }

        handler = self.make_handler(environ=environ)

        result = hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.status, '400 Bad Request')
        self.assertEqual(result, ['Invalid value for key'])
        self.assertEqual(handler.headers, [])

    def test_missing_key3(self):
        """
        Assuming that key1 and 2 are valid, if reading an incomplete/missing
        key3 must result in a `exc.WebSocketError`.
        """
        old_environ = environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': self.key1,
            'HTTP_SEC_WEBSOCKET_KEY2': self.key2,
        }

        handler = self.make_handler(environ=environ)

        with self.assertRaises(exc.WebSocketError) as ctx:
            hixie.upgrade_connection(handler, environ)

        self.assertEqual(
            unicode(ctx.exception),
            u'Unexpected EOF while reading key3'
        )

        self.assertEqual(environ, old_environ)

    def test_full_challenge(self):
        """
        Basic sanity check for creating a hixie-76 websocket.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': self.key1,
            'HTTP_SEC_WEBSOCKET_KEY2': self.key2,
        }

        socket = FakeSocket('\x00' * 8)
        handler = self.make_handler(environ=environ, socket=socket)

        result = hixie.upgrade_connection(handler, environ)

        self.assertEqual(
            socket.data[10:],
            '{\xf8\x0b\xfe\x83,"\x9e}\x1b\xda0\xb2)'
        )

        self.assertIsNone(result)
        self.assertEqual(handler.status, '101 WebSocket Protocol Handshake')
        self.assertEqual('hixie-76', environ['wsgi.websocket_version'])

        ws = environ['wsgi.websocket']

        self.assertIsInstance(ws, hixie.WebSocketHixie76)
        self.assertFalse(ws.closed)
        self.assertEqual(handler.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade')
        ])

    def test_protocol(self):
        """
        Ensure that the `Sec-WebSocket-Protocol` header is echoed back.
        """
        handler = self.make_hixie76()
        environ = {
            'HTTP_SEC_WEBSOCKET_PROTOCOL': 'foobar'
        }

        environ.update(handler.environ)
        hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Protocol', 'foobar'),
        ])

    def test_location(self):
        """
        Ensure that the `Sec-WebSocket-Location` header is sent.
        """
        handler = self.make_hixie76()
        handler.ws_url = 'ws://localhost:6666/'

        hixie.upgrade_connection(handler, handler.environ)

        self.assertEqual(handler.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Location', 'ws://localhost:6666/'),
        ])

    def test_origin(self):
        """
        Ensure that the `Sec-WebSocket-Origin` header is sent.
        """
        handler = self.make_hixie76()
        environ = {
            'HTTP_ORIGIN': 'foobar'
        }

        environ.update(handler.environ)
        hixie.upgrade_connection(handler, environ)

        self.assertEqual(handler.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Origin', 'foobar'),
        ])


class BaseStreamTestCase(unittest.TestCase):
    def make_socket(self, data):
        return FakeSocket(data)

    def make_websocket(self, socket=None, environ=None):
        socket = socket or FakeSocket()
        environ = environ or {}

        return hixie.BaseWebSocket(socket, environ, socket.makefile('rb', 0))


class SendTestCase(BaseStreamTestCase):
    """
    Tests for `hixie.WebSocketHixie.send`.
    """

    def test_text(self):
        """
        Ensure that sending unicode works correctly
        """
        socket = FakeSocket()
        ws = self.make_websocket(socket)

        text = u'ƒøø'
        ws.send(text)

        self.assertEqual(
            '\x00' + text.encode('utf-8') + '\xff',
            socket.data,
            )

    def test_send_empty(self):
        """
        An empty frame is considered a close frame. Ensure that sending an
        empty frame does not close the websocket.
        """
        ws = self.make_websocket()

        self.assertFalse(ws.closed)
        ws.send('')
        self.assertFalse(ws.closed)

    def test_invalid_utf8(self):
        """
        Attempting to send binary data should NOT close the websocket and raise
        the exception.
        """
        socket = FakeSocket()
        ws = self.make_websocket(socket)

        blob = '\xff'

        with self.assertRaises(UnicodeDecodeError) as ctx:
            ws.send(blob)

        self.assertFalse(ws.closed)

    @patch.object(FakeSocket, 'sendall')
    def test_broken_socket(self, sendall):
        """
        Any attempt to write to this socket will result in an error. A
        WebSocketError should be raised but the websocket must not be closed.
        """
        from socket import error

        sendall.side_effect = error

        ws = self.make_websocket()
        self.assertFalse(ws.closed)
        self.assertRaises(exc.WebSocketError, ws.send, 'foobar')
        self.assertFalse(ws.closed)

    @patch.object(FakeSocket, 'sendall')
    def test_random_exception(self, sendall):
        """
        Any random exception when attempting to send a payload must NOT result
        in a closed websocket.
        """
        sendall.side_effect = RuntimeError

        ws = self.make_websocket()
        self.assertFalse(ws.closed)
        self.assertRaises(RuntimeError, ws.send, 'foobar')
        self.assertFalse(ws.closed)

    def test_send_closed(self):
        """
        Attempting to send a payload when the websocket is already closed must
        result in an `exc.WebSocketError`
        """
        ws = self.make_websocket()

        ws.close()
        self.assertTrue(ws.closed)

        with self.assertRaises(exc.WebSocketError) as ctx:
            ws.send('foobar')

        self.assertTrue(ws.closed)
        self.assertEqual(
            u'The connection was closed',
            unicode(ctx.exception)
        )


class MessageReadingTestCase(BaseStreamTestCase):
    """
    Tests for `BaseWebSocket.read_message`
    """

    def make_websocket(self, *args):
        """
        :param args: payloads
        """
        data = ''

        for payload in args:
            data += '\x00' + payload.encode('utf-8') + '\xff'

        socket = self.make_socket(data)
        ws = hixie.BaseWebSocket(socket, {}, socket.makefile('rb', 0))

        return ws

    def test_single_frame_text(self):
        """
        Ensure that a single, contained frame is decoded correctly.
        """
        ws = self.make_websocket('foo')

        msg = ws.read_message()

        self.assertIsInstance(msg, unicode)
        self.assertEqual(msg, 'foo')

    def test_large_frame(self):
        """
        Reading a large frame should buffer the data.
        """
        ws = self.make_websocket('a' * 8096)

        msg = ws.read_message()

        self.assertIsInstance(msg, unicode)
        self.assertEqual(msg, 'a' * 8096)

    def test_multiple_large_frames(self):
        """
        Reading a large frame should buffer the data.
        """
        ws = self.make_websocket('a' * 8096, 'b')

        msg = ws.read_message()

        self.assertIsInstance(msg, unicode)
        self.assertEqual(msg, 'a' * 8096)

        msg = ws.read_message()

        self.assertIsInstance(msg, unicode)
        self.assertEqual(msg, 'b')

    def test_empty_socket(self):
        """
        Failing to read from the socket must return None.
        """
        ws = self.make_websocket()

        msg = ws.read_message()
        self.assertIsNone(msg)

    def test_bad_frame_type(self):
        """
        A frame type != 0x00 should result in an error.
        """
        for frame_type in xrange(0x01, 0xff):
            socket = self.make_socket(chr(frame_type))
            ws = hixie.BaseWebSocket(socket, {}, socket.makefile('rb', 0))

            with self.assertRaises(exc.ProtocolError) as ctx:
                ws.read_message()

            self.assertEqual(
                unicode(ctx.exception),
                u'Received an invalid frame_type=%s' % (frame_type,)
            )


class ReceiveTestCase(BaseStreamTestCase):
    """
    Tests for `BaseWebSocket.receive`
    """

    def setUp(self):
        self._patcher = patch.object(hixie.BaseWebSocket, 'read_message')
        self.read_message = self._patcher.start()

    def tearDown(self):
        self._patcher.stop()

    def test_closed(self):
        """
        Attempting to read from a closed socket must return `None`.
        """
        ws = self.make_websocket()

        ws.close()

        msg = ws.receive()
        self.assertIsNone(msg)
        self.assertFalse(self.read_message.called)

    def test_return(self):
        """
        Reading from the socket must return the message.
        """
        self.read_message.return_value = u'foobar'

        ws = self.make_websocket()

        msg = ws.receive()

        self.assertEqual(msg, self.read_message.return_value)

    def test_empty_message(self):
        """
        An empty message means close the socket.
        """
        self.read_message.return_value = None

        ws = self.make_websocket()

        msg = ws.receive()

        self.assertEqual(msg, self.read_message.return_value)
        self.assertFalse(ws.closed)
