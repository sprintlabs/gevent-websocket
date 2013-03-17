# -*- coding: utf-8 -*-

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from mock import patch

from geventwebsocket import hixie, exceptions as exc

from .util import StreamStub, FakeSocket


class BaseConnectionTestCase(unittest.TestCase):
    def setUp(self):
        self.status = None
        self.headers = None

    def start_response(self, status, headers):
        self.status = status
        self.headers = headers

    def upgrade_connection(self, environ, stream=None):
        stream = stream or StreamStub()

        environ.setdefault('wsgi.url_scheme', 'http')
        environ.setdefault('SERVER_NAME', 'unittest')
        environ.setdefault('SERVER_PORT', '1010')
        environ.setdefault('QUERY_STRING', '')

        return hixie.upgrade_connection(environ, self.start_response, stream)

    def assertStatus(self, status):
        self.assertEqual(self.status, status)

    def assertHeaders(self, headers):
        try:
            assert self.status

            self.assertEqual(len(headers), len(self.headers))

            for header in headers:
                self.assertIn(header, self.headers)
        except AssertionError:
            self.assertEqual(headers, self.headers)


class UpgradeConnectionHixie75TestCase(BaseConnectionTestCase):
    """
    Tests for `hixie.upgrade_connection` for a hixie-75 websocket.
    """

    def test_sanity(self):
        """
        Ensure that given a valid challenge, a `hixie-75` websocket is
        established.
        """
        environ = {}
        result = self.upgrade_connection(environ)

        self.assertIsNone(result)
        self.assertEqual('hixie-75', environ['wsgi.websocket_version'])

        ws = environ['wsgi.websocket']

        self.assertIsInstance(ws, hixie.WebSocketHixie75)
        self.assertFalse(ws.closed)
        self.assertEqual(self.status, '101 WebSocket Protocol Handshake')
        self.assertEqual(self.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('WebSocket-Location', 'ws://unittest:1010'),
        ])

    def test_protocol(self):
        """
        Ensure that the `Sec-WebSocket-Protocol` header is echoed back.
        """
        environ = {
            'HTTP_WEBSOCKET_PROTOCOL': 'foobar'
        }

        result = self.upgrade_connection(environ)

        self.assertIsNone(result)
        self.assertEqual(self.status, '101 WebSocket Protocol Handshake')
        self.assertEqual(self.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('WebSocket-Location', 'ws://unittest:1010'),
            ('WebSocket-Protocol', 'foobar'),
        ])

    def test_location(self):
        """
        Ensure that the `WebSocket-Location` header is sent.
        """
        result = self.upgrade_connection({})

        self.assertIsNone(result)
        self.assertEqual(self.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('WebSocket-Location', 'ws://unittest:1010'),
        ])

    def test_origin(self):
        """
        Ensure that the `WebSocket-Origin` header is sent.
        """
        environ = {
            'HTTP_ORIGIN': 'foobar'
        }
        result = self.upgrade_connection(environ)

        self.assertIsNone(result)
        self.assertEqual(self.headers, [
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('WebSocket-Location', 'ws://unittest:1010'),
            ('WebSocket-Origin', 'foobar'),
        ])


class UpgradeConnectionHixie76TestCase(BaseConnectionTestCase):
    """
    Tests for `hixie.upgrade_connection`.
    """

    # values taken from
    # http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76 page 8
    key1 = '18x 6]8vM;54 *(5:  {   U1]8  z [  8'
    key2 = '1_ tx7X d  <  nw  334J702) 7]o}` 0'
    key3 = 'Tm[K T2u'
    response_md5 = 'fQJ,fN/4F4!~K~MH'

    def make_hixie76(self, environ=None, socket=None):
        if environ is None:
            environ = {}

        environ.update({
            'HTTP_SEC_WEBSOCKET_KEY1': self.key1,
            'HTTP_SEC_WEBSOCKET_KEY2': self.key2,
        })

        socket = socket or StreamStub(self.key3)

        return self.upgrade_connection(environ, socket)

    def test_no_keys(self):
        """
        No keys in the client handshake means `hixie-75` version.
        """
        environ = {}

        result = self.upgrade_connection(environ)

        self.assertIsNone(result)
        self.assertEqual('hixie-75', environ['wsgi.websocket_version'])

        ws = environ['wsgi.websocket']

        self.assertIsInstance(ws, hixie.WebSocketHixie75)
        self.assertFalse(ws.closed)
        self.assertStatus('101 WebSocket Protocol Handshake')
        self.assertHeaders([
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('WebSocket-Location', 'ws://unittest:1010'),
        ])

    def test_empty_key1(self):
        """
        An existing (but empty) Sec-Websocket-Key1 must result in a 400.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': ''
        }

        result = self.upgrade_connection(environ)

        self.assertStatus('400 Bad Request')
        self.assertEqual(result, ['400: Sec-WebSocket-Key1 header is empty'])
        self.assertHeaders([])

    def test_missing_key2(self):
        """
        A 'valid' key1 but a missing key2 must result in a 400.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': 'foobar'
        }

        result = self.upgrade_connection(environ)

        self.assertStatus('400 Bad Request')
        self.assertEqual(
            result,
            ['400: Sec-WebSocket-Key2 header is missing/empty']
        )
        self.assertHeaders([])

    def test_empty_key2(self):
        """
        A 'valid' key1 but an empty key2 must result in a 400.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': 'foobar',
            'HTTP_SEC_WEBSOCKET_KEY2': '',
        }

        result = self.upgrade_connection(environ)

        self.assertStatus('400 Bad Request')
        self.assertHeaders([])
        self.assertEqual(
            result,
            ['400: Sec-WebSocket-Key2 header is missing/empty']
        )

    def test_invalid_key1(self):
        """
        An invalid key1 must result in a 400 status.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': 'foo',
            'HTTP_SEC_WEBSOCKET_KEY2': 'bar',
        }

        result = self.upgrade_connection(environ)

        self.assertStatus('400 Bad Request')
        self.assertEqual(result, ['Invalid value for key'])
        self.assertHeaders([])

    def test_invalid_key2(self):
        """
        An invalid key2 must result in a 400 status.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': self.key1,
            'HTTP_SEC_WEBSOCKET_KEY2': 'bar',
        }

        result = self.upgrade_connection(environ)

        self.assertStatus('400 Bad Request')
        self.assertEqual(result, ['Invalid value for key'])
        self.assertHeaders([])

    def test_missing_key3(self):
        """
        Assuming that key1 and 2 are valid, if reading an incomplete/missing
        key3 must result in a `exc.WebSocketError`.
        """
        old_environ = environ = {
            'HTTP_SEC_WEBSOCKET_KEY1': self.key1,
            'HTTP_SEC_WEBSOCKET_KEY2': self.key2,
        }

        with self.assertRaises(exc.WebSocketError) as ctx:
            self.upgrade_connection(environ)

        self.assertEqual(
            unicode(ctx.exception),
            u'Unexpected EOF while reading key3'
        )

        self.assertEqual(environ, old_environ)

    def test_full_challenge(self):
        """
        Basic sanity check for creating a hixie-76 websocket.
        """
        socket = StreamStub(self.key3)
        environ = {}
        result = self.make_hixie76(environ, socket)

        self.assertIsNone(result)
        self.assertStatus('101 WebSocket Protocol Handshake')
        self.assertEqual('hixie-76', environ['wsgi.websocket_version'])
        self.assertHeaders([
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Location', 'ws://unittest:1010'),
        ])

        self.assertEqual(
            socket.write_stream.getvalue(),
            self.response_md5
        )

        ws = environ['wsgi.websocket']

        self.assertIsInstance(ws, hixie.WebSocketHixie76)
        self.assertFalse(ws.closed)

    def test_protocol(self):
        """
        Ensure that the `Sec-WebSocket-Protocol` header is echoed back.
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_PROTOCOL': 'foobar'
        }
        self.make_hixie76(environ)

        self.assertHeaders([
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Location', 'ws://unittest:1010'),
            ('Sec-WebSocket-Protocol', 'foobar'),
        ])

    def test_location(self):
        """
        Ensure that the `Sec-WebSocket-Location` header is sent.
        """
        self.make_hixie76()
        self.assertHeaders([
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Location', 'ws://unittest:1010'),
        ])

    def test_origin(self):
        """
        Ensure that the `Sec-WebSocket-Origin` header is sent.
        """
        environ = {
            'HTTP_ORIGIN': 'foobar'
        }
        result = self.make_hixie76(environ)

        self.assertIsNone(result)
        self.assertStatus('101 WebSocket Protocol Handshake')
        self.assertHeaders([
            ('Upgrade', 'WebSocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Location', 'ws://unittest:1010'),
            ('Sec-WebSocket-Origin', 'foobar'),
        ])


class BaseStreamTestCase(unittest.TestCase):
    def make_socket(self, data):
        return FakeSocket(data)

    def make_websocket(self, socket=None, environ=None):
        socket = socket or StreamStub()
        environ = environ or {}

        return hixie.BaseWebSocket(environ, socket)


class SendTestCase(BaseStreamTestCase):
    """
    Tests for `hixie.WebSocketHixie.send`.
    """

    def test_text(self):
        """
        Ensure that sending unicode works correctly
        """
        socket = StreamStub()
        ws = self.make_websocket(socket)

        text = u'ƒøø'
        ws.send(text)

        self.assertEqual(
            '\x00' + text.encode('utf-8') + '\xff',
            socket.write_stream.getvalue(),
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
        socket = StreamStub()
        ws = self.make_websocket(socket)

        blob = '\xff'

        with self.assertRaises(UnicodeDecodeError):
            ws.send(blob)

        self.assertFalse(ws.closed)

    @patch.object(StreamStub, 'write')
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

    @patch.object(StreamStub, 'write')
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

        ws = hixie.BaseWebSocket({}, StreamStub(data))

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
            socket = StreamStub(chr(frame_type))
            ws = hixie.BaseWebSocket({}, socket)

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
