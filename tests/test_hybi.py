# -*- coding: utf-8 -*-

import unittest
from mock import patch

try:
    from cStringIO import StringIO
except ImportError:
    import StringIO

from geventwebsocket import hybi, exceptions as exc

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

        response = hybi.upgrade_connection(handler, environ)

        expected_headers = [
            ('Upgrade', 'websocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=')
        ]

        self.assertEqual(handler.status, '101 Switching Protocols')
        self.assertIsNone(response)
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

    def test_missing_key(self):
        """
        A missing Sec-WebSocket-Key must result in a 400 status
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_VERSION': '13',
        }

        handler = self.make_handler(environ=environ)

        response = hybi.upgrade_connection(handler, environ)

        self.assertEqual('400 Bad Request', handler.status)
        self.assertEqual([], handler.headers)
        self.assertEqual(
            response,
            ['Sec-WebSocket-Key header is missing/empty']
        )

    def test_empty_key(self):
        """
        An empty Sec-WebSocket-Key must result in a 400 status
        """
        environ = {
            'HTTP_SEC_WEBSOCKET_VERSION': '13',
            'HTTP_SEC_WEBSOCKET_KEY': '',
        }

        handler = self.make_handler(environ=environ)

        response = hybi.upgrade_connection(handler, environ)

        self.assertEqual('400 Bad Request', handler.status)
        self.assertEqual([], handler.headers)
        self.assertEqual(
            response,
            ['Sec-WebSocket-Key header is missing/empty']
        )

    def test_invalid_key(self):
        """
        A none base64 encoded Sec-WebSocket-Key must result in a 400 status
        """
        import base64
        key = 'A=='

        self.assertRaises(TypeError, base64.b64decode, key)

        environ = {
            'HTTP_SEC_WEBSOCKET_VERSION': '13',
            'HTTP_SEC_WEBSOCKET_KEY': key,
        }

        handler = self.make_handler(environ=environ)

        response = hybi.upgrade_connection(handler, environ)

        self.assertEqual('400 Bad Request', handler.status)
        self.assertEqual([], handler.headers)
        self.assertEqual(response, ["Invalid key: 'A=='"])

    def test_invalid_key_length(self):
        """
        A decoded key that is not of length 16 must result in a 400 status
        """
        import base64
        key = 'a' * 17

        environ = {
            'HTTP_SEC_WEBSOCKET_VERSION': '13',
            'HTTP_SEC_WEBSOCKET_KEY': base64.b64encode(key),
        }

        handler = self.make_handler(environ=environ)

        response = hybi.upgrade_connection(handler, environ)

        self.assertEqual('400 Bad Request', handler.status)
        self.assertEqual([], handler.headers)
        self.assertEqual(response, ["Invalid key: 'YWFhYWFhYWFhYWFhYWFhYWE='"])


class DecodeHeaderTestCase(unittest.TestCase):
    """
    Tests for `hybi.decode_header`
    """

    def test_bad_length(self):
        """
        `exc.WebSocketError` must be raised if the number of bytes supplied < 2
        """
        for data in ('', '\x00'):
            # skip 2 bytes
            stream = StringIO(data)

            with self.assertRaises(exc.WebSocketError) as ctx:
                hybi.decode_header(stream)

            self.assertEqual(
                u'Unexpected EOF while decoding header',
                unicode(ctx.exception)
            )

    def test_rsv_bits(self):
        """
        If the RSV bits are set then raise a `ProtocolError`
        """
        for rsv_mask in [0x40, 0x20, 0x10]:
            byte = chr(rsv_mask)

            header = hybi.decode_header(StringIO(byte + '\x00'))

            self.assertEqual(header.flags, rsv_mask)

    def test_control_frame_fragmentation(self):
        """
        Page 36 of the spec specifies that control frames must not be fragmented
        """
        byte = chr(hybi.OPCODE_CLOSE)

        with self.assertRaises(exc.ProtocolError) as ctx:
            hybi.decode_header(StringIO(byte + 'a'))

        self.assertEqual(
            u"Received fragmented control frame: '\\x08a'",
            unicode(ctx.exception)
        )

    def test_control_frame_size(self):
        """
        Page 37 of the spec specifies that control frames must not have a length
        of greater that 125.
        """
        byte = chr(hybi.FIN_MASK | hybi.OPCODE_CLOSE) + chr(0x7f)

        with self.assertRaises(exc.FrameTooLargeException) as ctx:
            hybi.decode_header(StringIO(byte))

        self.assertEqual(
            u"Control frame cannot be larger than 125 bytes: '\\x88\\x7f'",
            unicode(ctx.exception)
        )

    def test_decode(self):
        """
        Basic sanity checks for decoding a header.
        """
        header = hybi.decode_header(StringIO(
            chr(hybi.FIN_MASK | hybi.OPCODE_CLOSE) + '\x00'
        ))

        # fin, opcode, mask, length
        self.assertTrue(header.fin)
        self.assertEqual(header.opcode, 0x08)
        self.assertEqual(header.mask, '')
        self.assertEqual(header.length, 0)
        self.assertEqual(header.flags, 0)

        # check the length
        header = hybi.decode_header(StringIO(
            chr(hybi.FIN_MASK | hybi.OPCODE_CLOSE) + '\x10'
        ))

        self.assertTrue(header.fin)
        self.assertEqual(header.opcode, 0x08)
        self.assertEqual(header.mask, '')
        # this is changed ..
        self.assertEqual(header.length, 16)
        self.assertEqual(header.flags, 0)

        # check the mask
        data = StringIO(
            chr(hybi.FIN_MASK | hybi.OPCODE_CLOSE) + chr(hybi.MASK_MASK) +
            'abcd' # this is the mask data
        )
        header = hybi.decode_header(data)

        self.assertTrue(header.fin)
        self.assertEqual(header.opcode, 0x08)
        self.assertEqual(header.mask, 'abcd')
        self.assertEqual(header.length, 0)
        self.assertEqual(header.flags, 0)

    def test_length_126_no_trailing(self):
        """
        Reading a header with a length of 126 that is missing the 2 trailing
        bytes should result in a WebSocketError.
        """
        data = StringIO('\x00\x7e')

        with self.assertRaises(exc.WebSocketError) as ctx:
            hybi.decode_header(data)

        self.assertEqual(
            'Unexpected EOF while decoding header',
            unicode(ctx.exception)
        )

    def test_length_126_actual(self):
        """
        The correct length should be decoded when reading a 126 length header.
        """
        data = StringIO('\x00\x7e\x00\x00')

        header = hybi.decode_header(data)

        self.assertFalse(header.fin)
        self.assertEqual(header.opcode, 0x00)
        self.assertEqual(header.mask, '')
        self.assertEqual(header.length, 0)
        self.assertEqual(header.flags, 0)

    def test_length_127_no_trailing(self):
        """
        A header with base length 127 should read another 8 bytes of trailing
        data.
        """
        for i in xrange(0, 8):
            data = StringIO('\x00\x7f' + ('\x00' * i))

            with self.assertRaises(exc.WebSocketError) as ctx:
                hybi.decode_header(data)

            self.assertEqual(
                'Unexpected EOF while decoding header',
                unicode(ctx.exception)
            )

    def test_length_127_actual(self):
        """
        8 bytes should be decoded when reading a 127 base length header
        """
        data = StringIO('\x00\x7f' + ('\x00' * 8))

        header = hybi.decode_header(data)

        self.assertFalse(header.fin)
        self.assertEqual(header.opcode, 0x00)
        self.assertEqual(header.mask, '')
        self.assertEqual(header.length, 0)
        self.assertEqual(header.flags, 0)

    def test_length_127_unsigned(self):
        """
        Ensure that the 8 byte header is unsigned
        """
        data = StringIO('\x00\x7f' + ('\xff' * 8))
        header = hybi.decode_header(data)

        self.assertFalse(header.fin)
        self.assertEqual(header.opcode, 0x00)
        self.assertEqual(header.mask, '')
        self.assertEqual(header.length, 0xffffffffffffffff)
        self.assertEqual(header.flags, 0)

    def test_missing_mask(self):
        """
        Ensure that the 8 byte header is unsigned
        """
        # check the mask
        data = StringIO(
            chr(hybi.FIN_MASK | hybi.OPCODE_CLOSE) + chr(hybi.MASK_MASK) +
            'abc' # this is the mask data
        )

        with self.assertRaises(exc.WebSocketError) as ctx:
            hybi.decode_header(data)

        self.assertEqual(
            'Unexpected EOF while decoding header',
            unicode(ctx.exception)
        )


class EncodeHeaderTestCase(unittest.TestCase):
    """
    Tests for `hybi.encode_header`
    """

    def encode_header(self, length):
        base_header = [False, 0, '']

        return hybi.encode_header(*(base_header + [length, 0]))

    def test_fin(self):
        """
        Ensure that the fin is applied correctly
        """
        header = chr(hybi.FIN_MASK) + '\x00'

        self.assertEqual(header, hybi.encode_header(
            True,  # fin
            0,     # opcode
            '',    # mask
            0,     # length
            0      # flags
        ))

    def test_not_fin(self):
        """
        Unfinished frame.
        """
        header = '\x00\x00'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            0,     # opcode
            '',    # mask
            0,     # length
            0      # flags
        ))

    def test_rsv0(self):
        """
        Test all basic permutations of rsv0
        """
        header = '\x40\x00'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            0,     # opcode
            '',    # mask
            0,     # length
            0x40   # flags
        ))

    def test_rsv1(self):
        """
        Test all basic permutations of rsv1
        """
        header = '\x20\x00'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            0,     # opcode
            '',    # mask
            0,     # length
            0x20   # flags
        ))

    def test_rsv2(self):
        """
        Test all basic permutations of rsv2
        """
        header = '\x10\x00'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            0,     # opcode
            '',    # mask
            0,     # length
            0x10   # flags
        ))

    def test_mask(self):
        """
        Test setting a mask
        """
        header = '\x00\x80foo'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            0,     # opcode
            'foo', # mask
            0,     # length
            0      # flags
        ))

    def test_length_lt_126(self):
        """
        Test setting a length less than 126
        """
        for i in xrange(0, 126):
            self.assertEqual('\x00' + chr(i), hybi.encode_header(
                False, # fin
                0,     # opcode
                '',    # mask
                i,     # length
                0      # flags
            ))

        self.assertNotEqual('\x00' + chr(126), hybi.encode_header(
            False, # fin
            0,     # opcode
            '',    # mask
            126,   # length
            0      # flags
        ))

    def test_length_lte_0xffff(self):
        """
        Encoding a header length of >=126 <= 1<<16 results in a 2 byte extended
        header
        """
        self.assertEqual('\x00\x7e\x00\x7e', self.encode_header(126))
        self.assertEqual('\x00\x7e\xff\xff', self.encode_header(0xffff))

    def test_length_lte_0xffffffff(self):
        """
        Encoding a header length of > 0xffff <= 0xfffffffff results in an 8
        byte extended header.
        """
        self.assertEqual(
            '\x00\x7f\x00\x00\x00\x00\x00\x01\x00\x00',
            self.encode_header(0xffff + 1)
        )
        self.assertEqual(
            '\x00\x7f' + ('\xff' * 8),
            self.encode_header(0xffffffffffffffff)
        )

    def test_length_gt_64bit(self):
        """
        Encoding a header > 1 << 64 MUST result in a `FrameTooLargeException`
        """
        self.assertRaises(exc.FrameTooLargeException,
                          self.encode_header, (1 << 64) + 1)


class BaseStreamTestCase(unittest.TestCase):
    def make_socket(self, data):
        return FakeSocket(data)

    def make_websocket(self, socket=None, environ=None):
        socket = socket or FakeSocket()
        environ = environ or {}

        return hybi.WebSocketHybi(socket, environ)


class FrameReadingTestCase(BaseStreamTestCase):
    """
    Tests for `WebSocketHybi.read_frame`
    """

    def test_not_enough_data(self):
        """
        If the socket does not return enough data when reading a header (i.e.
        the socket died) then a `WebSocketError` must be raised.
        """
        socket = self.make_socket('')
        ws = self.make_websocket(socket)

        with self.assertRaises(exc.WebSocketError) as ctx:
            ws.read_frame()

        self.assertEqual(
            u'Unexpected EOF while decoding header',
            unicode(ctx.exception)
        )

    def test_empty_header(self):
        """
        Reading a header with no payload must return correctly.
        """
        socket = self.make_socket('\x00\x00')
        ws = self.make_websocket(socket)

        header, payload = ws.read_frame()

        self.assertEqual(payload, '')

        # ensure that only 2 bytes were read
        self.assertEqual(socket.tell(), 2)

    def test_good_header_missing_payload(self):
        """
        Simulate the socket dying after reading a header.
        """
        # payload of 1 byte
        socket = self.make_socket('\x00\x01')
        ws = self.make_websocket(socket)

        with self.assertRaises(exc.WebSocketError) as ctx:
            ws.read_frame()

        self.assertEqual(
            'Unexpected EOF reading frame payload',
            unicode(ctx.exception)
        )

    def test_read_frame(self):
        """
        Ensure that reading a header and payload works as expected.
        """
        # payload of 1 byte
        socket = self.make_socket('\x00\x06foobar')
        ws = self.make_websocket(socket)

        header, payload = ws.read_frame()

        self.assertEqual(payload, 'foobar')

    def test_masked_payload(self):
        """
        Ensure that a masked header+frame are decoded correctly.
        """
        socket = self.make_socket(
            # from the spec document
            '\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58')
        ws = self.make_websocket(socket)

        header, payload = ws.read_frame()

        self.assertEqual(payload, 'Hello')
        self.assertEqual(header.mask, '7\xfa!=')


class MessageReadingTestCase(BaseStreamTestCase):
    """
    Tests for `WebSocketHybi.read_message`
    """

    def make_websocket(self, *args):
        """
        :param args: triplets of fin, opcode, payload
        """
        data = ''

        for i in xrange(0, len(args), 3):
            fin, opcode, payload = args[i], args[i + 1], args[i + 2]

            data += hybi.encode_header(fin, opcode, '', len(payload), 0)
            data += payload

        socket = self.make_socket(data)
        ws = hybi.WebSocketHybi(socket, {})

        return ws

    def test_single_frame_text(self):
        """
        Ensure that a single, contained frame is decoded correctly.
        """
        ws = self.make_websocket(True, hybi.OPCODE_TEXT, 'foo')

        msg = ws.read_message()

        self.assertIsInstance(msg, unicode)
        self.assertEqual(msg, 'foo')

    def test_single_frame_bad_utf8(self):
        """
        A text frame with bad utf-8 data must close the websocket
        """
        data = '\xff\xff'

        self.assertRaises(UnicodeDecodeError, data.decode, 'utf-8')

        ws = self.make_websocket(True, hybi.OPCODE_TEXT, data)

        self.assertFalse(ws.closed)

        self.assertRaises(UnicodeDecodeError, ws.read_message)
        self.assertTrue(ws.closed)

    def test_multiple_continuous_frames(self):
        """
        `read_message` must return the full message with payloads split over
        multiple frames.
        """
        ws = self.make_websocket(
            False, hybi.OPCODE_TEXT, 'foo',
            True, hybi.OPCODE_CONTINUATION, 'bar',
        )

        msg = ws.read_message()

        self.assertIsInstance(msg, unicode)
        self.assertEqual(msg, 'foobar')

    def test_continuation_frame_bad_state(self):
        """
        Reading a continuation frame when there has been no previous frame
        definition must raise a `exc.ProtocolError`.
        """
        ws = self.make_websocket(
            True, hybi.OPCODE_CONTINUATION, '',
        )

        with self.assertRaises(exc.ProtocolError) as ctx:
            ws.read_message()

        self.assertEqual(
            u'Unexpected frame with opcode=0',
            unicode(ctx.exception)
        )

    def test_multiple_text_frames(self):
        """
        Reading a text frame when the first has not finished must raise a
        `exc.ProtocolError`.
        """
        ws = self.make_websocket(
            False, hybi.OPCODE_TEXT, 'foo',
            True, hybi.OPCODE_TEXT, 'bar',
        )

        with self.assertRaises(exc.ProtocolError) as ctx:
            ws.read_message()

        self.assertEqual(
            u'The opcode in non-fin frame is expected to be zero, got 1',
            unicode(ctx.exception)
        )

    def test_multiple_binary_frames(self):
        """
        Reading a binary frame when the first has not finished must raise a
        `exc.ProtocolError`.
        """
        ws = self.make_websocket(
            False, hybi.OPCODE_BINARY, 'foo',
            True, hybi.OPCODE_BINARY, 'bar',
        )

        with self.assertRaises(exc.ProtocolError) as ctx:
            ws.read_message()

        self.assertEqual(
            u'The opcode in non-fin frame is expected to be zero, got 2',
            unicode(ctx.exception)
        )

    def test_single_frame_binary(self):
        """
        Ensure that a single, contained binary frame is decoded correctly.
        """
        ws = self.make_websocket(True, hybi.OPCODE_BINARY, 'foo')

        msg = ws.read_message()

        self.assertIsInstance(msg, str)
        self.assertEqual(msg, 'foo')

    def test_unknown_opcode(self):
        """
        A frame with an unknown opcode must raise a `exc.ProtocolError`.
        """
        ws = self.make_websocket(True, 0xf, 'foo')

        with self.assertRaises(exc.ProtocolError) as ctx:
            ws.read_message()

        self.assertEqual(
            u'Unexpected opcode=15',
            unicode(ctx.exception)
        )

        self.assertFalse(ws.closed)

    def test_ping(self):
        """
        While decoding frames, ensure that a ping frame calls `handle_ping`.
        """
        with patch.object(hybi.WebSocketHybi, 'handle_ping') as mock:
            ws = self.make_websocket(
                False, hybi.OPCODE_TEXT, 'foobar',
                True, hybi.OPCODE_PING, '',
                True, hybi.OPCODE_CONTINUATION, ''
            )

            msg = ws.read_message()

            self.assertTrue(mock.called)
            self.assertEqual(msg, 'foobar')

    def test_pong(self):
        """
        While decoding frames, ensure that a pong frame calls `handle_pong`.
        """
        with patch.object(hybi.WebSocketHybi, 'handle_pong') as mock:
            ws = self.make_websocket(
                False, hybi.OPCODE_TEXT, 'foobar',
                True, hybi.OPCODE_PONG, '',
                True, hybi.OPCODE_CONTINUATION, ''
            )

            msg = ws.read_message()

            self.assertTrue(mock.called)
            self.assertEqual(msg, 'foobar')

    def test_close(self):
        """
        While decoding frames, ensure that a close frame calls `handle_close`.
        """
        with patch.object(hybi.WebSocketHybi, 'handle_close') as mock:
            ws = self.make_websocket(
                False, hybi.OPCODE_TEXT, 'foobar',
                True, hybi.OPCODE_CLOSE, '',
                True, hybi.OPCODE_CONTINUATION, ''
            )

            msg = ws.read_message()

            self.assertTrue(mock.called)
            self.assertEqual(msg, 'foobar')


class CloseFrameTestCase(BaseStreamTestCase):
    """
    Tests for `hybi.WebSocketHybi.handle_close`
    """

    def test_no_payload(self):
        """
        When there is no payload, ensure that `hybi.ConnectionClosed` is raised.
        """
        ws = self.make_websocket()

        with self.assertRaises(hybi.ConnectionClosed) as ctx:
            ws.handle_close(None, '')

        self.assertEqual(ctx.exception.code, 1000)
        self.assertEqual(ctx.exception.message, None)

    def test_min_payload(self):
        """
        When a close frame with a payload < 2 is received, ensure that
        `exc.ProtocolError` is raised.
        """
        ws = self.make_websocket()

        with self.assertRaises(exc.ProtocolError) as ctx:
            ws.handle_close(None, ' ')

        self.assertEqual(
            u"Invalid close frame: None ' '",
            unicode(ctx.exception)
        )

    def test_decode_payload(self):
        """
        Ensure that `hybi.ConnectionClosed` is raised with the correct
        code/message
        """
        ws = self.make_websocket()

        with self.assertRaises(hybi.ConnectionClosed) as ctx:
            ws.handle_close(None, '\x00\x09foobar')

        self.assertEqual(ctx.exception.code, 9)
        self.assertEqual(ctx.exception.message, 'foobar')


class CloseTestCase(BaseStreamTestCase):
    """
    Tests for closing a hybi websocket.
    """

    def assertClosed(self, ws):
        self.assertTrue(ws.closed)
        self.assertIsNone(ws.environ)
        self.assertIsNone(ws._socket)
        self.assertIsNone(ws._fobj)
        self.assertIsNone(ws._read)
        self.assertIsNone(ws._write)

    def test_state(self):
        """
        Closing an active websocket should set the correct internal state.
        """
        ws = self.make_websocket()

        self.assertFalse(ws.closed)

        ws.close()

        self.assertClosed(ws)

    def test_already_closed(self):
        """
        Ensure that closing an already closed socket does not fail.
        """
        ws = self.make_websocket()

        self.assertFalse(ws.closed)

        ws.close()
        ws.close()

        self.assertClosed(ws)

    def test_send_frame(self):
        """
        Ensure that a close frame is sent with the default code of 1000 when
        closing the websocket.
        """
        with patch.object(hybi.WebSocketHybi, 'send_frame') as mock:
            ws = self.make_websocket()

            ws.close()

            mock.assert_called_with('\x03\xe8', opcode=8)

    def test_send_code(self):
        """
        Ensure that a close frame with the appropriate code is sent when
        closing the websocket.
        """
        with patch.object(hybi.WebSocketHybi, 'send_frame') as mock:
            ws = self.make_websocket()

            ws.close(1007, 'foobar')

            mock.assert_called_with('\x03\xeffoobar', opcode=8)

    def test_only_one_send_frame(self):
        """
        Ensure that only the first close frame is sent when closing the
        websocket.
        """
        with patch.object(hybi.WebSocketHybi, 'send_frame') as mock:
            ws = self.make_websocket()

            ws.close()
            ws.close(1007, 'foobar')

            mock.assert_called_once_with('\x03\xe8', opcode=8)

    @patch.object(hybi.WebSocketHybi, 'send_frame')
    def test_socket_error_when_sending_frame(self, send_frame):
        """
        When calling `close`, the socket may be dead and `send_frame` will raise
        a `exc.WebSocketError`. Ensure that this exception is not propagated.
        """
        send_frame.side_effect = exc.WebSocketError

        ws = self.make_websocket()
        message = ws.close()

        self.assertIsNone(message)
        self.assertTrue(ws.closed)


class ReceiveTestCase(BaseStreamTestCase):
    """
    Tests for the public method `HybiWebSocket.receive`
    """

    def test_broken_socket(self):
        """
        Ensure that when the socket is broken that the websocket is closed.
        """
        from socket import error

        class BrokenSocket(FakeSocket):
            def read(self, size):
                # any reads from the socket will result in an error.
                raise error

        with patch.object(hybi.WebSocketHybi, 'close') as mock:
            ws = self.make_websocket(BrokenSocket())

            self.assertRaises(error, ws._socket.read, 1)
            self.assertRaises(exc.WebSocketError, ws.receive)

            mock.assert_called_with(None)

    @patch.object(hybi.WebSocketHybi, 'read_message')
    def test_read_message(self, read_message):
        """
        Ensure that a message read from the stream is returned correctly.
        """
        read_message.return_value = 'foobar'

        ws = self.make_websocket()
        message = ws.receive()

        self.assertEqual(message, read_message.return_value)

    @patch.object(hybi.WebSocketHybi, 'send_frame')
    @patch.object(hybi.WebSocketHybi, 'read_message')
    def test_protocol_error(self, read_message, send_frame):
        """
        When an `exc.ProtocolError` is raised by `read_message`, the websocket
        must be closed and the correct close frame sent.
        """
        read_message.side_effect = exc.ProtocolError

        ws = self.make_websocket()

        self.assertRaises(exc.ProtocolError, ws.receive)

        self.assertTrue(ws.closed)

        send_frame.assert_called_with('\x03\xea', opcode=8)

    @patch.object(hybi.WebSocketHybi, 'send_frame')
    @patch.object(hybi.WebSocketHybi, 'read_message')
    def test_close_connection(self, read_message, send_frame):
        """
        When the connection is closed normally, a close frame must be sent and
        a return of `None`.
        """
        read_message.side_effect = hybi.ConnectionClosed(1002, '')

        ws = self.make_websocket()

        self.assertIsNone(ws.receive())
        self.assertTrue(ws.closed)

        send_frame.assert_called_with('\x03\xea', opcode=8)

    @patch.object(hybi.WebSocketHybi, 'read_message')
    def test_random_error(self, read_message):
        """
        When _any_ other type of exception is raised, the websocket must be
        closed and send a close frame.
        """
        read_message.side_effect = RuntimeError

        ws = self.make_websocket()

        self.assertRaises(RuntimeError, ws.receive)
        self.assertTrue(ws.closed)


class SendTestCase(BaseStreamTestCase):
    """
    Tests for `hybi.WebSocketHybi.send`.
    """

    def test_text(self):
        """
        Ensure that sending unicode works correctly
        """
        socket = FakeSocket()
        ws = self.make_websocket(socket)

        text = u'ƒøø'
        ws.send(text, binary=False)

        self.assertEqual(
            '\x81\x06' + text.encode('utf-8'),
            socket.data,
        )

    def test_default(self):
        """
        Ensure that the default for sending data is utf-8 encoded.
        """
        socket = FakeSocket()
        ws = self.make_websocket(socket)

        text = u'ƒøø'
        # note the lack of a binary=? kwarg
        ws.send(text)

        self.assertEqual(
            '\x81\x06' + text.encode('utf-8'),
            socket.data,
        )

    def test_binary(self):
        """
        Ensure that sending binary works correctly
        """
        socket = FakeSocket()
        ws = self.make_websocket(socket)

        blob = '\x00' * 10
        ws.send(blob, binary=True)

        self.assertEqual(
            '\x82\x0a' + blob,
            socket.data,
        )

    @patch.object(FakeSocket, 'sendall')
    def test_broken_socket(self, sendall):
        """
        Any attempt to write to this socket will result in an error
        """
        from socket import error

        sendall.side_effect = error

        ws = self.make_websocket()
        self.assertFalse(ws.closed)
        self.assertRaises(exc.WebSocketError, ws.send, 'foobar')
        self.assertTrue(ws.closed)

    @patch.object(FakeSocket, 'sendall')
    def test_random_exception(self, sendall):
        """
        Any random exception when attempting to send a payload must result in a
        closed websocket.
        """
        sendall.side_effect = RuntimeError

        ws = self.make_websocket()
        self.assertFalse(ws.closed)
        self.assertRaises(RuntimeError, ws.send, 'foobar')
        self.assertTrue(ws.closed)

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
