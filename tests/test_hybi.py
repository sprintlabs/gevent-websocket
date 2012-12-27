import unittest
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
        ValueError must be raised if the number of bytes supplied != 2
        """
        for data in ('', 'a', 'aaa'):
            # skip 2 bytes
            stream = StringIO(data)

            with self.assertRaises(exc.WebSocketError):
                hybi.decode_header(stream)

        with self.assertRaises(exc.WebSocketError) as ctx:
            hybi.decode_header(StringIO('aa'))

        self.assertNotEqual(
            'Unexpected EOF while decoding header',
            unicode(ctx.exception)
        )

    def test_rsv_bits(self):
        """
        If the RSV bits are set then raise a `ProtocolError`
        """
        for rsv_mask in [0x40, 0x20, 0x10]:
            byte = chr(rsv_mask)

            with self.assertRaises(exc.ProtocolError) as ctx:
                hybi.decode_header(StringIO(byte + 'a'))

            self.assertTrue(unicode(ctx.exception).startswith(
                'Received frame with non-zero reserved bits: '))

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
        self.assertEqual((True, 0x08, False, 0), header)

        # check the length
        header = hybi.decode_header(StringIO(
            chr(hybi.FIN_MASK | hybi.OPCODE_CLOSE) + '\x10'
        ))

        self.assertEqual((True, 0x08, False, 16), header)

        # check the mask
        header = hybi.decode_header(StringIO(
            chr(hybi.FIN_MASK | hybi.OPCODE_CLOSE) + chr(hybi.MASK_MASK)
        ))

        self.assertEqual((True, 0x08, True, 0), header)

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

        self.assertEqual(
            (False, 0, False, 0),
            header
        )

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

        self.assertEqual(
            (False, 0, False, 0),
            header
        )

    def test_length_127_unsigned(self):
        """
        Ensure that the 8 byte header is unsigned
        """
        data = StringIO('\x00\x7f' + ('\xff' * 8))
        header = hybi.decode_header(data)

        self.assertEqual(
            (False, 0, False, 0xffffffffffffffff),
            header
        )

        print data.tell()

    def test_length_128(self):
        """
        A base length of 128 should cause a `ProtocolError`
        """
        data = StringIO('\x00\x80')
        header = hybi.decode_header(data)


class EncodeHeaderTestCase(unittest.TestCase):
    """
    Tests for `hybi.encode_header`
    """

    def test_fin(self):
        """
        Ensure that the fin is applied correctly
        """
        header = chr(hybi.FIN_MASK) + '\x00'

        self.assertEqual(header, hybi.encode_header(
            True,  # fin
            False, # rsv0
            False, # rsv1
            False, # rsv2
            0,     # opcode
            False, # mask
            0      # length
        ))

    def test_not_fin(self):
        """
        Unfinished frame.
        """
        header = '\x00\x00'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            False, # rsv0
            False, # rsv1
            False, # rsv2
            0,     # opcode
            False, # mask
            0      # length
        ))

    def test_rsv0(self):
        """
        Test all basic permutations of rsv0
        """
        header = '\x40\x00'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            True,  # rsv0
            False, # rsv1
            False, # rsv2
            0,     # opcode
            False, # mask
            0      # length
        ))

    def test_rsv1(self):
        """
        Test all basic permutations of rsv1
        """
        header = '\x20\x00'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            False, # rsv0
            True,  # rsv1
            False, # rsv2
            0,     # opcode
            False, # mask
            0      # length
        ))

    def test_rsv2(self):
        """
        Test all basic permutations of rsv2
        """
        header = '\x10\x00'

        self.assertEqual(header, hybi.encode_header(
            False, # fin
            False, # rsv0
            False, # rsv1
            True,  # rsv2
            0,     # opcode
            False, # mask
            0      # length
        ))

